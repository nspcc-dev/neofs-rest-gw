package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	sessionv2 "github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"go.uber.org/zap"
)

// PrmAttributes groups parameters to form attributes from request headers.
type PrmAttributes struct {
	DefaultTimestamp bool
	DefaultFileName  string
}

type epochDurations struct {
	currentEpoch    uint64
	secondsPerEpoch uint64
}

const (
	SystemAttributePrefix = "__NEOFS__"

	ExpirationDurationAttr       = SystemAttributePrefix + "EXPIRATION_DURATION"
	ExpirationTimestampAttr      = SystemAttributePrefix + "EXPIRATION_TIMESTAMP"
	ExpirationRFC3339Attr        = SystemAttributePrefix + "EXPIRATION_RFC3339"
	containerDomainNameAttribute = SystemAttributePrefix + "NAME"
	containerDomainZoneAttribute = SystemAttributePrefix + "ZONE"

	neofsAttributeHeaderPrefix = "Neofs-"

	offsetMin     = 0
	offsetDefault = 0

	limitMin     = 1
	limitMax     = 1000
	limitDefault = 100

	handlerFieldName = "handler"
)

func getEpochDurations(ctx context.Context, networkInfoGetter networkInfoGetter) (*epochDurations, error) {
	networkInfo, err := networkInfoGetter.NetworkInfo(ctx)
	if err != nil {
		return nil, err
	}

	res := &epochDurations{
		currentEpoch:    networkInfo.CurrentEpoch(),
		secondsPerEpoch: networkInfo.EpochDuration(),
	}

	if res.secondsPerEpoch == 0 {
		return nil, errors.New("EpochDuration is zero")
	}
	return res, nil
}

func needParseExpiration(headers map[string]string) bool {
	_, ok1 := headers[ExpirationDurationAttr]
	_, ok2 := headers[ExpirationRFC3339Attr]
	_, ok3 := headers[ExpirationTimestampAttr]
	return ok1 || ok2 || ok3
}

func prepareExpirationHeader(headers map[string]string, epochDurations *epochDurations, now time.Time) error {
	expirationInEpoch := headers[object.AttributeExpirationEpoch]

	if timeRFC3339, ok := headers[ExpirationRFC3339Attr]; ok {
		expTime, err := time.Parse(time.RFC3339, timeRFC3339)
		if err != nil {
			return fmt.Errorf("couldn't parse value %s of header %s", timeRFC3339, ExpirationRFC3339Attr)
		}

		if expTime.Before(now) {
			return fmt.Errorf("value %s of header %s must be in the future", timeRFC3339, ExpirationRFC3339Attr)
		}
		updateExpirationHeader(headers, epochDurations, expTime.Sub(now))
		delete(headers, ExpirationRFC3339Attr)
	}

	if timestamp, ok := headers[ExpirationTimestampAttr]; ok {
		value, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return fmt.Errorf("couldn't parse value %s of header %s", timestamp, ExpirationTimestampAttr)
		}
		expTime := time.Unix(value, 0)

		now := time.Now()
		if expTime.Before(now) {
			return fmt.Errorf("value %s of header %s must be in the future", timestamp, ExpirationTimestampAttr)
		}
		updateExpirationHeader(headers, epochDurations, expTime.Sub(now))
		delete(headers, ExpirationTimestampAttr)
	}

	if duration, ok := headers[ExpirationDurationAttr]; ok {
		expDuration, err := time.ParseDuration(duration)
		if err != nil {
			return fmt.Errorf("couldn't parse value %s of header %s", duration, ExpirationDurationAttr)
		}
		if expDuration <= 0 {
			return fmt.Errorf("value %s of header %s must be positive", expDuration, ExpirationDurationAttr)
		}
		updateExpirationHeader(headers, epochDurations, expDuration)
		delete(headers, ExpirationDurationAttr)
	}

	if expirationInEpoch != "" {
		headers[object.AttributeExpirationEpoch] = expirationInEpoch
	}

	return nil
}

func updateExpirationHeader(headers map[string]string, durations *epochDurations, expDuration time.Duration) {
	currentEpoch := durations.currentEpoch
	numEpoch := (uint64(expDuration.Seconds()) + durations.secondsPerEpoch - 1) / durations.secondsPerEpoch

	expirationEpoch := uint64(math.MaxUint64)
	if numEpoch < math.MaxUint64-currentEpoch {
		expirationEpoch = currentEpoch + numEpoch
	}

	headers[object.AttributeExpirationEpoch] = strconv.FormatUint(expirationEpoch, 10)
}

// decodeBasicACL is the same as DecodeString on acl.Basic but
// it also checks length for hex formatted acl.
func decodeBasicACL(input string) (acl.Basic, error) {
	switch input {
	case acl.NamePrivate:
		return acl.Private, nil
	case acl.NamePrivateExtended:
		return acl.PrivateExtended, nil
	case acl.NamePublicRO:
		return acl.PublicRO, nil
	case acl.NamePublicROExtended:
		return acl.PublicROExtended, nil
	case acl.NamePublicRW:
		return acl.PublicRW, nil
	case acl.NamePublicRWExtended:
		return acl.PublicRWExtended, nil
	case acl.NamePublicAppend:
		return acl.PublicAppend, nil
	case acl.NamePublicAppendExtended:
		return acl.PublicAppendExtended, nil
	default:
		trimmedInput := strings.TrimPrefix(strings.ToLower(input), "0x")
		if len(trimmedInput) != 8 {
			return 0, fmt.Errorf("invalid basic ACL size: %s", input)
		}

		v, err := strconv.ParseUint(trimmedInput, 16, 32)
		if err != nil {
			return 0, fmt.Errorf("parse hex: %w", err)
		}

		var res acl.Basic
		res.FromBits(uint32(v))
		return res, nil
	}
}

func systemTranslator(key, prefix string) string {
	// replace the specified prefix with `__NEOFS__`
	key = strings.Replace(key, prefix, SystemAttributePrefix, 1)

	// replace `-` with `_`
	key = strings.ReplaceAll(key, "-", "_")

	// replace with uppercase
	return strings.ToUpper(key)
}

func filterHeaders(l *zap.Logger, header http.Header) (map[string]string, error) {
	result := make(map[string]string)

	for key, values := range header {
		// check if key gets duplicated
		// return error containing full key name (with prefix)
		if len(values) > 1 {
			return nil, fmt.Errorf("key duplication error: %s", key)
		}

		// checks that the value is  not empty
		if len(values) == 0 {
			continue
		}

		value := values[0]

		// checks that the key and the val not empty and the key has attribute prefix
		if !isValidKeyValue(key, value) {
			continue
		}

		// removing attribute prefix and checks that it's a system NeoFS header
		clearKey := processKey(key)

		// checks that the attribute key is not empty
		if clearKey == "" {
			continue
		}

		clearKey = formatSpecialAttribute(clearKey)
		result[clearKey] = value

		l.Debug("add attribute to result object",
			zap.String("key", clearKey),
			zap.String("value", value))
	}
	return result, nil
}

// formatSpecialAttribute checks if a key-string is one of the special NEOFS
// attributes and returns the string in the correct case.
// For example: "Filepath" -> "FilePath".
func formatSpecialAttribute(s string) string {
	switch s {
	case attributeFilepathHTTP:
		return object.AttributeFilePath
	case attributeFilenameHTTP:
		return object.AttributeFileName
	default:
		return s
	}
}

func getOffsetAndLimit(offset, limit *int) (int, int, error) {
	var (
		off = offsetDefault
		lim = limitDefault
	)

	if offset != nil {
		if *offset < offsetMin {
			return 0, 0, fmt.Errorf("offset %d < %d", *offset, offsetMin)
		}

		off = *offset
	}

	if limit != nil {
		if *limit < limitMin {
			return 0, 0, fmt.Errorf("limit %d < %d", *limit, limitMin)
		}
		if *limit > limitMax {
			return 0, 0, fmt.Errorf("limit %d > %d", *limit, limitMax)
		}

		lim = *limit
	}

	return off, lim, nil
}

func getLimit(limit *int) (int, error) {
	var lim = limitDefault

	if limit != nil {
		if *limit < limitMin {
			return 0, fmt.Errorf("limit %d < %d", *limit, limitMin)
		}
		if *limit > limitMax {
			return 0, fmt.Errorf("limit %d > %d", *limit, limitMax)
		}

		lim = *limit
	}

	return lim, nil
}

func isValidKeyValue(key, value string) bool {
	return len(key) > 0 && len(value) > 0 && strings.HasPrefix(key, userAttributeHeaderPrefix)
}

func processKey(key string) string {
	clearKey := strings.TrimPrefix(key, userAttributeHeaderPrefix)
	if strings.HasPrefix(clearKey, neofsAttributeHeaderPrefix) {
		return systemTranslator(clearKey, neofsAttributeHeaderPrefix)
	}
	return clearKey
}

func parseAndFilterAttributes(logger *zap.Logger, jsonAttr *string) (map[string]string, error) {
	parsed := make(map[string]string)
	if jsonAttr == nil {
		logger.Debug("JSON attribute pointer is nil")
		return parsed, nil
	}

	if err := json.Unmarshal([]byte(*jsonAttr), &parsed); err != nil {
		return nil, err
	}

	result := filterAttributes(logger, parsed)
	return result, nil
}

func filterAttributes(logger *zap.Logger, attributes map[string]string) map[string]string {
	for key, value := range attributes {
		if key == "" || value == "" {
			delete(attributes, key)
			continue
		}
		logger.Debug("Filtered attribute", zap.String("key", key), zap.String("value", value))
	}
	return attributes
}

func paramIsPositive(s *string) bool {
	if s != nil {
		switch *s {
		case "1", "t", "T", "true", "TRUE", "True", "y", "yes", "Y", "YES", "Yes":
			return true
		}
	}
	return false
}

func addExpirationHeaders(headers map[string]string, params apiserver.NewUploadContainerObjectParams) {
	// Add non-empty string pointer values to the map
	if params.XNeofsExpirationDuration != nil && *params.XNeofsExpirationDuration != "" {
		headers[ExpirationDurationAttr] = *params.XNeofsExpirationDuration
	}
	if params.XNeofsExpirationTimestamp != nil && *params.XNeofsExpirationTimestamp != "" {
		headers[ExpirationTimestampAttr] = *params.XNeofsExpirationTimestamp
	}
	if params.XNeofsExpirationRFC3339 != nil && *params.XNeofsExpirationRFC3339 != "" {
		headers[ExpirationRFC3339Attr] = *params.XNeofsExpirationRFC3339
	}
}

// shares code of NeoFS object recording performed by various RestAPI methods.
func (a *RestAPI) putObject(ctx echo.Context, hdr object.Object, bt *bearer.Token, sessionToken *sessionv2.Token, wp func(io.Writer) error) (oid.ID, error) {
	var opts client.PrmObjectPutInit
	if bt != nil {
		opts.WithBearerToken(*bt)
	}
	if sessionToken != nil {
		opts.WithinSessionV2(*sessionToken)
	}
	writer, err := a.pool.ObjectPutInit(ctx.Request().Context(), hdr, a.signer, opts)
	if err != nil {
		return oid.ID{}, fmt.Errorf("init: %w", err)
	}

	err = wp(writer)
	if err != nil {
		return oid.ID{}, fmt.Errorf("write: %w", err)
	}

	if err = writer.Close(); err != nil {
		return oid.ID{}, fmt.Errorf("writer close: %w", err)
	}

	return writer.GetResult().StoredObjectID(), nil
}

func isDomainName(d string) error {
	if len(d) < 3 {
		return errors.New("domain name is too short")
	}

	if len(d) > 255 {
		return errors.New("domain name is too long")
	}

	// Raw IP is not a valid domain.
	if ip := net.ParseIP(d); ip != nil {
		return errors.New("IP addresses are not valid domain names in this context")
	}

	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return errors.New("domain must have at least a TLD (e.g., example.com)")
	}

	for _, label := range labels {
		l := len(label)
		if l < 1 || l > 63 {
			return errors.New("domain labels must be between 1 and 63 characters")
		}
		if label[0] == '-' || label[l-1] == '-' {
			return errors.New("domain labels cannot start or end with a hyphen")
		}

		for _, char := range label {
			isAlphaNum := (char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9')

			if !isAlphaNum && char != '-' {
				return errors.New("domain contains invalid characters")
			}
		}
	}

	return nil
}

func getSessionTokenV2(v string) (*sessionv2.Token, error) {
	tokenBts, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("base64 encoding: %w", err)
	}

	lock := tokenBts[:sessionLockSize]

	var st sessionv2.Token
	if err = st.Unmarshal(tokenBts[sessionLockSize:]); err != nil {
		return nil, fmt.Errorf("token unmarshal: %w", err)
	}

	lockHash := sha256.Sum256(lock)
	if !bytes.Equal(lockHash[:], st.AppData()) {
		return nil, fmt.Errorf("lock mismatch: %w", err)
	}

	if !st.VerifySignature() {
		return nil, errors.New("invalid signature")
	}

	return &st, nil
}

func prepareSessionTokenV2Expiration(tokenIssueTime time.Time, apiParams apiserver.SessionTokenV2Request) (time.Time, error) {
	var expireAt = tokenIssueTime.Add(defaultSessionTokenExpiration)

	if apiParams.ExpirationRfc3339 != nil && *apiParams.ExpirationRfc3339 != "" {
		exp, err := time.Parse(time.RFC3339, *apiParams.ExpirationRfc3339)
		if err != nil {
			return time.Time{}, errors.New("format must be in RFC3339")
		}

		if tokenIssueTime.After(exp) {
			return time.Time{}, errors.New("must be in the future")
		}

		expireAt = exp
	}

	if apiParams.ExpirationTimestamp != nil && *apiParams.ExpirationTimestamp > 0 {
		exp := time.Unix(int64(*apiParams.ExpirationTimestamp), 0)
		if tokenIssueTime.After(exp) {
			return time.Time{}, errors.New("must be in the future")
		}

		expireAt = exp
	}

	if apiParams.ExpirationDuration != nil && *apiParams.ExpirationDuration != "" {
		exp, err := time.ParseDuration(*apiParams.ExpirationDuration)
		if err != nil {
			return time.Time{}, errors.New("format must be in RFC3339")
		}

		expireAt = tokenIssueTime.Add(exp)
	}

	return expireAt, nil
}
