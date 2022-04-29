package handlers

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	objectv2 "github.com/nspcc-dev/neofs-api-go/v2/object"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
)

// PrmAttributes groups parameters to form attributes from request headers.
type PrmAttributes struct {
	DefaultTimestamp bool
	DefaultFileName  string
}

type epochDurations struct {
	currentEpoch  uint64
	msPerBlock    int64
	blockPerEpoch uint64
}

const (
	UserAttributeHeaderPrefix = "X-Attribute-"
	SystemAttributePrefix     = "__NEOFS__"

	ExpirationDurationAttr  = SystemAttributePrefix + "EXPIRATION_DURATION"
	ExpirationTimestampAttr = SystemAttributePrefix + "EXPIRATION_TIMESTAMP"
	ExpirationRFC3339Attr   = SystemAttributePrefix + "EXPIRATION_RFC3339"
)

var neofsAttributeHeaderPrefixes = [...]string{"Neofs-", "NEOFS-", "neofs-"}

func systemTranslator(key, prefix string) string {
	// replace specified prefix with `__NEOFS__`
	key = strings.Replace(key, prefix, SystemAttributePrefix, 1)

	// replace `-` with `_`
	key = strings.ReplaceAll(key, "-", "_")

	// replace with uppercase
	return strings.ToUpper(key)
}

func filterHeaders(header http.Header) map[string]string {
	result := make(map[string]string)
	prefix := UserAttributeHeaderPrefix

	for key, vals := range header {
		if len(key) == 0 || len(vals) == 0 || len(vals[0]) == 0 {
			continue
		}
		// checks that key has attribute prefix
		if !strings.HasPrefix(key, prefix) {
			continue
		}

		// removing attribute prefix
		key = strings.TrimPrefix(key, prefix)

		// checks that it's a system NeoFS header
		for _, system := range neofsAttributeHeaderPrefixes {
			if strings.HasPrefix(key, system) {
				key = systemTranslator(key, system)
				break
			}
		}

		// checks that attribute key not empty
		if len(key) == 0 {
			continue
		}

		result[key] = vals[0]
	}

	return result
}

// GetObjectAttributes forms object attributes from request headers.
func GetObjectAttributes(ctx context.Context, pool *pool.Pool, attrs []*models.Attribute, prm PrmAttributes) ([]object.Attribute, error) {
	headers := make(map[string]string, len(attrs))

	for _, attr := range attrs {
		headers[*attr.Key] = *attr.Value
	}
	delete(headers, object.AttributeFileName)

	if needParseExpiration(headers) {
		epochDuration, err := getEpochDurations(ctx, pool)
		if err != nil {
			return nil, fmt.Errorf("could not get epoch durations from network info: %w", err)
		}
		if err = prepareExpirationHeader(headers, epochDuration); err != nil {
			return nil, fmt.Errorf("could not prepare expiration header: %w", err)
		}
	}

	attributes := make([]object.Attribute, 0, len(headers))
	for key, val := range headers {
		attribute := object.NewAttribute()
		attribute.SetKey(key)
		attribute.SetValue(val)
		attributes = append(attributes, *attribute)
	}

	filename := object.NewAttribute()
	filename.SetKey(object.AttributeFileName)
	filename.SetValue(prm.DefaultFileName)
	attributes = append(attributes, *filename)

	if _, ok := headers[object.AttributeTimestamp]; !ok && prm.DefaultTimestamp {
		timestamp := object.NewAttribute()
		timestamp.SetKey(object.AttributeTimestamp)
		timestamp.SetValue(strconv.FormatInt(time.Now().Unix(), 10))
		attributes = append(attributes, *timestamp)
	}

	return attributes, nil
}

func getEpochDurations(ctx context.Context, p *pool.Pool) (*epochDurations, error) {
	networkInfo, err := p.NetworkInfo(ctx)
	if err != nil {
		return nil, err
	}

	res := &epochDurations{
		currentEpoch: networkInfo.CurrentEpoch(),
		msPerBlock:   networkInfo.MsPerBlock(),
	}

	networkInfo.NetworkConfig().IterateParameters(func(parameter *netmap.NetworkParameter) bool {
		if string(parameter.Key()) == "EpochDuration" {
			data := make([]byte, 8)
			copy(data, parameter.Value())
			res.blockPerEpoch = binary.LittleEndian.Uint64(data)
			return true
		}
		return false
	})
	if res.blockPerEpoch == 0 {
		return nil, fmt.Errorf("not found param: EpochDuration")
	}
	return res, nil
}

func needParseExpiration(headers map[string]string) bool {
	_, ok1 := headers[ExpirationDurationAttr]
	_, ok2 := headers[ExpirationRFC3339Attr]
	_, ok3 := headers[ExpirationTimestampAttr]
	return ok1 || ok2 || ok3
}

func prepareExpirationHeader(headers map[string]string, epochDurations *epochDurations) error {
	expirationInEpoch := headers[objectv2.SysAttributeExpEpoch]

	if timeRFC3339, ok := headers[ExpirationRFC3339Attr]; ok {
		expTime, err := time.Parse(time.RFC3339, timeRFC3339)
		if err != nil {
			return fmt.Errorf("couldn't parse value %s of header %s", timeRFC3339, ExpirationRFC3339Attr)
		}

		now := time.Now().UTC()
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
		headers[objectv2.SysAttributeExpEpoch] = expirationInEpoch
	}

	return nil
}

func updateExpirationHeader(headers map[string]string, durations *epochDurations, expDuration time.Duration) {
	epochDuration := durations.msPerBlock * int64(durations.blockPerEpoch)
	numEpoch := expDuration.Milliseconds() / epochDuration
	headers[objectv2.SysAttributeExpEpoch] = strconv.FormatInt(int64(durations.currentEpoch)+numEpoch, 10)
}
