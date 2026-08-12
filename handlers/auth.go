package handlers

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

const (
	defaultTokenExpDuration = 100 // in epoch

	defaultSessionTokenExpiration = 24 * time.Hour

	sessionLockSize = 32
)

var (
	fakeSignature = neofscrypto.NewSignatureFromRawKey(neofscrypto.ECDSA_SHA512, []byte{}, []byte{})
)

type objectTokenParams struct {
	Records  []apiserver.Record
	Issuer   string
	Lifetime uint64
}

func prepareObjectToken(ctx context.Context, params objectTokenParams, networkInfoGetter networkInfoGetter, owner user.ID) (string, error) {
	btoken, err := util.ToNativeObjectToken(params.Records)
	if err != nil {
		return "", fmt.Errorf("couldn't transform token to native: %w", err)
	}

	var issuer user.ID
	if err = issuer.DecodeString(params.Issuer); err != nil {
		return "", fmt.Errorf("invalid bearer issuer: %w", err)
	}
	btoken.SetIssuer(issuer)
	btoken.ForUser(owner)

	iat, exp, err := getTokenLifetime(ctx, networkInfoGetter, params.Lifetime)
	if err != nil {
		return "", fmt.Errorf("couldn't get lifetime: %w", err)
	}
	btoken.SetIat(iat)
	btoken.SetExp(exp)

	return base64.StdEncoding.EncodeToString(btoken.SignedData()), nil
}

func getCurrentEpoch(ctx context.Context, networkInfoGetter networkInfoGetter) (uint64, error) {
	netInfo, err := networkInfoGetter.NetworkInfo(ctx)
	if err != nil {
		return 0, fmt.Errorf("couldn't get netwokr info: %w", err)
	}

	return netInfo.CurrentEpoch(), nil
}

func getTokenLifetime(ctx context.Context, networkInfoGetter networkInfoGetter, expDuration uint64) (uint64, uint64, error) {
	currEpoch, err := getCurrentEpoch(ctx, networkInfoGetter)
	if err != nil {
		return 0, 0, err
	}

	var lifetimeDuration uint64 = defaultTokenExpDuration
	if expDuration != 0 {
		lifetimeDuration = expDuration
	}

	return currEpoch, currEpoch + lifetimeDuration, nil
}

// V2AuthSessionToken handler that forms v2 session token to sign.
func (a *RestAPI) V2AuthSessionToken(ctx echo.Context) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.V2AuthDuration)()
	}

	var (
		// https://github.com/nspcc-dev/neofs-node/pull/3671#discussion_r2709969518
		tokenIssueTime = time.Now().Add(-10 * time.Second)
		apiParams      apiserver.SessionTokenV2Request
		log            = a.log.With(zap.String(handlerFieldName, "V2AuthSessionToken"))
	)

	if err := ctx.Bind(&apiParams); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	var (
		originToken *session.Token
		tokenV2     session.Token
		owner       user.ID
		subjects    = make([]session.Target, 0, len(apiParams.Targets))
		contexts    = make([]session.Context, 0, len(apiParams.Contexts))
	)

	if err := owner.DecodeString(apiParams.Issuer); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid owner", err, log))
	}

	if len(apiParams.Targets) == 0 {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("no targets", errors.New("at least one target required"), log))
	}

	for _, target := range apiParams.Targets {
		if target == "" {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("empty target", errors.New("either owner or nns name must be set"), log))
		}

		var u user.ID
		if err := u.DecodeString(target); err != nil {
			if err = isDomainName(target); err != nil {
				return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid target nns name", err, log))
			}

			subjects = append(subjects, session.NewTargetNamed(target))
		} else {
			subjects = append(subjects, session.NewTargetUser(u))
		}
	}

	if err := tokenV2.SetSubjects(subjects); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid subjects", err, log))
	}

	if len(apiParams.Contexts) == 0 {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("no contexts", errors.New("at least one context required"), log))
	}

	var uniqueCnrIDs = make(map[cid.ID]struct{}, len(apiParams.Contexts))
	for _, apiTokenContext := range apiParams.Contexts {
		var cnrID cid.ID
		if apiTokenContext.ContainerID != "" {
			if err := cnrID.DecodeString(apiTokenContext.ContainerID); err != nil {
				return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid container id", err, log))
			}

			if _, ok := uniqueCnrIDs[cnrID]; ok {
				return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("two different contexts have the same container", fmt.Errorf("containerID: %s", cnrID.String()), log))
			}

			uniqueCnrIDs[cnrID] = struct{}{}
		}

		if len(apiTokenContext.Verbs) == 0 {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("zero verbs", errors.New("must have at least one verb"), log))
		}

		var uniqueVerbs = make(map[session.Verb]struct{}, len(apiTokenContext.Verbs))
		for _, verb := range apiTokenContext.Verbs {
			v, err := sessionVerbV2(verb)
			if err != nil {
				return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid verb", err, log))
			}

			uniqueVerbs[v] = struct{}{}
		}

		verbs := maps.Keys(uniqueVerbs)
		sortedVerbs := slices.Sorted(verbs)

		newContext, err := session.NewContext(cnrID, sortedVerbs)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid contexts", err, log))
		}

		contexts = append(contexts, newContext)
	}

	slices.SortFunc(contexts, func(a, b session.Context) int {
		return a.Container().Compare(b.Container())
	})

	if err := tokenV2.SetContexts(contexts); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid contexts", err, log))
	}

	expiration, err := prepareSessionTokenV2Expiration(tokenIssueTime, apiParams)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid expiration", err, log))
	}

	tokenV2.SetNbf(tokenIssueTime)
	tokenV2.SetIat(tokenIssueTime)
	tokenV2.SetExp(expiration)
	tokenV2.SetFinal(apiParams.Final)
	tokenV2.SetIssuer(owner)
	tokenV2.SetVersion(session.TokenCurrentVersion)

	if apiParams.Origin != "" {
		originToken, err = getOriginalSessionTokenV2(apiParams.Origin)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid origin token", err, log))
		}
	}

	if originToken != nil {
		tokenV2.SetOrigin(originToken)
	}

	lock := make([]byte, sessionLockSize)
	_, _ = rand.Read(lock)
	lockHash := sha256.Sum256(lock)

	if err := tokenV2.SetAppData(lockHash[:]); err != nil {
		return ctx.JSON(http.StatusInternalServerError, a.logAndGetErrorResponse("lock generation", err, log))
	}

	var resp = apiserver.SessionTokenv2Response{
		Token: base64.StdEncoding.EncodeToString(tokenV2.SignedData()),
		Lock:  base64.StdEncoding.EncodeToString(lock),
	}

	// For validation purposes only.
	tokenV2.AttachSignature(fakeSignature)
	if err = tokenV2.Validate(&noopNNSResolver{}); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("session token v2 validation", err, log))
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

func sessionVerbV2(verb apiserver.TokenVerb) (session.Verb, error) {
	switch verb {
	case "OBJECT_PUT":
		return session.VerbObjectPut, nil
	case "OBJECT_GET":
		return session.VerbObjectGet, nil
	case "OBJECT_HEAD":
		return session.VerbObjectHead, nil
	case "OBJECT_SEARCH":
		return session.VerbObjectSearch, nil
	case "OBJECT_DELETE":
		return session.VerbObjectDelete, nil
	case "OBJECT_RANGE":
		return session.VerbObjectRange, nil
	case "CONTAINER_PUT":
		return session.VerbContainerPut, nil
	case "CONTAINER_DELETE":
		return session.VerbContainerDelete, nil
	case "CONTAINER_SET_EACL":
		return session.VerbContainerSetEACL, nil
	case "CONTAINER_SET_ATTRIBUTE":
		return session.VerbContainerSetAttribute, nil
	case "CONTAINER_REMOVE_ATTRIBUTE":
		return session.VerbContainerRemoveAttribute, nil
	default:
		return 0, errors.New("unknown verb")
	}
}

func (a *RestAPI) V2CompleteAuthSessionToken(ctx echo.Context) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.V2AuthFormSessionTokenDuration)()
	}

	var (
		apiParams apiserver.CompleteSessionTokenV2Request
		log       = a.log.With(zap.String(handlerFieldName, "V2FormAuthSessionToken"))
	)

	if err := ctx.Bind(&apiParams); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	var scheme neofscrypto.Scheme
	switch apiParams.Scheme {
	case apiserver.WALLETCONNECT:
		scheme = neofscrypto.ECDSA_WALLETCONNECT
	case apiserver.SHA512:
		scheme = neofscrypto.ECDSA_SHA512
	case apiserver.DETERMINISTICSHA256:
		scheme = neofscrypto.ECDSA_DETERMINISTIC_SHA256
	case apiserver.N3:
		scheme = neofscrypto.N3
	default:
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("unknown scheme", fmt.Errorf("scheme: %s", apiParams.Scheme), log))
	}

	tokenBts, err := base64.StdEncoding.DecodeString(apiParams.Token)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("malformed base64 encoding", err, log))
	}

	var sessionToken session.Token
	if err = sessionToken.UnmarshalSignedData(tokenBts); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("malformed session token", err, log))
	}

	if len(apiParams.Lock) == 0 {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("empty lock", err, log))
	}

	lock, err := base64.StdEncoding.DecodeString(apiParams.Lock)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("malformed lock", err, log))
	}

	if len(lock) != sessionLockSize {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("wrong lock size", err, log))
	}

	lockHash := sha256.Sum256(lock)
	if !bytes.Equal(sessionToken.AppData(), lockHash[:]) {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid lock", err, log))
	}

	signatureValue, err := decodeHexOrBase64(apiParams.Signature)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("couldn't decode session token signature", err, log))
	}

	signatureKey, err := decodeHexOrBase64(apiParams.Key)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("couldn't fetch token owner key", err, log))
	}

	if scheme == neofscrypto.N3 {
		sessionToken.AttachSignature(neofscrypto.NewN3Signature(signatureValue, signatureKey))
	} else {
		if _, err = keys.NewPublicKeyFromBytes(signatureKey, elliptic.P256()); err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("couldn't extract token owner key", err, log))
		}

		sessionToken.AttachSignature(neofscrypto.NewSignatureFromRawKey(scheme, signatureKey, signatureValue))
		if !sessionToken.VerifySignature() {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid signature", errors.New("invalid signature"), log))
		}
	}

	if apiParams.Origin != "" {
		originToken, err := getOriginalSessionTokenV2(apiParams.Origin)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid origin token", err, log))
		}

		sessionToken.SetOrigin(originToken)
	}

	if err = sessionToken.Validate(&noopNNSResolver{}); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("session token v2 validation", err, log))
	}

	tokenWithLock := append(lock, sessionToken.Marshal()...)
	var resp = apiserver.BinarySessionV2{
		Token: base64.StdEncoding.EncodeToString(tokenWithLock),
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// UnsignedBearerToken handler that forms bearer token to sign.
func (a *RestAPI) UnsignedBearerToken(ctx echo.Context) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.UnsignedBearerTokenDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "UnsignedBearerToken"))

	var request apiserver.FormBearerRequest
	if err := ctx.Bind(&request); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	var tokenOwner user.ID
	if request.Owner != nil {
		if err := tokenOwner.DecodeString(*request.Owner); err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid bearer owner", err, log))
		}
	}

	tokenParams := objectTokenParams{
		Records: request.Records,
		Issuer:  request.Issuer,
	}

	if request.Lifetime != nil && *request.Lifetime > 0 {
		tokenParams.Lifetime = uint64(*request.Lifetime)
	}

	token, err := prepareObjectToken(ctx.Request().Context(), tokenParams, a.networkInfoGetter, tokenOwner)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	resp := apiserver.FormBearerResponse{
		Token: token,
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// CompleteUnsignedBearerToken handler that forms binary bearer token.
func (a *RestAPI) CompleteUnsignedBearerToken(ctx echo.Context) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.CompleteUnsignedBearerToken)()
	}

	var (
		apiParams apiserver.CompleteUnsignedBearerTokenRequest
		log       = a.log.With(zap.String(handlerFieldName, "CompleteUnsignedBearerToken"))
	)

	if err := ctx.Bind(&apiParams); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	var scheme neofscrypto.Scheme
	switch apiParams.Scheme {
	case apiserver.WALLETCONNECT:
		scheme = neofscrypto.ECDSA_WALLETCONNECT
	case apiserver.SHA512:
		scheme = neofscrypto.ECDSA_SHA512
	case apiserver.DETERMINISTICSHA256:
		scheme = neofscrypto.ECDSA_DETERMINISTIC_SHA256
	case apiserver.N3:
		scheme = neofscrypto.N3
	default:
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("unknown scheme", fmt.Errorf("scheme: %s", apiParams.Scheme), log))
	}

	btoken, err := assembleBearerTokenV2(apiParams.Token, apiParams.Signature, apiParams.Key, scheme)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid bearer token", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if btoken == nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(errors.New("empty bearer token")))
	}

	resp := &apiserver.BinaryBearer{
		Token: base64.StdEncoding.EncodeToString(btoken.Marshal()),
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}
