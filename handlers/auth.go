package handlers

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
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
)

type headersParams struct {
	XBearerLifetime    uint64
	XBearerIssuerID    string
	XBearerForAllUsers bool
}

type objectTokenParams struct {
	headersParams
	Records []apiserver.Record
	Name    string
}

type containerTokenParams struct {
	headersParams
	Rule *apiserver.Rule
	Name string
}

func newHeaderParams(params apiserver.AuthParams) headersParams {
	var bearerForAllUsers bool
	if params.XBearerForAllUsers != nil {
		bearerForAllUsers = *params.XBearerForAllUsers
	}

	prm := headersParams{
		XBearerIssuerID:    params.XBearerOwnerId,
		XBearerForAllUsers: bearerForAllUsers,
	}

	if params.XBearerLifetime != nil && *params.XBearerLifetime > 0 {
		prm.XBearerLifetime = uint64(*params.XBearerLifetime)
	}

	return prm
}

func newObjectParams(common headersParams, token apiserver.Bearer) objectTokenParams {
	return objectTokenParams{
		headersParams: common,
		Records:       token.Object,
		Name:          token.Name,
	}
}

func newContainerParams(common headersParams, token apiserver.Bearer) containerTokenParams {
	return containerTokenParams{
		headersParams: common,
		Rule:          token.Container,
		Name:          token.Name,
	}
}

// Auth handler that forms bearer token to sign.
func (a *RestAPI) Auth(ctx echo.Context, params apiserver.AuthParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.AuthDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "Auth"))

	var tokens []apiserver.Bearer
	if err := ctx.Bind(&tokens); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	commonPrm := newHeaderParams(params)

	tokenNames := make(map[string]struct{})
	response := make([]*apiserver.TokenResponse, len(tokens))
	for i, token := range tokens {
		if _, ok := tokenNames[token.Name]; ok {
			err := fmt.Errorf("duplicated token name '%s'", token.Name)
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("token", err, log))
		}
		tokenNames[token.Name] = struct{}{}

		isObject, err := IsObjectToken(token)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
		}

		if isObject {
			prm := newObjectParams(commonPrm, token)
			response[i], err = prepareObjectToken(ctx.Request().Context(), prm, a.networkInfoGetter, a.signer.UserID())
		} else {
			prm := newContainerParams(commonPrm, token)
			response[i], err = prepareContainerTokens(ctx.Request().Context(), prm, a.networkInfoGetter, a.signer.Public())
		}

		if err != nil {
			return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
		}
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, response)
}

// FormBinaryBearer handler that forms binary bearer token using headers with body and signature.
func (a *RestAPI) FormBinaryBearer(ctx echo.Context, params apiserver.FormBinaryBearerParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.FormBinaryBearerDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "FormBinaryBearer"))

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, err := assembleBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
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

func prepareObjectToken(ctx context.Context, params objectTokenParams, networkInfoGetter networkInfoGetter, owner user.ID) (*apiserver.TokenResponse, error) {
	btoken, err := util.ToNativeObjectToken(params.Records)
	if err != nil {
		return nil, fmt.Errorf("couldn't transform token to native: %w", err)
	}

	var issuer user.ID
	if err = issuer.DecodeString(params.XBearerIssuerID); err != nil {
		return nil, fmt.Errorf("invalid bearer issuer: %w", err)
	}
	btoken.SetIssuer(issuer)

	if !params.XBearerForAllUsers {
		btoken.ForUser(owner)
	}

	iat, exp, err := getTokenLifetime(ctx, networkInfoGetter, params.XBearerLifetime)
	if err != nil {
		return nil, fmt.Errorf("couldn't get lifetime: %w", err)
	}
	btoken.SetIat(iat)
	btoken.SetExp(exp)

	binaryBearer := btoken.SignedData()

	return &apiserver.TokenResponse{
		Name:  &params.Name,
		Type:  apiserver.Object,
		Token: base64.StdEncoding.EncodeToString(binaryBearer),
	}, nil
}

func prepareContainerTokens(ctx context.Context, params containerTokenParams, networkInfoGetter networkInfoGetter, pubKey neofscrypto.PublicKey) (*apiserver.TokenResponse, error) {
	iat, exp, err := getTokenLifetime(ctx, networkInfoGetter, params.XBearerLifetime)
	if err != nil {
		return nil, fmt.Errorf("couldn't get lifetime: %w", err)
	}

	var ownerID user.ID
	if err = ownerID.DecodeString(params.XBearerIssuerID); err != nil {
		return nil, fmt.Errorf("invalid bearer issuer: %w", err)
	}

	if params.Rule == nil {
		return nil, errors.New("rule is empty")
	}

	stoken, err := util.ToNativeContainerToken(*params.Rule)
	if err != nil {
		return nil, fmt.Errorf("couldn't transform rule to native session token: %w", err)
	}

	stoken.SetID(uuid.New())
	stoken.SetIat(iat)
	stoken.SetExp(exp)

	stoken.SetAuthKey(pubKey)
	stoken.SetIssuer(ownerID)

	binaryToken := stoken.SignedData()

	return &apiserver.TokenResponse{
		Name:  &params.Name,
		Type:  apiserver.Container,
		Token: base64.StdEncoding.EncodeToString(binaryToken),
	}, nil
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
		expiration  = time.Now().Add(defaultSessionTokenExpiration)
		subjects    = make([]session.Target, 0, len(apiParams.Targets))
		contexts    = make([]session.Context, 0, len(apiParams.Contexts))
	)

	if err := owner.DecodeString(apiParams.Owner); err != nil {
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

	if apiParams.ExpirationRfc3339 != "" {
		expireAt, err := time.Parse(time.RFC3339, apiParams.ExpirationRfc3339)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid expiration", errors.New("format must be in RFC3339"), log))
		}

		if tokenIssueTime.After(expireAt) {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid expiration", errors.New("must be in the future"), log))
		}

		expiration = expireAt
	} else if apiParams.ExpirationDuration != "" {
		expDuration, err := time.ParseDuration(apiParams.ExpirationDuration)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid expiration duration", err, log))
		}

		if expDuration <= 0 {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid expiration duration", errors.New("must be positive"), log))
		}

		expiration = tokenIssueTime.Add(expDuration)
	}

	if apiParams.Origin != "" {
		originTokenBts, err := base64.StdEncoding.DecodeString(apiParams.Origin)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("origin token base64 decode failed", err, log))
		}

		var ot session.Token
		if err = ot.Unmarshal(originTokenBts); err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("origin token decode failed", err, log))
		}

		originToken = &ot
	}

	tokenV2.SetNbf(tokenIssueTime)
	tokenV2.SetIat(tokenIssueTime)
	tokenV2.SetExp(expiration)
	tokenV2.SetFinal(apiParams.Final)
	tokenV2.SetIssuer(owner)
	tokenV2.SetVersion(session.TokenCurrentVersion)

	if originToken != nil {
		tokenV2.SetOrigin(originToken)
	}

	var resp = apiserver.SessionTokenv2Response{
		Token: base64.StdEncoding.EncodeToString(tokenV2.SignedData()),
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
	case "OBJECT_RANGE_HASH":
		return session.VerbObjectRangeHash, nil
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

	signatureValue, err := base64.StdEncoding.DecodeString(apiParams.Value)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("couldn't decode session token signature", err, log))
	}

	var signatureKey []byte

	if scheme == neofscrypto.N3 {
		signatureKey, err = base64.StdEncoding.DecodeString(apiParams.Key)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("couldn't fetch token owner key", err, log))
		}

		sessionToken.AttachSignature(neofscrypto.NewN3Signature(signatureValue, signatureKey))
	} else {
		signatureKey, err = hex.DecodeString(apiParams.Key)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("couldn't fetch token owner key", err, log))
		}

		if _, err = keys.NewPublicKeyFromBytes(signatureKey, elliptic.P256()); err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("couldn't extract token owner key", err, log))
		}

		sessionToken.AttachSignature(neofscrypto.NewSignatureFromRawKey(scheme, signatureKey, signatureValue))
		if !sessionToken.VerifySignature() {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid signature", errors.New("invalid signature"), log))
		}
	}

	var resp = apiserver.BinarySessionV2{
		Token: base64.StdEncoding.EncodeToString(sessionToken.Marshal()),
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// UnsignedBearerToken handler that forms bearer token to sign.
func (a *RestAPI) UnsignedBearerToken(ctx echo.Context, params apiserver.UnsignedBearerTokenParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.UnsignedBearerTokenDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "UnsignedBearerToken"))

	var request apiserver.FormBearerRequest
	if err := ctx.Bind(&request); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	var tokenOwner user.ID
	if params.XBearerOwnerId != nil {
		if err := tokenOwner.DecodeString(*params.XBearerOwnerId); err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid bearer owner", err, log))
		}
	}

	prm := headersParams{
		XBearerIssuerID: params.XBearerIssuerId,
	}

	if params.XBearerLifetime != nil && *params.XBearerLifetime > 0 {
		prm.XBearerLifetime = uint64(*params.XBearerLifetime)
	}

	tokenParams := objectTokenParams{
		headersParams: prm,
		Records:       request.Records,
	}

	preparedTokenData, err := prepareObjectToken(ctx.Request().Context(), tokenParams, a.networkInfoGetter, tokenOwner)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	resp := apiserver.FormBearerResponse{
		Token: preparedTokenData.Token,
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}
