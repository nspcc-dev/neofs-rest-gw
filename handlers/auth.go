package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

const defaultTokenExpDuration = 100 // in epoch

type headersParams struct {
	XBearerLifetime    uint64
	XBearerOwnerID     string
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
	prm := headersParams{
		XBearerOwnerID:     params.XBearerOwnerId,
		XBearerForAllUsers: *params.XBearerForAllUsers,
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
	var tokens []apiserver.Bearer
	if err := ctx.Bind(&tokens); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err))
	}

	commonPrm := newHeaderParams(params)

	tokenNames := make(map[string]struct{})
	response := make([]*apiserver.TokenResponse, len(tokens))
	for i, token := range tokens {
		if _, ok := tokenNames[token.Name]; ok {
			err := fmt.Errorf("duplicated token name '%s'", token.Name)
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("token", err))
		}
		tokenNames[token.Name] = struct{}{}

		isObject, err := IsObjectToken(token)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
		}

		if isObject {
			prm := newObjectParams(commonPrm, token)
			response[i], err = prepareObjectToken(ctx.Request().Context(), prm, a.pool, a.signer.UserID())
		} else {
			prm := newContainerParams(commonPrm, token)
			response[i], err = prepareContainerTokens(ctx.Request().Context(), prm, a.pool, a.signer.Public())
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
	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect, false)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid bearer token", err)
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

func prepareObjectToken(ctx context.Context, params objectTokenParams, pool *pool.Pool, owner user.ID) (*apiserver.TokenResponse, error) {
	btoken, err := util.ToNativeObjectToken(params.Records)
	if err != nil {
		return nil, fmt.Errorf("couldn't transform token to native: %w", err)
	}

	var issuer user.ID
	if err = issuer.DecodeString(params.XBearerOwnerID); err != nil {
		return nil, fmt.Errorf("invalid bearer owner: %w", err)
	}
	btoken.SetIssuer(issuer)

	if !params.XBearerForAllUsers {
		btoken.ForUser(owner)
	}

	iat, exp, err := getTokenLifetime(ctx, pool, params.XBearerLifetime)
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

func prepareContainerTokens(ctx context.Context, params containerTokenParams, pool *pool.Pool, pubKey neofscrypto.PublicKey) (*apiserver.TokenResponse, error) {
	iat, exp, err := getTokenLifetime(ctx, pool, params.XBearerLifetime)
	if err != nil {
		return nil, fmt.Errorf("couldn't get lifetime: %w", err)
	}

	var ownerID user.ID
	if err = ownerID.DecodeString(params.XBearerOwnerID); err != nil {
		return nil, fmt.Errorf("invalid bearer owner: %w", err)
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

func getCurrentEpoch(ctx context.Context, p *pool.Pool) (uint64, error) {
	netInfo, err := p.NetworkInfo(ctx, client.PrmNetworkInfo{})
	if err != nil {
		return 0, fmt.Errorf("couldn't get netwokr info: %w", err)
	}

	return netInfo.CurrentEpoch(), nil
}

func getTokenLifetime(ctx context.Context, p *pool.Pool, expDuration uint64) (uint64, uint64, error) {
	currEpoch, err := getCurrentEpoch(ctx, p)
	if err != nil {
		return 0, 0, err
	}

	var lifetimeDuration uint64 = defaultTokenExpDuration
	if expDuration != 0 {
		lifetimeDuration = expDuration
	}

	return currEpoch, currEpoch + lifetimeDuration, nil
}
