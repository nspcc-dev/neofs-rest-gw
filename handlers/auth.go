package handlers

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/go-openapi/runtime/middleware"
	"github.com/google/uuid"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
)

const defaultTokenExpDuration = 100 // in epoch

type headersParams struct {
	XBearerLifetime uint64
	XBearerOwnerID  string
}

type objectTokenParams struct {
	headersParams
	Records []*models.Record
	Name    string
}

type containerTokenParams struct {
	headersParams
	Rule *models.Rule
	Name string
}

func newHeaderParams(params operations.AuthParams) headersParams {
	prm := headersParams{
		XBearerOwnerID: params.XBearerOwnerID,
	}

	if params.XBearerLifetime != nil && *params.XBearerLifetime > 0 {
		prm.XBearerLifetime = uint64(*params.XBearerLifetime)
	}

	return prm
}

func newObjectParams(common headersParams, token *models.Bearer) objectTokenParams {
	return objectTokenParams{
		headersParams: common,
		Records:       token.Object,
		Name:          token.Name,
	}
}

func newContainerParams(common headersParams, token *models.Bearer) containerTokenParams {
	return containerTokenParams{
		headersParams: common,
		Rule:          token.Container,
		Name:          token.Name,
	}
}

// PostAuth handler that forms bearer token to sign.
func (a *API) PostAuth(params operations.AuthParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	commonPrm := newHeaderParams(params)

	tokenNames := make(map[string]struct{})
	response := make([]*models.TokenResponse, len(params.Tokens))
	for i, token := range params.Tokens {
		if _, ok := tokenNames[token.Name]; ok {
			return operations.NewAuthBadRequest().WithPayload(models.Error(fmt.Sprintf("duplicated token name '%s'", token.Name)))
		}
		tokenNames[token.Name] = struct{}{}

		isObject, err := IsObjectToken(token)
		if err != nil {
			return operations.NewAuthBadRequest().WithPayload(models.Error(err.Error()))
		}

		if isObject {
			prm := newObjectParams(commonPrm, token)
			response[i], err = prepareObjectToken(ctx, prm, a.pool)
		} else {
			prm := newContainerParams(commonPrm, token)
			response[i], err = prepareContainerTokens(ctx, prm, a.pool, a.key.PublicKey())
		}
		if err != nil {
			return operations.NewAuthBadRequest().WithPayload(models.Error(err.Error()))
		}
	}

	return operations.NewAuthOK().WithPayload(response)
}

func prepareObjectToken(ctx context.Context, params objectTokenParams, pool *pool.Pool) (*models.TokenResponse, error) {
	btoken, err := util.ToNativeObjectToken(params.Records)
	if err != nil {
		return nil, fmt.Errorf("couldn't transform token to native: %w", err)
	}
	btoken.SetOwner(pool.OwnerID())

	iat, exp, err := getTokenLifetime(ctx, pool, params.XBearerLifetime)
	if err != nil {
		return nil, fmt.Errorf("couldn't get lifetime: %w", err)
	}
	btoken.SetLifetime(exp, 0, iat)

	binaryBearer, err := btoken.ToV2().GetBody().StableMarshal(nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal bearer token: %w", err)
	}

	return &models.TokenResponse{
		Name:  params.Name,
		Type:  models.NewTokenType(models.TokenTypeObject),
		Token: util.NewString(base64.StdEncoding.EncodeToString(binaryBearer)),
	}, nil
}

func prepareContainerTokens(ctx context.Context, params containerTokenParams, pool *pool.Pool, key *keys.PublicKey) (*models.TokenResponse, error) {
	iat, exp, err := getTokenLifetime(ctx, pool, params.XBearerLifetime)
	if err != nil {
		return nil, fmt.Errorf("couldn't get lifetime: %w", err)
	}

	var ownerID owner.ID
	if err = ownerID.Parse(params.XBearerOwnerID); err != nil {
		return nil, fmt.Errorf("invalid bearer owner: %w", err)
	}

	stoken, err := util.ToNativeContainerToken(params.Rule)
	if err != nil {
		return nil, fmt.Errorf("couldn't transform rule to native session token: %w", err)
	}

	uid, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, err
	}
	stoken.SetID(uid)

	stoken.SetOwnerID(&ownerID)

	stoken.SetIat(iat)
	stoken.SetExp(exp)
	stoken.SetSessionKey(key.Bytes())

	binaryToken, err := stoken.ToV2().GetBody().StableMarshal(nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal session token: %w", err)
	}

	return &models.TokenResponse{
		Name:  params.Name,
		Type:  models.NewTokenType(models.TokenTypeContainer),
		Token: util.NewString(base64.StdEncoding.EncodeToString(binaryToken)),
	}, nil
}

func getCurrentEpoch(ctx context.Context, p *pool.Pool) (uint64, error) {
	netInfo, err := p.NetworkInfo(ctx)
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
