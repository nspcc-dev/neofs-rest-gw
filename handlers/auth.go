package handlers

import (
	"context"
	"crypto/ecdsa"
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

// PostAuth handler that forms bearer token to sign.
func (a *API) PostAuth(params operations.AuthParams) middleware.Responder {
	var (
		err  error
		resp *models.TokenResponse
	)

	if params.XBearerScope == "object" {
		resp, err = prepareObjectToken(params, a.pool)
	} else {
		resp, err = prepareContainerTokens(params, a.pool, a.key.PublicKey())
	}
	if err != nil {
		return operations.NewAuthBadRequest().WithPayload(models.Error(err.Error()))
	}

	return operations.NewAuthOK().WithPayload(resp)
}

func prepareObjectToken(params operations.AuthParams, pool *pool.Pool) (*models.TokenResponse, error) {
	ctx := params.HTTPRequest.Context()

	btoken, err := util.ToNativeObjectToken(params.Token)
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

	var resp models.TokenResponse
	resp.Type = models.NewTokenType(models.TokenTypeObject)
	resp.Token = util.NewString(base64.StdEncoding.EncodeToString(binaryBearer))

	return &resp, nil
}

func prepareContainerTokens(params operations.AuthParams, pool *pool.Pool, key *keys.PublicKey) (*models.TokenResponse, error) {
	ctx := params.HTTPRequest.Context()

	iat, exp, err := getTokenLifetime(ctx, pool, params.XBearerLifetime)
	if err != nil {
		return nil, fmt.Errorf("couldn't get lifetime: %w", err)
	}

	ownerKey, err := keys.NewPublicKeyFromString(params.XBearerSignatureKey)
	if err != nil {
		return nil, fmt.Errorf("invalid singature key: %w", err)
	}

	var resp models.TokenResponse
	resp.Type = models.NewTokenType(models.TokenTypeContainer)

	stoken, err := util.ToNativeContainerToken(params.Token)
	if err != nil {
		return nil, fmt.Errorf("couldn't transform rule to native session token: %w", err)
	}

	uid, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, err
	}
	stoken.SetID(uid)

	stoken.SetOwnerID(owner.NewIDFromPublicKey((*ecdsa.PublicKey)(ownerKey)))

	stoken.SetIat(iat)
	stoken.SetExp(exp)
	stoken.SetSessionKey(key.Bytes())

	binaryToken, err := stoken.ToV2().GetBody().StableMarshal(nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal session token: %w", err)
	}

	resp.Token = util.NewString(base64.StdEncoding.EncodeToString(binaryToken))

	return &resp, nil
}

func getCurrentEpoch(ctx context.Context, p *pool.Pool) (uint64, error) {
	netInfo, err := p.NetworkInfo(ctx)
	if err != nil {
		return 0, fmt.Errorf("couldn't get netwokr info: %w", err)
	}

	return netInfo.CurrentEpoch(), nil
}

func getTokenLifetime(ctx context.Context, p *pool.Pool, expDuration *int64) (uint64, uint64, error) {
	currEpoch, err := getCurrentEpoch(ctx, p)
	if err != nil {
		return 0, 0, err
	}

	var lifetimeDuration uint64 = defaultTokenExpDuration
	if expDuration != nil && *expDuration > 0 {
		lifetimeDuration = uint64(*expDuration)
	}

	return currEpoch, currEpoch + lifetimeDuration, nil
}
