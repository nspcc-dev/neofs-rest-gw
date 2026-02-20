package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/cache"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	sessionv2 "github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

// PrmAPI groups parameters to init rest API.
type PrmAPI struct {
	Logger           *zap.Logger
	Pool             *pool.Pool
	Key              *keys.PrivateKey
	NNSName          string
	DefaultTimestamp bool
	// Size limit for buffering of object payloads. Must be positive.
	MaxPayloadBufferSize uint64

	GateMetric             *metrics.GateMetrics
	ApiMetric              *metrics.ApiMetrics
	PrometheusService      *metrics.Service
	PprofService           *metrics.Service
	ServiceShutdownTimeout time.Duration
	WaiterOperationTimeout time.Duration
}

type BearerToken struct {
	Token     string
	Signature string
	Key       string
}

type networkInfoGetter interface {
	NetworkInfo(ctx context.Context) (netmap.NetworkInfo, error)
	StoreNetworkInfo(ni netmap.NetworkInfo)
}

const (
	// bearerCookieName is the name of the bearer cookie.
	bearerCookieName = "Bearer"
	// bearerPrefix is the prefix for authorization token.
	bearerPrefix = bearerCookieName + " "

	accessControlAllowOriginHeader = "Access-Control-Allow-Origin"
	authorizationHeader            = "Authorization"
	locationHeader                 = "Location"

	neofsBearerToken = "NeoFS-Bearer-Token"
)

//go:generate go run github.com/deepmap/oapi-codegen/cmd/oapi-codegen --config=server.cfg.yaml ../spec/rest.yaml

// NewAPI creates a new RestAPI using specified logger, connection pool and other parameters.
func NewAPI(prm *PrmAPI) (*RestAPI, error) {
	if prm.MaxPayloadBufferSize == 0 {
		return nil, errors.New("zero payload buffer size limit")
	}
	signer := user.NewAutoIDSignerRFC6979(prm.Key.PrivateKey)

	return &RestAPI{
		log:               prm.Logger,
		pool:              prm.Pool,
		signer:            signer,
		nnsName:           prm.NNSName,
		defaultTimestamp:  prm.DefaultTimestamp,
		payloadBufferSize: prm.MaxPayloadBufferSize,

		prometheusService:      prm.PrometheusService,
		pprofService:           prm.PprofService,
		gateMetric:             prm.GateMetric,
		apiMetric:              prm.ApiMetric,
		serviceShutdownTimeout: prm.ServiceShutdownTimeout,
		networkInfoGetter:      cache.NewNetworkInfoCache(prm.Pool),
	}, nil
}

func getAuthorizationHeaderValue(ctx echo.Context) (string, error) {
	headerValue := ctx.Request().Header.Get(authorizationHeader)
	if headerValue == "" {
		// just not exists
		return "", nil
	}

	if !strings.HasPrefix(headerValue, bearerPrefix) {
		return "", errors.New("http auth: no bearer token")
	}

	if headerValue = strings.TrimPrefix(headerValue, bearerPrefix); len(headerValue) == 0 {
		return "", errors.New("http auth: bearer token is empty")
	}

	return headerValue, nil
}

func getNeoFSBearerFromCookie(ctx echo.Context) (string, error) {
	for _, cookie := range ctx.Request().Cookies() {
		if cookie.Name == bearerCookieName {
			if len(cookie.Value) == 0 {
				return "", errors.New("cookie auth: bearer token is empty")
			}

			return cookie.Value, nil
		}
	}

	return "", nil
}

func getPrincipal(ctx echo.Context) (string, error) {
	headerValue, err := getAuthorizationHeaderValue(ctx)
	if err != nil {
		return "", err
	}

	if headerValue != "" {
		return headerValue, nil
	}

	return getNeoFSBearerFromCookie(ctx)
}

func getNeoFSBearerToken(ctx echo.Context) (string, error) {
	if principal := ctx.Request().Header.Get(neofsBearerToken); principal != "" {
		return principal, nil
	}

	return getNeoFSBearerFromCookie(ctx)
}

func (a *RestAPI) logAndGetErrorResponse(msg string, err error, log *zap.Logger) *apiserver.ErrorResponse {
	log.Error(msg, zap.Error(err))
	return util.NewErrorResponse(fmt.Errorf("%s: %w", msg, err))
}

// RestAPI is a REST v1 request handler.
type RestAPI struct {
	log               *zap.Logger
	pool              *pool.Pool
	signer            user.Signer
	defaultTimestamp  bool
	payloadBufferSize uint64
	nnsName           string

	gateMetric             *metrics.GateMetrics
	apiMetric              *metrics.ApiMetrics
	prometheusService      *metrics.Service
	pprofService           *metrics.Service
	serviceShutdownTimeout time.Duration
	networkInfoGetter      networkInfoGetter
}

func (a *RestAPI) StartCallback() {
	if a.gateMetric == nil {
		return
	}

	a.gateMetric.SetHealth(1)
}

func (a *RestAPI) RunServices() {
	go a.pprofService.Start()
	go a.prometheusService.Start()
}

// StopServices stops all running services with configured timeout.
func (a *RestAPI) StopServices() {
	ctx, cancel := context.WithTimeout(context.Background(), a.serviceShutdownTimeout)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		a.pprofService.ShutDown(ctx)
	}()
	go func() {
		defer wg.Done()
		a.prometheusService.ShutDown(ctx)
	}()
	wg.Wait()
}

// LocationHeader generates Location header for container creation request.
func LocationHeader(containerID cid.ID) string {
	return fmt.Sprintf("/v1/containers/%s", containerID.EncodeToString())
}

func getBearerAndSession(ctx echo.Context, signature *apiserver.SignatureParam, key *apiserver.SignatureKeyParam, walletConnect bool) (*bearer.Token, *sessionv2.Token, error) {
	headerValue, err := getAuthorizationHeaderValue(ctx)
	if err != nil {
		// Authorization header has invalid format or empty.
		return nil, nil, err
	}

	// Try to form NeoFS bearer.
	btoken, err := assembleBearerToken(headerValue, signature, key, walletConnect)
	if err == nil {
		// It is an "old call" with bearer in Authorization header.
		if btoken != nil {
			return btoken, nil, nil
		}
	}

	var sessionTokenV2 *sessionv2.Token
	if headerValue != "" {
		sessionTokenV2, err = getSessionTokenV2(headerValue)
		if err != nil {
			return nil, nil, fmt.Errorf("session v2 is invalid: %w", err)
		}
	}

	btokenStr, err := getNeoFSBearerToken(ctx)
	if err != nil {
		return nil, nil, err
	}

	btoken, err = assembleBearerToken(btokenStr, signature, key, walletConnect)
	if err != nil {
		// btokenStr was not empty, but something wrong with bearer.
		return nil, nil, err
	}

	return btoken, sessionTokenV2, nil
}

func sessionTokensFromAuthHeader(ctx echo.Context, v2Verb sessionv2.Verb, cnrID cid.ID) (*sessionv2.Token, error) {
	headerValue, err := getAuthorizationHeaderValue(ctx)
	if err != nil {
		return nil, err
	}

	if headerValue == "" {
		return nil, errors.New("empty auth header")
	}

	sessionTokenV2, err := getSessionTokenV2(headerValue)
	if err != nil {
		return nil, err
	}

	switch v2Verb {
	case sessionv2.VerbContainerDelete,
		sessionv2.VerbContainerPut,
		sessionv2.VerbContainerSetEACL,
		sessionv2.VerbContainerSetAttribute,
		sessionv2.VerbContainerRemoveAttribute:
	default:
		return nil, fmt.Errorf("invalid verb: %d", v2Verb)
	}

	if err = prepareSessionTokenV2(sessionTokenV2, cnrID, v2Verb); err != nil {
		return nil, err
	}

	return sessionTokenV2, nil
}
