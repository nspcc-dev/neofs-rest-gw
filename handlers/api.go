package handlers

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

// PrmAPI groups parameters to init rest API.
type PrmAPI struct {
	Logger           *zap.Logger
	Pool             *pool.Pool
	Key              *keys.PrivateKey
	DefaultTimestamp bool
	MaxObjectSize    int64

	GateMetric             *metrics.GateMetrics
	PrometheusService      *metrics.Service
	PprofService           *metrics.Service
	ServiceShutdownTimeout time.Duration
}

type BearerToken struct {
	Token     string
	Signature string
	Key       string
}

type SessionToken struct {
	BearerToken
	Verb session.ContainerVerb
}

const (
	// bearerCookieName is the name of the bearer cookie.
	bearerCookieName = "Bearer"
	// bearerPrefix is the prefix for authorization token.
	bearerPrefix = bearerCookieName + " "

	accessControlAllowOriginHeader = "Access-Control-Allow-Origin"
	authorizationHeader            = "Authorization"
)

//go:generate go run github.com/deepmap/oapi-codegen/cmd/oapi-codegen --config=server.cfg.yaml ../spec/rest.yaml

// NewAPI creates a new RestAPI using specified logger, connection pool and other parameters.
func NewAPI(prm *PrmAPI) *RestAPI {
	signer := user.NewAutoIDSignerRFC6979(prm.Key.PrivateKey)

	return &RestAPI{
		log:              prm.Logger,
		pool:             prm.Pool,
		signer:           signer,
		defaultTimestamp: prm.DefaultTimestamp,
		maxObjectSize:    prm.MaxObjectSize,

		prometheusService:      prm.PrometheusService,
		pprofService:           prm.PprofService,
		gateMetric:             prm.GateMetric,
		serviceShutdownTimeout: prm.ServiceShutdownTimeout,
	}
}

func getPrincipalFromHeader(ctx echo.Context) (string, error) {
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

func getPrincipalFromCookie(ctx echo.Context) (string, error) {
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
	principal, err := getPrincipalFromHeader(ctx)
	if err != nil {
		return "", err
	}

	if principal != "" {
		return principal, nil
	}

	return getPrincipalFromCookie(ctx)
}

func (a *RestAPI) logAndGetErrorResponse(msg string, err error, fields ...zap.Field) *apiserver.ErrorResponse {
	fields = append(fields, zap.Error(err))
	a.log.Error(msg, fields...)
	return util.NewErrorResponse(fmt.Errorf("%s: %w", msg, err))
}

// RestAPI is a REST v1 request handler.
type RestAPI struct {
	log              *zap.Logger
	pool             *pool.Pool
	signer           user.Signer
	defaultTimestamp bool
	maxObjectSize    int64

	gateMetric             *metrics.GateMetrics
	prometheusService      *metrics.Service
	pprofService           *metrics.Service
	serviceShutdownTimeout time.Duration
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
