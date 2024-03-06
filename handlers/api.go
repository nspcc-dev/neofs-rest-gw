package handlers

import (
	"fmt"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	sessionv2 "github.com/nspcc-dev/neofs-api-go/v2/session"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
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
	Verb sessionv2.ContainerSessionVerb
}

const (
	// BearerPrefix is the prefix for authorization token.
	BearerPrefix       = "Bearer "
	BearerCookiePrefix = "Bearer="

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

	if !strings.HasPrefix(headerValue, BearerPrefix) {
		return "", fmt.Errorf("http auth: no bearer token")
	}

	if headerValue = strings.TrimPrefix(headerValue, BearerPrefix); len(headerValue) == 0 {
		return "", fmt.Errorf("http auth: bearer token is empty")
	}

	return headerValue, nil
}

func getPrincipalFromCookie(ctx echo.Context) (string, error) {
	var bearerCookie string

	for _, cookie := range ctx.Request().Cookies() {
		cookieValue := strings.TrimSpace(cookie.Value)
		if strings.HasPrefix(cookieValue, BearerCookiePrefix) {
			bearerCookie = strings.TrimPrefix(cookieValue, BearerCookiePrefix)
			if len(bearerCookie) == 0 {
				return "", fmt.Errorf("cookie auth: bearer token is empty")
			}

			return bearerCookie, nil
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

	principal, err = getPrincipalFromCookie(ctx)
	if err != nil {
		return "", err
	}

	if principal != "" {
		return principal, nil
	}

	return "", nil
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
