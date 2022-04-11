package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-openapi/errors"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"go.uber.org/zap"
)

// API is a REST v1 request handler.
type API struct {
	log              *zap.Logger
	pool             *pool.Pool
	key              *keys.PrivateKey
	defaultTimestamp bool
}

// PrmAPI groups parameters to init rest API.
type PrmAPI struct {
	Logger           *zap.Logger
	Pool             *pool.Pool
	Key              *keys.PrivateKey
	DefaultTimestamp bool
}

type BearerToken struct {
	Token     string
	Signature string
	Key       string
}

// New creates a new API using specified logger, connection pool and other parameters.
func New(prm *PrmAPI) *API {
	return &API{
		log:              prm.Logger,
		pool:             prm.Pool,
		key:              prm.Key,
		defaultTimestamp: prm.DefaultTimestamp,
	}
}

const (
	bearerPrefix = "Bearer "
)

func (a *API) Configure(api *operations.NeofsRestGwAPI) http.Handler {
	api.ServeError = errors.ServeError

	api.AuthHandler = operations.AuthHandlerFunc(a.PostAuth)
	api.PutObjectHandler = operations.PutObjectHandlerFunc(a.PutObjects)
	api.PutContainerHandler = operations.PutContainerHandlerFunc(a.PutContainers)
	api.GetContainerHandler = operations.GetContainerHandlerFunc(a.GetContainer)
	api.BearerAuthAuth = func(s string) (*models.Principal, error) {
		if !strings.HasPrefix(s, bearerPrefix) {
			return nil, fmt.Errorf("has not bearer token")
		}
		if s = strings.TrimPrefix(s, bearerPrefix); len(s) == 0 {
			return nil, fmt.Errorf("bearer token is empty")
		}

		return (*models.Principal)(&s), nil
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation.
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics.
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}
