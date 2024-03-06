package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/loads"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	sessionv2 "github.com/nspcc-dev/neofs-api-go/v2/session"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

// API is a REST v1 request handler.
type API struct {
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

// ContextKey is used for context.Context value. The value requires a key that is not primitive type.
type ContextKey string

// specBasePath is used for keeping in memory basePath from restapi.SwaggerJSON.
var specBasePath string

func init() {
	specBasePath, _ = getBasePath()
}

const (
	// BearerPrefix is the prefix for authorization token.
	BearerPrefix       = "Bearer "
	BearerCookiePrefix = "Bearer="

	// ContextKeyRequestID is the ContextKey for RequestID.
	ContextKeyRequestID ContextKey = "requestID"

	accessControlAllowOriginHeader = "Access-Control-Allow-Origin"
)

// New creates a new API using specified logger, connection pool and other parameters.
func New(prm *PrmAPI) *API {
	signer := user.NewAutoIDSignerRFC6979(prm.Key.PrivateKey)

	return &API{
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

func (a *API) Configure(api *operations.NeofsRestGwAPI) http.Handler {
	api.ServeError = errors.ServeError

	api.UseSwaggerUI()

	api.OptionsAuthHandler = operations.OptionsAuthHandlerFunc(a.OptionsAuth)
	api.AuthHandler = operations.AuthHandlerFunc(a.PostAuth)

	api.OptionsAuthBearerHandler = operations.OptionsAuthBearerHandlerFunc(a.OptionsAuthBearer)
	api.FormBinaryBearerHandler = operations.FormBinaryBearerHandlerFunc(a.FormBinaryBearer)

	api.OptionsBalanceHandler = operations.OptionsBalanceHandlerFunc(a.OptionsBalance)
	api.GetBalanceHandler = operations.GetBalanceHandlerFunc(a.Balance)

	api.OptionsObjectsPutHandler = operations.OptionsObjectsPutHandlerFunc(a.OptionsObjectsPut)
	api.PutObjectHandler = operations.PutObjectHandlerFunc(a.PutObjects)

	api.OptionsObjectsGetDeleteHandler = operations.OptionsObjectsGetDeleteHandlerFunc(a.OptionsObjectsGetDelete)
	api.GetObjectInfoHandler = operations.GetObjectInfoHandlerFunc(a.GetObjectInfo)
	api.DeleteObjectHandler = operations.DeleteObjectHandlerFunc(a.DeleteObject)

	api.OptionsObjectsSearchHandler = operations.OptionsObjectsSearchHandlerFunc(a.OptionsObjectSearch)
	api.SearchObjectsHandler = operations.SearchObjectsHandlerFunc(a.SearchObjects)

	api.OptionsContainersPutListHandler = operations.OptionsContainersPutListHandlerFunc(a.OptionsContainersPutList)
	api.PutContainerHandler = operations.PutContainerHandlerFunc(a.PutContainers)
	api.ListContainersHandler = operations.ListContainersHandlerFunc(a.ListContainer)

	api.OptionsContainersGetDeleteHandler = operations.OptionsContainersGetDeleteHandlerFunc(a.OptionsContainersGetDelete)
	api.GetContainerHandler = operations.GetContainerHandlerFunc(a.GetContainer)
	api.DeleteContainerHandler = operations.DeleteContainerHandlerFunc(a.DeleteContainer)

	api.OptionsContainersEACLHandler = operations.OptionsContainersEACLHandlerFunc(a.OptionsContainersEACL)
	api.PutContainerEACLHandler = operations.PutContainerEACLHandlerFunc(a.PutContainerEACL)
	api.GetContainerEACLHandler = operations.GetContainerEACLHandlerFunc(a.GetContainerEACL)

	api.OptionsContainerObjectHandler = operations.OptionsContainerObjectHandlerFunc(a.OptionsContainerObject)
	api.GetContainerObjectHandler = operations.GetContainerObjectHandlerFunc(a.GetContainerObject)
	api.HeadContainerObjectHandler = operations.HeadContainerObjectHandlerFunc(a.HeadContainerObject)

	api.OptionsUploadContainerObjectHandler = operations.OptionsUploadContainerObjectHandlerFunc(a.OptionsUploadContainerObject)
	api.UploadContainerObjectHandler = operations.UploadContainerObjectHandlerFunc(a.UploadContainerObject)

	api.OptionsByAttributeHandler = operations.OptionsByAttributeHandlerFunc(a.OptionsByAttribute)
	api.GetByAttributeHandler = operations.GetByAttributeHandlerFunc(a.GetByAttribute)
	api.HeadByAttributeHandler = operations.HeadByAttributeHandlerFunc(a.HeadByAttribute)

	api.BearerAuthAuth = func(s string) (*models.Principal, error) {
		if !strings.HasPrefix(s, BearerPrefix) {
			return nil, fmt.Errorf("http auth: no bearer token")
		}
		if s = strings.TrimPrefix(s, BearerPrefix); len(s) == 0 {
			return nil, fmt.Errorf("http auth: bearer token is empty")
		}
		return (*models.Principal)(&s), nil
	}

	api.CookieAuthAuth = func(s string) (*models.Principal, error) {
		var bearerCookie string
		cookies := strings.Split(s, "; ")
		for _, cookie := range cookies {
			cookie = strings.TrimSpace(cookie)
			if strings.HasPrefix(cookie, BearerCookiePrefix) {
				// Cookie found, return its value without the prefix
				bearerCookie = strings.TrimPrefix(s, BearerCookiePrefix)
				if len(bearerCookie) == 0 {
					return nil, fmt.Errorf("cookie auth: bearer token is empty")
				}
				return (*models.Principal)(&bearerCookie), nil
			}
		}
		// We tried to find BearerCookie, but there isn't one. And it's not an error.
		return nil, nil
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {
		shutDownCtx, cancel := context.WithTimeout(context.Background(), a.serviceShutdownTimeout)
		defer cancel()

		a.prometheusService.ShutDown(shutDownCtx)
		a.pprofService.ShutDown(shutDownCtx)
	}

	return a.setupGlobalMiddleware(a.docMiddleware(api.Serve(setupMiddlewares)))
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation.
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics.
func (a *API) setupGlobalMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.NewString()
		a.log.Info("request", zap.String("remote", r.RemoteAddr),
			zap.String("method", r.Method), zap.String("url", r.URL.String()),
			zap.String("id", requestID))

		ctx := context.WithValue(r.Context(), ContextKeyRequestID, requestID)

		w.Header().Set(accessControlAllowOriginHeader, allOrigins)

		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *API) docMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || r.URL.Path == "/" {
			if specBasePath != "" {
				http.Redirect(w, r, specBasePath+"/docs/", http.StatusFound)
				return
			}
			a.log.Info("cannot get basePath from spec")
			handler.ServeHTTP(w, r)
		} else {
			handler.ServeHTTP(w, r)
		}
	})
}

func (a *API) logAndGetErrorResponse(msg string, err error, fields ...zap.Field) *models.ErrorResponse {
	fields = append(fields, zap.Error(err))
	a.log.Error(msg, fields...)
	return util.NewErrorResponse(fmt.Errorf("%s: %w", msg, err))
}

func (a API) StartCallback() {
	if a.gateMetric == nil {
		return
	}

	a.gateMetric.SetHealth(1)
}

func (a API) RunServices() {
	go a.pprofService.Start()
	go a.prometheusService.Start()
}

func getBasePath() (string, error) {
	// Load and parse the Swagger JSON file.
	spec, err := loads.Analyzed(restapi.SwaggerJSON, "")
	if err != nil {
		return "", err
	}
	return spec.BasePath(), nil
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

func (a *RestAPI) GetBalance(ctx echo.Context, address string) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsBalance(ctx echo.Context, address string) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsAuth(ctx echo.Context) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) Auth(ctx echo.Context, params apiserver.AuthParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) FormBinaryBearer(ctx echo.Context, params apiserver.FormBinaryBearerParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsAuthBearer(ctx echo.Context) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) ListContainers(ctx echo.Context, params apiserver.ListContainersParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsContainersPutList(ctx echo.Context) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) PutContainer(ctx echo.Context, params apiserver.PutContainerParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) DeleteContainer(ctx echo.Context, containerId apiserver.ContainerId, params apiserver.DeleteContainerParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) GetContainer(ctx echo.Context, containerId apiserver.ContainerId) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsContainersGetDelete(ctx echo.Context, containerId apiserver.ContainerId) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) GetContainerEACL(ctx echo.Context, containerId apiserver.ContainerId) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsContainersEACL(ctx echo.Context, containerId apiserver.ContainerId) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) PutContainerEACL(ctx echo.Context, containerId apiserver.ContainerId, params apiserver.PutContainerEACLParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) GetContainerObject(ctx echo.Context, containerId apiserver.ContainerId, objectId apiserver.ObjectId, params apiserver.GetContainerObjectParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) HeadContainerObject(ctx echo.Context, containerId apiserver.ContainerId, objectId apiserver.ObjectId, params apiserver.HeadContainerObjectParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsContainerObject(ctx echo.Context, containerId apiserver.ContainerId, objectId apiserver.ObjectId) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) GetByAttribute(ctx echo.Context, containerId apiserver.ContainerId, attrKey apiserver.AttrKey, attrVal apiserver.AttrVal, params apiserver.GetByAttributeParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) HeadByAttribute(ctx echo.Context, containerId apiserver.ContainerId, attrKey apiserver.AttrKey, attrVal apiserver.AttrVal, params apiserver.HeadByAttributeParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsByAttribute(ctx echo.Context, containerId apiserver.ContainerId, attrKey apiserver.AttrKey, attrVal apiserver.AttrVal) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsObjectsPut(ctx echo.Context) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) PutObject(ctx echo.Context, params apiserver.PutObjectParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsObjectsSearch(ctx echo.Context, containerId string) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) SearchObjects(ctx echo.Context, containerId apiserver.ContainerId, params apiserver.SearchObjectsParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) DeleteObject(ctx echo.Context, containerId apiserver.ContainerId, objectId apiserver.ObjectId, params apiserver.DeleteObjectParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) GetObjectInfo(ctx echo.Context, containerId apiserver.ContainerId, objectId apiserver.ObjectId, params apiserver.GetObjectInfoParams) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsObjectsGetDelete(ctx echo.Context, containerId apiserver.ContainerId, objectId apiserver.ObjectId) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) OptionsUploadContainerObject(ctx echo.Context, containerId apiserver.ContainerId) error {
	// TODO implement me
	panic("implement me")
}

func (a *RestAPI) UploadContainerObject(ctx echo.Context, containerId apiserver.ContainerId, params apiserver.UploadContainerObjectParams) error {
	// TODO implement me
	panic("implement me")
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
