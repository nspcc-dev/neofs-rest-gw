package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/static/docs"
	middleware "github.com/oapi-codegen/echo-middleware"
	"go.uber.org/zap"
)

const (
	docsURL     = baseURL + "/docs"
	swaggerURL  = docsURL + "/swagger.json"
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

var (
	swaggerPayload []byte
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	v := config()
	logger := newLogger(v)
	zap.ReplaceGlobals(logger)
	validateConfig(v, logger)

	neofsAPI, err := newNeofsAPI(ctx, logger, v)
	if err != nil {
		logger.Fatal("init neofs", zap.Error(err))
	}

	serverCfg := serverConfig(v)

	swagger, err := apiserver.GetSwagger()
	if err != nil {
		logger.Fatal("get swagger definition", zap.Error(err))
	}

	servers := make(openapi3.Servers, len(serverCfg.EnabledListeners))

	if serverCfg.ExternalAddress != "" {
		for i, scheme := range serverCfg.EnabledListeners {
			switch scheme {
			case schemeHTTP:
				servers[i] = &openapi3.Server{
					URL: fmt.Sprintf("%s://%s%s", scheme, serverCfg.ExternalAddress, baseURL),
				}
			case schemeHTTPS:
				servers[i] = &openapi3.Server{
					URL: fmt.Sprintf("%s://%s%s", scheme, serverCfg.ExternalAddress, baseURL),
				}
			default:
				logger.Error("unknown scheme", zap.String("scheme", scheme))
			}
		}
	}

	swagger.Servers = servers

	swaggerPayload, err = swagger.MarshalJSON()
	if err != nil {
		logger.Fatal("swagger marshal", zap.Error(err))
	}

	e := echo.New()
	e.HideBanner = true
	e.StaticFS(docsURL, docs.FS)
	e.Add(http.MethodHead, docsURL+"*", echo.StaticDirectoryHandler(docs.FS, false))

	e.GET(swaggerURL, swaggerDocHandler)
	e.HEAD(swaggerURL, swaggerDocHandler)

	e.GET("/", redirectHandler)
	e.HEAD("/", redirectHandler)

	e.Group(baseURL, middleware.OapiRequestValidator(swagger))
	apiserver.RegisterHandlersWithBaseURL(e, neofsAPI, baseURL)

	neofsAPI.RunServices()

	go func() {
		neofsAPI.StartCallback()

		if err = e.Start(serverCfg.ListenAddress); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				logger.Fatal("start", zap.Error(err))
			}

			cancel()
		}
	}()

	<-ctx.Done()
	if err = e.Shutdown(ctx); err != nil {
		logger.Fatal("shutdown", zap.Error(err))
	}
}

func swaggerDocHandler(c echo.Context) error {
	return c.JSONBlob(http.StatusOK, swaggerPayload)
}

func redirectHandler(c echo.Context) error {
	return c.Redirect(http.StatusTemporaryRedirect, docsURL)
}
