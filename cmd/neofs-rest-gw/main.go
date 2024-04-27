package main

import (
	"context"
	"crypto/tls"
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

	servers := make(openapi3.Servers, len(serverCfg.Endpoints))
	for i, endpointInfo := range serverCfg.Endpoints {
		if endpointInfo.ExternalAddress != "" {
			var scheme string
			// Determine the scheme based on whether TLS is enabled and set up e.TLSServer.
			if endpointInfo.TLS.Enabled {
				scheme = schemeHTTPS
				e.TLSServer.ReadTimeout = endpointInfo.ReadTimeout
				e.TLSServer.WriteTimeout = endpointInfo.WriteTimeout
				e.TLSServer.IdleTimeout = endpointInfo.KeepAlive

				if endpointInfo.TLS.CertCAFile != "" {
					ca, err := loadCA(endpointInfo.TLS.CertCAFile)
					if err != nil {
						logger.Fatal("reading server certificate", zap.Error(err))
					}
					e.TLSServer.TLSConfig = &tls.Config{ClientCAs: ca}
				}
			} else {
				scheme = schemeHTTP
			}
			servers[i] = &openapi3.Server{
				URL: fmt.Sprintf("%s://%s%s", scheme, endpointInfo.ExternalAddress, baseURL),
			}
		} else {
			logger.Info("Endpoint with missing external-address", zap.String("address", endpointInfo.Address))
		}
	}
	swagger.Servers = servers

	swaggerPayload, err = swagger.MarshalJSON()
	if err != nil {
		logger.Fatal("swagger marshal", zap.Error(err))
	}

	neofsAPI.RunServices()

	for i := range serverCfg.Endpoints {
		go func(i int) {
			endpointInfo := serverCfg.Endpoints[i]
			logger.Info("starting server", zap.String("address", endpointInfo.Address))

			if endpointInfo.TLS.Enabled {
				if err = e.StartTLS(endpointInfo.Address, endpointInfo.TLS.CertFile, endpointInfo.TLS.KeyFile); err != nil {
					if !errors.Is(err, http.ErrServerClosed) {
						logger.Fatal("start https", zap.Error(err))
					}
					cancel()
				}
			} else {
				if err = e.Start(endpointInfo.Address); err != nil {
					if !errors.Is(err, http.ErrServerClosed) {
						logger.Fatal("start http", zap.Error(err))
					}
					cancel()
				}
			}
		}(i)
	}

	go neofsAPI.StartCallback()

	<-ctx.Done()
	if err = e.Shutdown(ctx); err != nil {
		logger.Fatal("shutdown http and https", zap.Error(err))
	}
}

func swaggerDocHandler(c echo.Context) error {
	return c.JSONBlob(http.StatusOK, swaggerPayload)
}

func redirectHandler(c echo.Context) error {
	return c.Redirect(http.StatusTemporaryRedirect, docsURL)
}
