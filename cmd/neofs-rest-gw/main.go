package main

import (
	"context"

	"github.com/go-openapi/loads"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	"go.uber.org/zap"
)

func main() {
	ctx := context.Background()

	v := config()
	logger := newLogger(v)

	neofsAPI, err := newNeofsAPI(ctx, logger, v)
	if err != nil {
		logger.Fatal("init neofs", zap.Error(err))
	}

	swaggerSpec, err := loads.Analyzed(restapi.SwaggerJSON, "")
	if err != nil {
		logger.Fatal("init spec", zap.Error(err))
	}

	serverCfg := serverConfig(v)
	serverCfg.SuccessfulStartCallback = neofsAPI.StartCallback

	api := operations.NewNeofsRestGwAPI(swaggerSpec)
	server := restapi.NewServer(api, serverCfg)
	defer func() {
		if err = server.Shutdown(); err != nil {
			logger.Error("shutdown", zap.Error(err))
		}
	}()

	server.ConfigureAPI(neofsAPI.Configure)
	neofsAPI.RunServices()

	// serve API
	if err = server.Serve(); err != nil {
		logger.Fatal("serve", zap.Error(err))
	}
}
