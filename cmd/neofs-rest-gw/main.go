package main

import (
	"context"
	"encoding/json"
	"os/signal"
	"syscall"

	"github.com/go-openapi/loads"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	"go.uber.org/zap"
)

func main() {
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	v := config()
	logger := newLogger(v)
	validateConfig(v, logger)

	neofsAPI, err := newNeofsAPI(ctx, logger, v)
	if err != nil {
		logger.Fatal("init neofs", zap.Error(err))
	}

	serverCfg := serverConfig(v)
	serverCfg.SuccessfulStartCallback = neofsAPI.StartCallback

	// Unmarshal the JSON into a map
	var swaggerMap map[string]interface{}
	err = json.Unmarshal(restapi.SwaggerJSON, &swaggerMap)
	if err != nil {
		logger.Fatal("unmarshaling SwaggerJSON", zap.Error(err))
	}

	swaggerMap["host"] = serverCfg.ExternalAddress

	// Marshal the map back into json.RawMessage
	restapi.SwaggerJSON, err = json.MarshalIndent(swaggerMap, "", "    ")
	if err != nil {
		logger.Fatal("marshaling updated SwaggerJSON", zap.Error(err))
	}

	swaggerSpec, err := loads.Analyzed(restapi.SwaggerJSON, "")
	if err != nil {
		logger.Fatal("init spec", zap.Error(err))
	}

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
