package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
)

func (a *RestAPI) GatewayMetadata(ctx echo.Context) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.GatewayMetadataDuration)()
	}

	var resp = apiserver.GatewayMetadataResponse{
		Address: a.signer.UserID().String(),
		NnsName: &a.nnsName,
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}
