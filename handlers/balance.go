package handlers

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

// GetBalance handler that get balance from NeoFS.
func (a *RestAPI) GetBalance(ctx echo.Context, address string) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.GetBalanceDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "GetBalance"), zap.String("account", address))

	var ownerID user.ID
	if err := ownerID.DecodeString(address); err != nil {
		resp := a.logAndGetErrorResponse("parse address", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var prm client.PrmBalanceGet
	prm.SetAccount(ownerID)

	neofsBalance, err := a.pool.BalanceGet(ctx.Request().Context(), prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("get balance", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var resp apiserver.Balance
	resp.Address = address
	resp.Value = strconv.FormatInt(neofsBalance.Value(), 10)
	resp.Precision = neofsBalance.Precision()

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}
