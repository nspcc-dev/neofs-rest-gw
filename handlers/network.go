package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"go.uber.org/zap"
)

func (a *RestAPI) GetNetworkInfo(ctx echo.Context) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.GetNetworkInfoDuration)()
	}

	var log = a.log.With(zap.String(handlerFieldName, "GetNetworkInfo"))
	var prm client.PrmNetworkInfo

	networkInfo, err := a.pool.NetworkInfo(ctx.Request().Context(), prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("get network info", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	a.networkInfoGetter.StoreNetworkInfo(networkInfo)

	var resp apiserver.NetworkInfoOK
	resp.AuditFee = networkInfo.AuditFee()
	resp.StoragePrice = networkInfo.StoragePrice()
	resp.NamedContainerFee = networkInfo.NamedContainerFee()
	resp.ContainerFee = networkInfo.ContainerFee()
	resp.EpochDuration = networkInfo.EpochDuration()
	resp.HomomorphicHashingDisabled = networkInfo.HomomorphicHashingDisabled()
	resp.MaxObjectSize = networkInfo.MaxObjectSize()
	resp.WithdrawalFee = networkInfo.WithdrawalFee()

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}
