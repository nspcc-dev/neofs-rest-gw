package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-sdk-go/client"
)

func (a *RestAPI) GetNetworkInfo(ctx echo.Context) error {
	var prm client.PrmNetworkInfo

	networkInfo, err := a.pool.NetworkInfo(ctx.Request().Context(), prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not get network info", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

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
