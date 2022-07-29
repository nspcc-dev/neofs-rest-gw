package handlers

import (
	"strconv"

	"github.com/go-openapi/runtime/middleware"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

// Balance handler that get balance from NeoFS.
func (a *API) Balance(params operations.GetBalanceParams) middleware.Responder {
	var ownerID user.ID
	if err := ownerID.DecodeString(params.Address); err != nil {
		resp := a.logAndGetErrorResponse("parse address", err)
		return operations.NewGetBalanceBadRequest().WithPayload(resp)
	}

	var prm pool.PrmBalanceGet
	prm.SetAccount(ownerID)

	neofsBalance, err := a.pool.Balance(params.HTTPRequest.Context(), prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("get balance", err)
		return operations.NewGetBalanceBadRequest().WithPayload(resp)
	}

	var resp models.Balance
	resp.Address = util.NewString(params.Address)
	resp.Value = util.NewString(strconv.FormatInt(neofsBalance.Value(), 10))
	resp.Precision = util.NewInteger(int64(neofsBalance.Precision()))

	return operations.NewGetBalanceOK().WithPayload(&resp)
}
