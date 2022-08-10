package handlers

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
)

const (
	allOrigins   = "*"
	allowMethods = "PUT, DELETE"
	allowHeaders = "X-Bearer-Owner-Id, X-Bearer-Signature, X-Bearer-Signature-Key, Content-Type, Authorization"
)

func (a *API) OptionsAuth(operations.OptionsAuthParams) middleware.Responder {
	return operations.NewOptionsAuthOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders)
}

func (a *API) OptionsObjectSearch(operations.OptionsObjectsSearchParams) middleware.Responder {
	return operations.NewOptionsObjectsSearchOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders)
}

func (a *API) OptionsObjectsPut(operations.OptionsObjectsPutParams) middleware.Responder {
	return operations.NewOptionsObjectsPutOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods)
}

func (a *API) OptionsObjectsGetDelete(operations.OptionsObjectsGetDeleteParams) middleware.Responder {
	return operations.NewOptionsObjectsGetDeleteOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods)
}

func (a *API) OptionsContainersPutList(operations.OptionsContainersPutListParams) middleware.Responder {
	return operations.NewOptionsContainersPutListOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods)
}

func (a *API) OptionsContainersGetDelete(operations.OptionsContainersGetDeleteParams) middleware.Responder {
	return operations.NewOptionsContainersGetDeleteOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods)
}

func (a *API) OptionsContainersEACL(operations.OptionsContainersEACLParams) middleware.Responder {
	return operations.NewOptionsContainersEACLOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods)
}
