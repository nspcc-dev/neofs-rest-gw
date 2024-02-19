package handlers

import (
	"strings"

	"github.com/go-openapi/runtime/middleware"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
)

const (
	allOrigins   = "*"
	allowHeaders = "X-Bearer-For-All-Users, X-Bearer-Lifetime, X-Bearer-Owner-Id, X-Bearer-Signature, X-Bearer-Signature-Key, Content-Type, Authorization"

	methodGet    = "GET"
	methodHead   = "HEAD"
	methodPost   = "POST"
	methodPut    = "PUT"
	methodDelete = "DELETE"
)

func allowMethods(methods ...string) string {
	allowed := make([]string, 0)
	allowed = append(allowed, methods...)

	return strings.Join(allowed, ", ")
}

func (a *API) OptionsAuth(operations.OptionsAuthParams) middleware.Responder {
	return operations.NewOptionsAuthOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodPost))
}

func (a *API) OptionsAuthBearer(operations.OptionsAuthBearerParams) middleware.Responder {
	return operations.NewOptionsAuthBearerOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodGet))
}

func (a *API) OptionsBalance(operations.OptionsBalanceParams) middleware.Responder {
	return operations.NewOptionsBalanceOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodGet))
}

func (a *API) OptionsObjectSearch(operations.OptionsObjectsSearchParams) middleware.Responder {
	return operations.NewOptionsObjectsSearchOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodPost))
}

func (a *API) OptionsObjectsPut(operations.OptionsObjectsPutParams) middleware.Responder {
	return operations.NewOptionsObjectsPutOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodPut))
}

func (a *API) OptionsObjectsGetDelete(operations.OptionsObjectsGetDeleteParams) middleware.Responder {
	return operations.NewOptionsObjectsGetDeleteOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodGet, methodDelete))
}

func (a *API) OptionsContainersPutList(operations.OptionsContainersPutListParams) middleware.Responder {
	return operations.NewOptionsContainersPutListOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodGet, methodPut))
}

func (a *API) OptionsContainersGetDelete(operations.OptionsContainersGetDeleteParams) middleware.Responder {
	return operations.NewOptionsContainersGetDeleteOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodGet, methodDelete))
}

func (a *API) OptionsContainersEACL(operations.OptionsContainersEACLParams) middleware.Responder {
	return operations.NewOptionsContainersEACLOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodGet, methodPut))
}

func (a *API) OptionsContainerObject(operations.OptionsContainerObjectParams) middleware.Responder {
	return operations.NewOptionsContainerObjectOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodGet, methodHead))
}

func (a *API) OptionsUploadContainerObject(operations.OptionsUploadContainerObjectParams) middleware.Responder {
	return operations.NewOptionsUploadContainerObjectOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodPost))
}

func (a *API) OptionsByAttribute(operations.OptionsByAttributeParams) middleware.Responder {
	return operations.NewOptionsByAttributeOK().
		WithAccessControlAllowOrigin(allOrigins).
		WithAccessControlAllowHeaders(allowHeaders).
		WithAccessControlAllowMethods(allowMethods(methodGet, methodHead))
}
