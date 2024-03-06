package handlers

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
)

const (
	allOrigins   = "*"
	allowHeaders = "X-Bearer-For-All-Users, X-Bearer-Lifetime, X-Bearer-Owner-Id, X-Bearer-Signature, X-Bearer-Signature-Key, Content-Type, Authorization"

	methodGet    = "GET"
	methodHead   = "HEAD"
	methodPost   = "POST"
	methodPut    = "PUT"
	methodDelete = "DELETE"

	accessControlAllowHeadersHeader = "Access-Control-Allow-Headers"
	accessControlAllowMethodsHeader = "Access-Control-Allow-Methods"
)

func allowMethods(methods ...string) string {
	allowed := make([]string, 0)
	allowed = append(allowed, methods...)

	return strings.Join(allowed, ", ")
}

// OptionsAuth handler for the auth options request.
func (a *RestAPI) OptionsAuth(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsAuthBearer handler for the authBearer options request.
func (a *RestAPI) OptionsAuthBearer(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsBalance handler for the balance options request.
func (a *RestAPI) OptionsBalance(ctx echo.Context, _ string) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsObjectsSearch handler for the objectsSearch options request.
func (a *RestAPI) OptionsObjectsSearch(ctx echo.Context, _ string) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsObjectsPut handler for the objectsPut options request.
func (a *RestAPI) OptionsObjectsPut(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPut))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsObjectsGetDelete handler for the objectsGetDelete options request.
func (a *RestAPI) OptionsObjectsGetDelete(ctx echo.Context, _ apiserver.ContainerId, _ apiserver.ObjectId) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodDelete))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsContainersPutList handler for the containersPutList options request.
func (a *RestAPI) OptionsContainersPutList(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodPut))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsContainersGetDelete handler for the containersGetDelete options request.
func (a *RestAPI) OptionsContainersGetDelete(ctx echo.Context, _ apiserver.ContainerId) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodDelete))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsContainersEACL handler for the containersEACL options request.
func (a *RestAPI) OptionsContainersEACL(ctx echo.Context, _ apiserver.ContainerId) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodPut))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsContainerObject handler for the containerObject options request.
func (a *RestAPI) OptionsContainerObject(ctx echo.Context, _ apiserver.ContainerId, _ apiserver.ObjectId) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodHead))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsUploadContainerObject handler for the uploadContainerObject options request.
func (a *RestAPI) OptionsUploadContainerObject(ctx echo.Context, _ apiserver.ContainerId) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// OptionsByAttribute handler for the byAttribute options request.
func (a *RestAPI) OptionsByAttribute(ctx echo.Context, _ apiserver.ContainerId, _ apiserver.AttrKey, _ apiserver.AttrVal) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodHead))
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}
