package handlers

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
)

const (
	allOrigins   = "*"
	allowHeaders = "X-Bearer-For-All-Users, X-Bearer-Lifetime, X-Bearer-Owner-Id, " +
		"X-Bearer-Signature, X-Bearer-Signature-Key, Content-Type, Authorization, " +
		"X-Attribute-Filename, X-Attribute-Filepath, X-Attributes, " +
		"X-Neofs-Expiration-RFC3339, X-Neofs-Expiration-Timestamp, X-Neofs-Expiration-Duration, " +
		"X-Session-Token, X-Bearer-Issuer-Id"
	allowUploadHeader = "*"

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
	return ctx.NoContent(http.StatusOK)
}

// OptionsAuthBearer handler for the authBearer options request.
func (a *RestAPI) OptionsAuthBearer(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet))
	return ctx.NoContent(http.StatusOK)
}

// OptionsBalance handler for the balance options request.
func (a *RestAPI) OptionsBalance(ctx echo.Context, _ string) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet))
	return ctx.NoContent(http.StatusOK)
}

// OptionsObjectsSearch handler for the objectsSearch options request.
func (a *RestAPI) OptionsObjectsSearch(ctx echo.Context, _ string) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsObjectsPut handler for the objectsPut options request.
func (a *RestAPI) OptionsObjectsPut(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPut))
	return ctx.NoContent(http.StatusOK)
}

// OptionsObjectsGetDelete handler for the objectsGetDelete options request.
func (a *RestAPI) OptionsObjectsGetDelete(ctx echo.Context, _ apiserver.ContainerId, _ apiserver.ObjectId) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodDelete))
	return ctx.NoContent(http.StatusOK)
}

// OptionsContainersPutList handler for the containersPutList options request.
func (a *RestAPI) OptionsContainersPutList(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodPut, methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsContainersGetDelete handler for the containersGetDelete options request.
func (a *RestAPI) OptionsContainersGetDelete(ctx echo.Context, _ apiserver.ContainerId) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodDelete))
	return ctx.NoContent(http.StatusOK)
}

// OptionsContainersEACL handler for the containersEACL options request.
func (a *RestAPI) OptionsContainersEACL(ctx echo.Context, _ apiserver.ContainerId) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodPut))
	return ctx.NoContent(http.StatusOK)
}

// OptionsContainerObject handler for the containerObject options request.
func (a *RestAPI) OptionsContainerObject(ctx echo.Context, _ apiserver.ContainerId, _ apiserver.ObjectId) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodHead))
	return ctx.NoContent(http.StatusOK)
}

// OptionsUploadContainerObject handler for the uploadContainerObject options request.
func (a *RestAPI) OptionsUploadContainerObject(ctx echo.Context, _ apiserver.ContainerId) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowUploadHeader)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsByAttribute handler for the byAttribute options request.
func (a *RestAPI) OptionsByAttribute(ctx echo.Context, _ apiserver.ContainerId, _ apiserver.AttrKey, _ apiserver.AttrVal) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodHead))
	return ctx.NoContent(http.StatusOK)
}

// OptionsNetworkInfo handler for the network options request.
func (a *RestAPI) OptionsNetworkInfo(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet))
	return ctx.NoContent(http.StatusOK)
}

// NewOptionsUploadContainerObject handler for the upload object options request.
func (a *RestAPI) NewOptionsUploadContainerObject(ctx echo.Context, _ apiserver.ContainerId, _ apiserver.NewOptionsUploadContainerObjectParams) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowUploadHeader)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// NewOptionsContainerObject handler for the create object options request.
func (a *RestAPI) NewOptionsContainerObject(ctx echo.Context, _ apiserver.ContainerId, _ apiserver.ObjectId, _ apiserver.NewOptionsContainerObjectParams) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodHead))
	return ctx.NoContent(http.StatusOK)
}

// NewOptionsByAttribute handler for the find by attribute options request.
func (a *RestAPI) NewOptionsByAttribute(ctx echo.Context, _ apiserver.ContainerId, _ apiserver.AttrKey, _ apiserver.AttrVal, _ apiserver.NewOptionsByAttributeParams) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodHead))
	return ctx.NoContent(http.StatusOK)
}

// OptionsV2SearchObjects handler for the objectsSearch options request.
func (a *RestAPI) OptionsV2SearchObjects(ctx echo.Context, _ string) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsV2AuthSessionToken handler for the auth v2 session token options request.
func (a *RestAPI) OptionsV2AuthSessionToken(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsV2FormAuthSessionToken handler for the form v2 session token options request.
func (a *RestAPI) OptionsV2FormAuthSessionToken(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsGatewayMetadata handler for the gateway metadata options request.
func (a *RestAPI) OptionsGatewayMetadata(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet))
	return ctx.NoContent(http.StatusOK)
}

// OptionsUnsignedBearerToken handler for the form unsigned bearer token options request.
func (a *RestAPI) OptionsUnsignedBearerToken(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeaders)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}
