package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
)

const (
	allOrigins                      = "*"
	headerXBearerOwnerID            = "X-Bearer-Owner-Id"
	headerXBearerLifetime           = "X-Bearer-Lifetime"
	headerXBearerSignature          = "X-Bearer-Signature"
	headerXBearerSignatureKey       = "X-Bearer-Signature-Key"
	headerXNeofsBearerToken         = "NeoFS-Bearer-Token"
	headerRange                     = "Range"
	headerXAttributes               = "X-Attributes"
	headerXNeofsExpirationRFC3339   = "X-Neofs-Expiration-RFC3339"
	headerXNeofsExpirationTimestamp = "X-Neofs-Expiration-Timestamp"
	headerXNeofsExpirationDuration  = "X-Neofs-Expiration-Duration"

	methodGet    = "GET"
	methodHead   = "HEAD"
	methodPost   = "POST"
	methodPut    = "PUT"
	methodDelete = "DELETE"

	accessControlAllowHeadersHeader = "Access-Control-Allow-Headers"
	accessControlAllowMethodsHeader = "Access-Control-Allow-Methods"

	delimiter = ", "
)

var (
	allowHeaders    = []string{"Content-Type", "Authorization"}
	allowHeadersStr = strings.Join(allowHeaders, delimiter)

	defaultResponseInvalidContainerID = util.NewErrorResponse(errors.New("containerID is invalid"))

	optionsAuth = strings.Join(
		append(allowHeaders,
			"X-Bearer-For-All-Users",
			headerXBearerOwnerID,
			headerXBearerLifetime,
		),
		delimiter)

	optionsAuthBearer = strings.Join(
		append(allowHeaders,
			headerXBearerSignature,
			headerXBearerSignatureKey,
		),
		delimiter)

	optionsObjectsSearch = strings.Join(
		append(allowHeaders,
			headerXBearerSignature,
			headerXBearerSignatureKey,
			headerXNeofsBearerToken,
		),
		delimiter)

	optionsObjectsGetDelete = strings.Join(
		append(allowHeaders,
			headerXBearerSignature,
			headerXBearerSignatureKey,
			headerXNeofsBearerToken,
		),
		delimiter)

	newOptionsUploadContainerObject = strings.Join(
		append(allowHeaders,
			headerXBearerSignature,
			headerXBearerSignatureKey,
			headerXNeofsBearerToken,
			headerXAttributes,
			headerXNeofsExpirationRFC3339,
			headerXNeofsExpirationTimestamp,
			headerXNeofsExpirationDuration,
		),
		delimiter)

	newOptionsContainerObject = strings.Join(
		append(allowHeaders,
			headerXBearerSignature,
			headerXBearerSignatureKey,
			headerXNeofsBearerToken,
			headerRange,
		),
		delimiter)

	newOptionsByAttribute = strings.Join(
		append(allowHeaders,
			headerXBearerSignature,
			headerXBearerSignatureKey,
			headerXNeofsBearerToken,
			headerRange,
		),
		delimiter)

	optionsV2SearchObjects = strings.Join(
		append(allowHeaders,
			headerXBearerSignature,
			headerXBearerSignatureKey,
			headerXNeofsBearerToken,
		),
		delimiter)

	optionsUnsignedBearerToken = strings.Join(
		append(allowHeaders,
			headerXBearerLifetime,
			headerXBearerOwnerID,
		),
		delimiter)
)

type (
	// CORSRule describe a rule for CORS in a bucket.
	CORSRule struct {
		AllowedHeaders []string `json:"AllowedHeaders"`
		AllowedMethods []string `json:"AllowedMethods"`
		AllowedOrigins []string `json:"AllowedOrigins"`
		ExposeHeaders  []string `json:"ExposeHeaders"`
		MaxAgeSeconds  int      `json:"MaxAgeSeconds,omitempty"`
	}
)

func allowMethods(methods ...string) string {
	allowed := make([]string, 0)
	allowed = append(allowed, methods...)

	return strings.Join(allowed, ", ")
}

// OptionsAuth handler for the auth options request.
func (a *RestAPI) OptionsAuth(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, optionsAuth)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsAuthBearer handler for the authBearer options request.
func (a *RestAPI) OptionsAuthBearer(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, optionsAuthBearer)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet))
	return ctx.NoContent(http.StatusOK)
}

// OptionsBalance handler for the balance options request.
func (a *RestAPI) OptionsBalance(ctx echo.Context, _ string) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet))
	return ctx.NoContent(http.StatusOK)
}

// OptionsObjectsSearch handler for the objectsSearch options request.
func (a *RestAPI) OptionsObjectsSearch(ctx echo.Context, _ string) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, optionsObjectsSearch)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsObjectsGetDelete handler for the objectsGetDelete options request.
func (a *RestAPI) OptionsObjectsGetDelete(ctx echo.Context, containerID apiserver.ContainerId, _ apiserver.ObjectId) error {
	cnrID, err := cid.DecodeString(containerID)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, defaultResponseInvalidContainerID)
	}

	allowedOrigin, err := a.getContainerCORSOrigin(ctx.Request().Context(), ctx.Request().Header.Get(echo.HeaderOrigin), cnrID)
	if err != nil {
		return ctx.JSON(getResponseCodeFromStatus(err), a.logAndGetErrorResponse("check cors on preflight", err, a.log))
	}

	if allowedOrigin.IsDefault {
		ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
		ctx.Response().Header().Set(accessControlAllowHeadersHeader, optionsObjectsGetDelete)
		ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodDelete))
	} else {
		setCORSResponseHeaders(ctx, allowedOrigin)
	}

	return ctx.NoContent(http.StatusOK)
}

// OptionsContainersPutList handler for the containersPutList options request.
func (a *RestAPI) OptionsContainersPutList(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodPut, methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsContainersGetDelete handler for the containersGetDelete options request.
func (a *RestAPI) OptionsContainersGetDelete(ctx echo.Context, containerId apiserver.ContainerId) error {
	cnrID, err := cid.DecodeString(containerId)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, defaultResponseInvalidContainerID)
	}

	allowedOrigin, err := a.getContainerCORSOrigin(ctx.Request().Context(), ctx.Request().Header.Get(echo.HeaderOrigin), cnrID)
	if err != nil {
		return ctx.JSON(getResponseCodeFromStatus(err), a.logAndGetErrorResponse("check cors on preflight", err, a.log))
	}

	if allowedOrigin.IsDefault {
		ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
		ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
		ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodDelete))
	} else {
		setCORSResponseHeaders(ctx, allowedOrigin)
	}

	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
	return ctx.NoContent(http.StatusOK)
}

// OptionsContainersEACL handler for the containersEACL options request.
func (a *RestAPI) OptionsContainersEACL(ctx echo.Context, containerId apiserver.ContainerId) error {
	cnrID, err := cid.DecodeString(containerId)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, defaultResponseInvalidContainerID)
	}

	allowedOrigin, err := a.getContainerCORSOrigin(ctx.Request().Context(), ctx.Request().Header.Get(echo.HeaderOrigin), cnrID)
	if err != nil {
		return ctx.JSON(getResponseCodeFromStatus(err), a.logAndGetErrorResponse("check cors on preflight", err, a.log))
	}

	if allowedOrigin.IsDefault {
		ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
		ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
		ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodPut))
	} else {
		setCORSResponseHeaders(ctx, allowedOrigin)
	}
	return ctx.NoContent(http.StatusOK)
}

// OptionsNetworkInfo handler for the network options request.
func (a *RestAPI) OptionsNetworkInfo(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet))
	return ctx.NoContent(http.StatusOK)
}

// NewOptionsUploadContainerObject handler for the upload object options request.
func (a *RestAPI) NewOptionsUploadContainerObject(ctx echo.Context, containerId apiserver.ContainerId, _ apiserver.NewOptionsUploadContainerObjectParams) error {
	cnrID, err := cid.DecodeString(containerId)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, defaultResponseInvalidContainerID)
	}

	allowedOrigin, err := a.getContainerCORSOrigin(ctx.Request().Context(), ctx.Request().Header.Get(echo.HeaderOrigin), cnrID)
	if err != nil {
		return ctx.JSON(getResponseCodeFromStatus(err), a.logAndGetErrorResponse("check cors on preflight", err, a.log))
	}

	if allowedOrigin.IsDefault {
		ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
		ctx.Response().Header().Set(accessControlAllowHeadersHeader, newOptionsUploadContainerObject)
		ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	} else {
		setCORSResponseHeaders(ctx, allowedOrigin)
	}
	return ctx.NoContent(http.StatusOK)
}

// NewOptionsContainerObject handler for the create object options request.
func (a *RestAPI) NewOptionsContainerObject(ctx echo.Context, containerId apiserver.ContainerId, _ apiserver.ObjectId, _ apiserver.NewOptionsContainerObjectParams) error {
	cnrID, err := cid.DecodeString(containerId)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, defaultResponseInvalidContainerID)
	}

	allowedOrigin, err := a.getContainerCORSOrigin(ctx.Request().Context(), ctx.Request().Header.Get(echo.HeaderOrigin), cnrID)
	if err != nil {
		return ctx.JSON(getResponseCodeFromStatus(err), a.logAndGetErrorResponse("check cors on preflight", err, a.log))
	}

	if allowedOrigin.IsDefault {
		ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
		ctx.Response().Header().Set(accessControlAllowHeadersHeader, newOptionsContainerObject)
		ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodHead))
	} else {
		setCORSResponseHeaders(ctx, allowedOrigin)
	}
	return ctx.NoContent(http.StatusOK)
}

// NewOptionsByAttribute handler for the find by attribute options request.
func (a *RestAPI) NewOptionsByAttribute(ctx echo.Context, containerId apiserver.ContainerId, _ apiserver.AttrKey, _ apiserver.AttrVal, _ apiserver.NewOptionsByAttributeParams) error {
	cnrID, err := cid.DecodeString(containerId)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, defaultResponseInvalidContainerID)
	}

	allowedOrigin, err := a.getContainerCORSOrigin(ctx.Request().Context(), ctx.Request().Header.Get(echo.HeaderOrigin), cnrID)
	if err != nil {
		return ctx.JSON(getResponseCodeFromStatus(err), a.logAndGetErrorResponse("check cors on preflight", err, a.log))
	}

	if allowedOrigin.IsDefault {
		ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
		ctx.Response().Header().Set(accessControlAllowHeadersHeader, newOptionsByAttribute)
		ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet, methodHead))
	} else {
		setCORSResponseHeaders(ctx, allowedOrigin)
	}
	return ctx.NoContent(http.StatusOK)
}

// OptionsV2SearchObjects handler for the objectsSearch options request.
func (a *RestAPI) OptionsV2SearchObjects(ctx echo.Context, _ string) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, optionsV2SearchObjects)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsV2AuthSessionToken handler for the auth v2 session token options request.
func (a *RestAPI) OptionsV2AuthSessionToken(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsV2FormAuthSessionToken handler for the form v2 session token options request.
func (a *RestAPI) OptionsV2FormAuthSessionToken(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsGatewayMetadata handler for the gateway metadata options request.
func (a *RestAPI) OptionsGatewayMetadata(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodGet))
	return ctx.NoContent(http.StatusOK)
}

// OptionsUnsignedBearerToken handler for the form unsigned bearer token options request.
func (a *RestAPI) OptionsUnsignedBearerToken(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, optionsUnsignedBearerToken)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsCompleteUnsignedBearerToken handler for the form unsigned bearer token options request.
func (a *RestAPI) OptionsCompleteUnsignedBearerToken(ctx echo.Context) error {
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}

// OptionsContainerCORS handler for the CORS options request.
func (a *RestAPI) OptionsContainerCORS(ctx echo.Context, _ apiserver.ContainerId) error {
	// We leave it a wildcard to avoid a situation where the user cuts off their own access.
	ctx.Response().Header().Set(accessControlAllowOriginHeader, allOrigins)
	ctx.Response().Header().Set(accessControlAllowHeadersHeader, allowHeadersStr)
	ctx.Response().Header().Set(accessControlAllowMethodsHeader, allowMethods(methodPost))
	return ctx.NoContent(http.StatusOK)
}
