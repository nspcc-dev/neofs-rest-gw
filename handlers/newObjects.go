package handlers

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"go.uber.org/zap"
)

// NewUploadContainerObject handler that upload file as object with attributes to NeoFS.
func (a *RestAPI) NewUploadContainerObject(ctx echo.Context, containerID apiserver.ContainerId, params apiserver.NewUploadContainerObjectParams) error {
	var (
		err    error
		addr   oid.Address
		btoken *bearer.Token
	)

	var idCnr cid.ID
	if err = idCnr.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	if principal != "" {
		btoken, err = getBearerTokenFromString(principal)
		if err != nil {
			resp := a.logAndGetErrorResponse("get bearer token", err)
			return ctx.JSON(http.StatusBadRequest, resp)
		}
	}

	filtered, err := parseAndFilterAttributes(a.log, params.XAttributes)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not process header "+userAttributesHeader, err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	addExpirationHeaders(filtered, params)
	if needParseExpiration(filtered) {
		epochDuration, err := getEpochDurations(ctx.Request().Context(), a.pool)
		if err != nil {
			resp := a.logAndGetErrorResponse("could not get epoch durations from network info", err)
			return ctx.JSON(http.StatusBadRequest, resp)
		}

		if err = prepareExpirationHeader(filtered, epochDuration, time.Now()); err != nil {
			resp := a.logAndGetErrorResponse("could not parse expiration header", err)
			return ctx.JSON(http.StatusBadRequest, resp)
		}
	}

	attributes := make([]object.Attribute, 0, len(filtered))
	// prepares attributes from filtered headers
	for key, val := range filtered {
		attribute := object.NewAttribute(key, val)
		attributes = append(attributes, *attribute)
	}

	// sets Content-Type attribute if the attribute isn't already set
	// and if the Content-Type header is present and non-empty
	if _, ok := filtered[object.AttributeContentType]; !ok {
		if ct := ctx.Request().Header.Get("Content-Type"); len(ct) > 0 {
			attrContentType := object.NewAttribute(object.AttributeContentType, ct)
			attributes = append(attributes, *attrContentType)
		}
	}
	// sets Timestamp attribute if it wasn't set from header and enabled by settings
	if _, ok := filtered[object.AttributeTimestamp]; !ok {
		if a.defaultTimestamp {
			timestamp := object.NewAttribute(object.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
			attributes = append(attributes, *timestamp)
		} else if date := ctx.Request().Header.Get("Date"); len(date) > 0 {
			parsedTime, err := time.Parse(time.RFC1123, date)
			if err != nil {
				resp := a.logAndGetErrorResponse("could not parse header Date", err)
				return ctx.JSON(http.StatusBadRequest, resp)
			}

			timestamp := object.NewAttribute(object.AttributeTimestamp, strconv.FormatInt(parsedTime.Unix(), 10))
			attributes = append(attributes, *timestamp)
		}
	}

	var hdr object.Object
	hdr.SetContainerID(idCnr)
	a.setOwner(&hdr, btoken)
	hdr.SetAttributes(attributes...)

	idObj, err := a.putObject(ctx, hdr, btoken, func(w io.Writer) error {
		var err error
		if cln := ctx.Request().ContentLength; cln >= 0 && uint64(cln) < a.payloadBufferSize { // negative means unknown
			if cln != 0 { // otherwise io.CopyBuffer panics
				_, err = io.CopyBuffer(w, ctx.Request().Body, make([]byte, cln))
			}
		} else {
			_, err = io.CopyBuffer(w, ctx.Request().Body, make([]byte, a.payloadBufferSize))
		}
		return err
	})
	if err != nil {
		return err
	}

	addr.SetObject(idObj)
	addr.SetContainer(idCnr)

	var resp apiserver.AddressForUpload
	resp.ContainerId = containerID
	resp.ObjectId = idObj.String()

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// NewGetContainerObject handler that returns object (using container ID and object ID).
func (a *RestAPI) NewGetContainerObject(ctx echo.Context, containerID apiserver.ContainerId, objectID apiserver.ObjectId, params apiserver.NewGetContainerObjectParams) error {
	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	addr, err := parseAddress(containerID, objectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	return a.getByAddress(ctx, addr, params.Download, principal, true)
}

// NewHeadContainerObject handler that returns object info (using container ID and object ID).
func (a *RestAPI) NewHeadContainerObject(ctx echo.Context, containerID apiserver.ContainerId, objectID apiserver.ObjectId, params apiserver.NewHeadContainerObjectParams) error {
	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	addr, err := parseAddress(containerID, objectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return a.headByAddress(ctx, addr, params.Download, principal, true)
}

// NewGetByAttribute handler that returns object (payload and attributes) by a specific attribute.
func (a *RestAPI) NewGetByAttribute(ctx echo.Context, containerID apiserver.ContainerId, attrKey apiserver.AttrKey, attrVal apiserver.AttrVal, params apiserver.NewGetByAttributeParams) error {
	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	var cnrID cid.ID
	if err = cnrID.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	res, err := a.search(ctx.Request().Context(), principal, cnrID, attrKey, attrVal, object.MatchStringEqual)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not search for objects", err)
		return ctx.JSON(http.StatusNotFound, resp)
	}

	defer func() {
		if err = res.Close(); err != nil {
			zap.L().Error("failed to close resource", zap.Error(err))
		}
	}()

	buf := make([]oid.ID, 1)

	n, _ := res.Read(buf)
	if n == 0 {
		err = res.Close()

		if err == nil || errors.Is(err, io.EOF) {
			return ctx.JSON(http.StatusNotFound, util.NewErrorResponse(errors.New("object not found")))
		}

		resp := a.logAndGetErrorResponse("read object list failed", err)
		return ctx.JSON(http.StatusNotFound, resp)
	}

	var addrObj oid.Address
	addrObj.SetContainer(cnrID)
	addrObj.SetObject(buf[0])

	return a.getByAddress(ctx, addrObj, params.Download, principal, true)
}

// NewHeadByAttribute handler that returns object info (payload and attributes) by a specific attribute.
func (a *RestAPI) NewHeadByAttribute(ctx echo.Context, containerID apiserver.ContainerId, attrKey apiserver.AttrKey, attrVal apiserver.AttrVal, params apiserver.NewHeadByAttributeParams) error {
	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	var cnrID cid.ID
	if err = cnrID.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	res, err := a.search(ctx.Request().Context(), principal, cnrID, attrKey, attrVal, object.MatchStringEqual)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not search for objects", err)
		return ctx.JSON(http.StatusNotFound, resp)
	}

	defer func() {
		if err = res.Close(); err != nil {
			zap.L().Error("failed to close resource", zap.Error(err))
		}
	}()

	buf := make([]oid.ID, 1)

	n, _ := res.Read(buf)
	if n == 0 {
		err = res.Close()

		if err == nil || errors.Is(err, io.EOF) {
			return ctx.JSON(http.StatusNotFound, util.NewErrorResponse(errors.New("object not found")))
		}

		resp := a.logAndGetErrorResponse("read object list failed", err)
		return ctx.JSON(http.StatusNotFound, resp)
	}

	var addrObj oid.Address
	addrObj.SetContainer(cnrID)
	addrObj.SetObject(buf[0])

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return a.headByAddress(ctx, addrObj, params.Download, principal, true)
}
