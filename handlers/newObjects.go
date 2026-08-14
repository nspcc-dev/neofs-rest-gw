package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"go.uber.org/zap"
)

// NewUploadContainerObject handler that upload file as object with attributes to NeoFS.
func (a *RestAPI) NewUploadContainerObject(ctx echo.Context, containerID apiserver.ContainerId, params apiserver.NewUploadContainerObjectParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.NewUploadContainerObjectDuration)()
	}

	var (
		err           error
		addr          oid.Address
		walletConnect apiserver.SignatureScheme
		log           = a.log.With(zap.String(handlerFieldName, "NewUploadContainerObject"), zap.String("containerID", containerID))
	)

	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	var idCnr cid.ID
	if err = idCnr.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	btoken, sessionTokenV2, err := getBearerAndSession(ctx, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("auth failed", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	attrHeaderValue, attrHeaderName := params.XAttributes, userAttributesHeader
	if params.XAttributesBase64 != nil {
		decoded, err := base64.StdEncoding.DecodeString(*params.XAttributesBase64)
		if err != nil {
			resp := a.logAndGetErrorResponse("could not decode header "+userAttributesEncodedHeader, err, log)
			return ctx.JSON(http.StatusBadRequest, resp)
		}

		var val = string(decoded)
		attrHeaderValue, attrHeaderName = &val, userAttributesEncodedHeader
	}

	filtered, err := parseAndFilterAttributes(log, attrHeaderValue)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not process header "+attrHeaderName, err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	addExpirationHeaders(filtered, params)
	if needParseExpiration(filtered) {
		epochDuration, err := getEpochDurations(ctx.Request().Context(), a.networkInfoGetter)
		if err != nil {
			resp := a.logAndGetErrorResponse("could not get epoch durations from network info", err, log)
			return ctx.JSON(getResponseCodeFromStatus(err), resp)
		}

		if err = prepareExpirationHeader(filtered, epochDuration, time.Now()); err != nil {
			resp := a.logAndGetErrorResponse("could not parse expiration header", err, log)
			return ctx.JSON(http.StatusBadRequest, resp)
		}
	}

	attributes := make([]object.Attribute, 0, len(filtered))
	// prepares attributes from filtered headers
	for key, val := range filtered {
		attribute := object.NewAttribute(key, val)
		log.Debug("Added attribute", zap.String("key", key), zap.String("value", val))
		attributes = append(attributes, attribute)
	}

	// sets Content-Type attribute if the attribute isn't already set
	// and if the Content-Type header is present and non-empty
	if _, ok := filtered[object.AttributeContentType]; !ok {
		if ct := ctx.Request().Header.Get("Content-Type"); len(ct) > 0 {
			attrContentType := object.NewAttribute(object.AttributeContentType, ct)
			log.Debug("Added attribute", zap.String("key", object.AttributeContentType), zap.String("value", ct))
			attributes = append(attributes, attrContentType)
		}
	}
	// sets Timestamp attribute if it wasn't set from header and enabled by settings
	if _, ok := filtered[object.AttributeTimestamp]; !ok {
		if a.defaultTimestamp {
			timestamp := object.NewAttribute(object.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
			attributes = append(attributes, timestamp)
		} else if date := ctx.Request().Header.Get("Date"); len(date) > 0 {
			parsedTime, err := time.Parse(time.RFC1123, date)
			if err != nil {
				resp := a.logAndGetErrorResponse("could not parse header Date", err, log.With(zap.String("date", date)))
				return ctx.JSON(http.StatusBadRequest, resp)
			}

			tsStr := strconv.FormatInt(parsedTime.Unix(), 10)
			timestamp := object.NewAttribute(object.AttributeTimestamp, tsStr)
			log.Debug("Added attribute", zap.String("key", object.AttributeTimestamp), zap.String("value", tsStr))
			attributes = append(attributes, timestamp)
		}
	}

	var hdr object.Object
	hdr.SetContainerID(idCnr)
	a.setOwner(&hdr, btoken)
	hdr.SetAttributes(attributes...)

	idObj, err := a.putObject(ctx, hdr, btoken, sessionTokenV2, ctx.Request().Body)
	if err != nil {
		resp := a.logAndGetErrorResponse("put object", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
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
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.NewGetContainerObjectDuration)()
	}

	log := a.log.With(
		zap.String(handlerFieldName, "NewGetContainerObject"),
		zap.String("containerID", containerID),
		zap.String("objectID", objectID),
	)

	addr, err := parseAddress(containerID, objectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, sessionTokenV2, err := getBearerAndSession(ctx, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("auth failed", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if params.Range != nil {
		return a.getRange(ctx, addr, *params.Range, params.Download, btoken, sessionTokenV2, log)
	}
	return a.getByAddress(ctx, addr, params.Download, btoken, sessionTokenV2, true, log)
}

// NewHeadContainerObject handler that returns object info (using container ID and object ID).
func (a *RestAPI) NewHeadContainerObject(ctx echo.Context, containerID apiserver.ContainerId, objectID apiserver.ObjectId, params apiserver.NewHeadContainerObjectParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.NewHeadContainerObjectDuration)()
	}

	log := a.log.With(
		zap.String(handlerFieldName, "NewHeadContainerObject"),
		zap.String("containerID", containerID),
		zap.String("objectID", objectID),
	)

	addr, err := parseAddress(containerID, objectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, sessionTokenV2, err := getBearerAndSession(ctx, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("auth failed", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	return a.headByAddress(ctx, addr, params.Download, btoken, sessionTokenV2, true, log)
}

// NewGetByAttribute handler that returns object (payload and attributes) by a specific attribute.
func (a *RestAPI) NewGetByAttribute(ctx echo.Context, containerID apiserver.ContainerId, attrKey apiserver.AttrKey, attrVal apiserver.AttrVal, params apiserver.NewGetByAttributeParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.NewGetByAttributeDuration)()
	}

	log := a.log.With(
		zap.String(handlerFieldName, "NewGetByAttribute"),
		zap.String("containerID", containerID),
		zap.String("attrKey", attrKey),
		zap.String("attrVal", attrVal),
	)

	var cnrID cid.ID
	if err := cnrID.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, sessionTokenV2, err := getBearerAndSession(ctx, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("auth failed", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	objectID, err := a.search(ctx.Request().Context(), btoken, sessionTokenV2, cnrID, attrKey, attrVal, object.MatchStringEqual)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not search for objects", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	if objectID.IsZero() {
		return ctx.JSON(http.StatusNotFound, util.NewErrorResponse(errors.New("object not found")))
	}

	var addrObj oid.Address
	addrObj.SetContainer(cnrID)
	addrObj.SetObject(objectID)

	if params.Range != nil {
		return a.getRange(ctx, addrObj, *params.Range, params.Download, btoken, sessionTokenV2, log)
	}
	return a.getByAddress(ctx, addrObj, params.Download, btoken, sessionTokenV2, true, log)
}

// NewHeadByAttribute handler that returns object info (payload and attributes) by a specific attribute.
func (a *RestAPI) NewHeadByAttribute(ctx echo.Context, containerID apiserver.ContainerId, attrKey apiserver.AttrKey, attrVal apiserver.AttrVal, params apiserver.NewHeadByAttributeParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.NewHeadByAttributeDuration)()
	}

	log := a.log.With(
		zap.String(handlerFieldName, "NewHeadByAttribute"),
		zap.String("containerID", containerID),
		zap.String("attrKey", attrKey),
		zap.String("attrVal", attrVal),
	)

	var cnrID cid.ID
	if err := cnrID.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, sessionTokenV2, err := getBearerAndSession(ctx, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("auth failed", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	objectID, err := a.search(ctx.Request().Context(), btoken, sessionTokenV2, cnrID, attrKey, attrVal, object.MatchStringEqual)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not search for objects", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	if objectID.IsZero() {
		return ctx.JSON(http.StatusNotFound, util.NewErrorResponse(errors.New("object not found")))
	}

	var addrObj oid.Address
	addrObj.SetContainer(cnrID)
	addrObj.SetObject(objectID)

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")

	return a.headByAddress(ctx, addrObj, params.Download, btoken, sessionTokenV2, true, log)
}

func (a *RestAPI) getRange(ctx echo.Context, addr oid.Address, rangeParam string, downloadParam *string, btoken *bearer.Token, sessionToken *session.Token, log *zap.Logger) error {
	rng, err := parseRangeHeader(rangeParam)
	if err != nil {
		resp := a.logAndGetErrorResponse("parse Range header", err, log.With(zap.String("range", rangeParam)))
		return ctx.JSON(http.StatusRequestedRangeNotSatisfiable, resp)
	}

	var prm client.PrmObjectGet
	attachBearer(&prm, btoken)
	if sessionToken != nil {
		prm.WithinSessionV2(*sessionToken)
	}

	switch rng.kind {
	case rangeSuffix:
		prm.SetRangeSuffix(rng.suffix)
	case rangeFrom:
		prm.SetRangeFrom(rng.first)
	default:
		prm.SetRangeBounds(rng.first, rng.last)
	}

	prm.SkipChecksumVerification()

	header, resObj, err := a.pool.ObjectGetInit(ctx.Request().Context(), addr.Container(), addr.Object(), a.signer, prm)
	if err != nil {
		if isNotFoundError(err) {
			resp := a.logAndGetErrorResponse("get object range: not found", err, log)
			return ctx.JSON(http.StatusNotFound, resp)
		}
		resp := a.logAndGetErrorResponse("get object range", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	payload := readCloseWriterTo(resObj)
	payloadSize := header.PayloadSize()

	start, end, err := rng.resolveRangeForResponse(payloadSize)
	if err != nil {
		_ = payload.Close()
		resp := a.logAndGetErrorResponse("resolve range", err, log.With(zap.String("range", rangeParam), zap.Uint64("payloadSize", payloadSize)))
		return ctx.JSON(http.StatusRequestedRangeNotSatisfiable, resp)
	}

	log.Debug("Range",
		zap.Uint64("start", start),
		zap.Uint64("end", end),
		zap.Uint64("payloadSize", payloadSize))

	// Set attributes.
	param := setAttributeParams{
		cid:         addr.Container().String(),
		oid:         addr.Object().String(),
		payloadSize: payloadSize,
		download:    downloadParam,
		useJSON:     true,
		header:      header,
	}
	contentType := a.setAttributes(ctx, param, log)

	if len(contentType) == 0 {
		if start == 0 {
			// The payload starts at the object beginning, detect the Content-Type from it.
			var payloadHead []byte

			contentType, payloadHead, err = readContentType(end-start+1, payload)
			if err != nil {
				_ = payload.Close()
				resp := a.logAndGetErrorResponse("invalid  ContentType", err, log)
				return ctx.JSON(getResponseCodeFromStatus(err), resp)
			}

			// Reset the payload reader since a part of the data has been read.
			payload = &prefixedReadCloser{
				prefix: payloadHead,
				reader: payload,
			}
		} else {
			// The requested payload does not start at the object beginning,
			// so the Content-Type requires a separate request.
			contentType, err = a.detectContentTypeFromObjectBeginning(ctx.Request().Context(), addr, payloadSize, btoken, sessionToken)
			if err != nil {
				_ = payload.Close()
				resp := a.logAndGetErrorResponse("invalid  ContentType", err, log)
				return ctx.JSON(getResponseCodeFromStatus(err), resp)
			}
		}
	}

	ctx.Response().Header().Set("Content-Type", contentType)
	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	ctx.Response().Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, payloadSize))
	ctx.Response().Header().Set("Content-Length", strconv.FormatUint(end-start+1, 10))
	ctx.Response().Header().Set("Accept-Ranges", "bytes")

	return ctx.Stream(http.StatusPartialContent, contentType, payload)
}
