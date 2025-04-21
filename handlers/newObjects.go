package handlers

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
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
	"go.uber.org/zap"
)

// maxRangeStart represents the maximum start range position for reading a payload in one piece
// to detect the Content-Type in the beginning and return the payload simultaneously.
const maxRangeStart = 4096

// NewUploadContainerObject handler that upload file as object with attributes to NeoFS.
func (a *RestAPI) NewUploadContainerObject(ctx echo.Context, containerID apiserver.ContainerId, params apiserver.NewUploadContainerObjectParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.NewUploadContainerObjectDuration)()
	}

	var (
		err           error
		addr          oid.Address
		btoken        *bearer.Token
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

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	btoken, err = getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid bearer token", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	filtered, err := parseAndFilterAttributes(log, params.XAttributes)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not process header "+userAttributesHeader, err, log)
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
		attributes = append(attributes, *attribute)
	}

	// sets Content-Type attribute if the attribute isn't already set
	// and if the Content-Type header is present and non-empty
	if _, ok := filtered[object.AttributeContentType]; !ok {
		if ct := ctx.Request().Header.Get("Content-Type"); len(ct) > 0 {
			attrContentType := object.NewAttribute(object.AttributeContentType, ct)
			log.Debug("Added attribute", zap.String("key", object.AttributeContentType), zap.String("value", ct))
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
				resp := a.logAndGetErrorResponse("could not parse header Date", err, log.With(zap.String("date", date)))
				return ctx.JSON(http.StatusBadRequest, resp)
			}

			tsStr := strconv.FormatInt(parsedTime.Unix(), 10)
			timestamp := object.NewAttribute(object.AttributeTimestamp, tsStr)
			log.Debug("Added attribute", zap.String("key", object.AttributeTimestamp), zap.String("value", tsStr))
			attributes = append(attributes, *timestamp)
		}
	}

	var hdr object.Object
	hdr.SetContainerID(idCnr)
	a.setOwner(&hdr, btoken)
	hdr.SetAttributes(attributes...)

	wp := func(w io.Writer) error {
		var err error
		if cln := ctx.Request().ContentLength; cln >= 0 && uint64(cln) < a.payloadBufferSize { // negative means unknown
			if cln != 0 { // otherwise io.CopyBuffer panics
				_, err = io.CopyBuffer(w, ctx.Request().Body, make([]byte, cln))
			}
		} else {
			_, err = io.CopyBuffer(w, ctx.Request().Body, make([]byte, a.payloadBufferSize))
		}
		return err
	}

	idObj, err := a.putObject(ctx, hdr, btoken, wp)
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

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	addr, err := parseAddress(containerID, objectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("get bearer token", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if params.Range != nil {
		return a.getRange(ctx, addr, *params.Range, params.Download, btoken, log)
	}
	return a.getByAddress(ctx, addr, params.Download, btoken, true, log)
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

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

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

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("get bearer token", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	return a.headByAddress(ctx, addr, params.Download, btoken, true, log)
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

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	var cnrID cid.ID
	if err = cnrID.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("get bearer token", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	objectID, err := a.search(ctx.Request().Context(), btoken, cnrID, attrKey, attrVal, object.MatchStringEqual)
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
		return a.getRange(ctx, addrObj, *params.Range, params.Download, btoken, log)
	}
	return a.getByAddress(ctx, addrObj, params.Download, btoken, true, log)
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

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	var cnrID cid.ID
	if err = cnrID.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("get bearer token", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	objectID, err := a.search(ctx.Request().Context(), btoken, cnrID, attrKey, attrVal, object.MatchStringEqual)
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

	return a.headByAddress(ctx, addrObj, params.Download, btoken, true, log)
}

func (a *RestAPI) getRange(ctx echo.Context, addr oid.Address, rangeParam string, downloadParam *string, btoken *bearer.Token, log *zap.Logger) error {
	// Read the object header to determine the attributes and the size of the payload.
	var prm client.PrmObjectHead
	if btoken != nil {
		attachBearer(&prm, btoken)
	}

	header, err := a.pool.ObjectHead(ctx.Request().Context(), addr.Container(), addr.Object(), a.signer, prm)
	if err != nil {
		if isNotFoundError(err) {
			resp := a.logAndGetErrorResponse("head object: not found", err, log)
			return ctx.JSON(http.StatusNotFound, resp)
		}
		resp := a.logAndGetErrorResponse("head object", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	payloadSize := header.PayloadSize()

	// Parse range parameters.
	var start, end uint64
	start, end, err = getRangeParams(rangeParam, payloadSize)
	if err != nil {
		resp := a.logAndGetErrorResponse("get range params", err, log.With(zap.String("range", rangeParam)))
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
		header:      *header,
	}
	contentType := a.setAttributes(ctx, param, log)

	// Find offset and length.
	separateContentType := false
	offset := start
	if len(contentType) == 0 {
		if start > maxRangeStart {
			// We need to detect the Content-Type in a separate object range request
			// because the start of the requested payload is far from the beginning.
			separateContentType = true
		} else {
			// We should read payload from the beginning to detect ContentType.
			offset = 0
		}
	}
	length := end - offset + 1
	log.Debug("Params for ObjectRangeInit",
		zap.Bool("separateContentType", separateContentType),
		zap.Uint64("offset", offset),
		zap.Uint64("length", length))

	// Get object range.
	var prmRange client.PrmObjectRange
	if btoken != nil {
		attachBearer(&prmRange, btoken)
	}

	resObj, err := a.pool.ObjectRangeInit(ctx.Request().Context(), addr.Container(), addr.Object(), offset, length, a.signer, prmRange)
	if err != nil {
		return ctx.JSON(getResponseCodeFromStatus(err), util.NewErrorResponse(err))
	}

	payload := io.ReadCloser(resObj)

	if len(contentType) == 0 {
		if separateContentType {
			readerInit := func(sz uint64) (io.Reader, error) {
				beginObj, err := a.pool.ObjectRangeInit(ctx.Request().Context(), addr.Container(), addr.Object(), 0, sz, a.signer, prmRange)
				if err != nil {
					return nil, err
				}
				return beginObj, nil
			}

			// Determine the Content-Type in a separate request .
			contentType, _, err = readContentType(payloadSize, readerInit)
			if err != nil {
				resp := a.logAndGetErrorResponse("invalid  ContentType", err, log)
				return ctx.JSON(getResponseCodeFromStatus(err), resp)
			}
		} else {
			// Determine the Content-Type from the payload head.
			var payloadHead []byte

			contentType, payloadHead, err = readContentType(length, func(uint64) (io.Reader, error) {
				return payload, nil
			})
			if err != nil {
				resp := a.logAndGetErrorResponse("invalid  ContentType", err, log)
				return ctx.JSON(getResponseCodeFromStatus(err), resp)
			}

			// A piece of `payload` was read and is stored in `payloadHead`.
			// RangeReader allows reading data from both `payloadHead` and `payload` starting from position `start`,
			// regardless of where the `start` is.
			log.Debug("RangeReader params",
				zap.Int("payloadHead length", len(payloadHead)),
				zap.Uint64("length", length),
				zap.Uint64("start", start))
			rangeReader := NewRangeReader(payload, payloadHead, length, start)
			payload = readCloser{rangeReader, rangeReader}
		}
	}

	ctx.Response().Header().Set("Content-Type", contentType)
	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	ctx.Response().Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, payloadSize))
	ctx.Response().Header().Set("Content-Length", strconv.FormatUint(end-start+1, 10))
	ctx.Response().Header().Set("Accept-Ranges", "bytes")

	return ctx.Stream(http.StatusPartialContent, contentType, payload)
}

func getRangeParams(rangeParam string, payloadSize uint64) (end, start uint64, err error) {
	const (
		prefix  = "bytes="
		base    = 10
		bitSize = 64
	)

	// Preliminary checks.
	if payloadSize == 0 {
		return 0, 0, errors.New("zero payload size")
	}
	var found bool
	if rangeParam, found = strings.CutPrefix(rangeParam, prefix); !found {
		return 0, 0, errors.New("bytes= prefix required")
	}
	arr := strings.Split(rangeParam, "-")
	if len(arr) > 2 {
		return 0, 0, errors.New("unsupported multipart range request")
	} else if len(arr) != 2 || (arr[0] == "" && arr[1] == "") {
		return 0, 0, errors.New("wrong Range header format")
	}

	// Parse range parameters.
	var err0, err1 error

	if len(arr[0]) == 0 {
		end, err1 = strconv.ParseUint(arr[1], base, bitSize)
		start = payloadSize - end
		end = payloadSize - 1
	} else if len(arr[1]) == 0 {
		start, err0 = strconv.ParseUint(arr[0], base, bitSize)
		end = payloadSize - 1
	} else {
		start, err0 = strconv.ParseUint(arr[0], base, bitSize)
		end, err1 = strconv.ParseUint(arr[1], base, bitSize)
		if end > payloadSize-1 {
			end = payloadSize - 1
		}
	}

	if err0 != nil || err1 != nil || start > end || start > payloadSize {
		return 0, 0, errors.New("invalid range parameters")
	}
	return start, end, nil
}
