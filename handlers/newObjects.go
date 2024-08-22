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
	var (
		err           error
		addr          oid.Address
		btoken        *bearer.Token
		walletConnect apiserver.SignatureScheme
	)

	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	var idCnr cid.ID
	if err = idCnr.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	btoken, err = getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid bearer token", err)
		return ctx.JSON(http.StatusBadRequest, resp)
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
		a.log.Debug("Added attribute", zap.String("key", key), zap.String("value", val))
		attributes = append(attributes, *attribute)
	}

	// sets Content-Type attribute if the attribute isn't already set
	// and if the Content-Type header is present and non-empty
	if _, ok := filtered[object.AttributeContentType]; !ok {
		if ct := ctx.Request().Header.Get("Content-Type"); len(ct) > 0 {
			attrContentType := object.NewAttribute(object.AttributeContentType, ct)
			a.log.Debug("Added attribute", zap.String("key", object.AttributeContentType), zap.String("value", ct))
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

			tsStr := strconv.FormatInt(parsedTime.Unix(), 10)
			timestamp := object.NewAttribute(object.AttributeTimestamp, tsStr)
			a.log.Debug("Added attribute", zap.String("key", object.AttributeTimestamp), zap.String("value", tsStr))
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

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("get bearer token", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if params.Range != nil {
		return a.getRange(ctx, addr, *params.Range, params.Download, btoken)
	}
	return a.getByAddress(ctx, addr, params.Download, btoken, true)
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

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("get bearer token", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	return a.headByAddress(ctx, addr, params.Download, btoken, true)
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

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("get bearer token", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	res, err := a.search(ctx.Request().Context(), btoken, cnrID, attrKey, attrVal, object.MatchStringEqual)
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

	if params.Range != nil {
		return a.getRange(ctx, addrObj, *params.Range, params.Download, btoken)
	}
	return a.getByAddress(ctx, addrObj, params.Download, btoken, true)
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

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("get bearer token", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	res, err := a.search(ctx.Request().Context(), btoken, cnrID, attrKey, attrVal, object.MatchStringEqual)
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

	return a.headByAddress(ctx, addrObj, params.Download, btoken, true)
}

func (a *RestAPI) getRange(ctx echo.Context, addr oid.Address, rangeParam string, downloadParam *string, btoken *bearer.Token) error {
	// Read the object header to determine the attributes and the size of the payload.
	var prm client.PrmObjectHead
	if btoken != nil {
		attachBearer(&prm, btoken)
	}

	header, err := a.pool.ObjectHead(ctx.Request().Context(), addr.Container(), addr.Object(), a.signer, prm)
	if err != nil {
		if isNotFoundError(err) {
			resp := a.logAndGetErrorResponse("not found", err)
			return ctx.JSON(http.StatusNotFound, resp)
		}
		resp := a.logAndGetErrorResponse("head object", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	payloadSize := header.PayloadSize()

	// Parse range parameters.
	var start, end uint64
	start, end, err = getRangeParams(rangeParam, payloadSize)
	if err != nil {
		resp := a.logAndGetErrorResponse("range", err, zap.String("range", rangeParam))
		return ctx.JSON(http.StatusRequestedRangeNotSatisfiable, resp)
	}

	a.log.Debug("Range",
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
	contentType := a.setAttributes(ctx, param)

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
	a.log.Debug("Params for ObjectRangeInit",
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
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	payload := io.ReadCloser(resObj)

	if len(contentType) == 0 {
		if separateContentType {
			// Determine the Content-Type in a separate request .
			contentType, _, err = readContentType(payloadSize, func(sz uint64) (io.Reader, error) {
				beginObj, err := a.pool.ObjectRangeInit(ctx.Request().Context(), addr.Container(), addr.Object(), 0, sz, a.signer, prmRange)
				if err != nil {
					return nil, err
				}
				return beginObj, nil
			})
			if err != nil {
				resp := a.logAndGetErrorResponse("invalid  ContentType", err)
				return ctx.JSON(http.StatusBadRequest, resp)
			}
		} else {
			// Determine the Content-Type from the payload head.
			var payloadHead []byte

			contentType, payloadHead, err = readContentType(length, func(uint64) (io.Reader, error) {
				return payload, nil
			})
			if err != nil {
				resp := a.logAndGetErrorResponse("invalid  ContentType", err)
				return ctx.JSON(http.StatusBadRequest, resp)
			}

			// A piece of `payload` was read and is stored in `payloadHead`.
			// RangeReader allows reading data from both `payloadHead` and `payload` starting from position `start`,
			// regardless of where the `start` is.
			a.log.Debug("RangeReader params",
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
