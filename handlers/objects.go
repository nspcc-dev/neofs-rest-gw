package handlers

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

const (
	sizeToDetectType          = 512
	userAttributeHeaderPrefix = "X-Attribute-"
	userAttributesHeader      = "X-Attributes"

	attributeFilepathHTTP = "Filepath"
	attributeFilenameHTTP = "Filename"

	// according to the [http] package.
	defaultMaxMemory = 32 << 20 // 32 MB
)

type readCloser struct {
	io.Reader
	io.Closer
}

type setAttributeParams struct {
	cid         string
	oid         string
	payloadSize uint64
	download    *string
	useJSON     bool
	header      object.Object
}

// PutObject handler that uploads object to NeoFS.
func (a *RestAPI) PutObject(ctx echo.Context, params apiserver.PutObjectParams) error {
	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	var body apiserver.ObjectUpload
	if err = ctx.Bind(&body); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err))
	}

	var walletConnect apiserver.SignatureScheme
	if params.WalletConnect != nil {
		walletConnect = *params.WalletConnect
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, walletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid bearer token", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var cnrID cid.ID
	if err = cnrID.DecodeString(body.ContainerId); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var payload []byte

	if body.Payload != nil {
		payload, err = base64.StdEncoding.DecodeString(*body.Payload)
		if err != nil {
			resp := a.logAndGetErrorResponse("invalid object payload", err)
			return ctx.JSON(http.StatusBadRequest, resp)
		}
	}

	prm := PrmAttributes{
		DefaultTimestamp: a.defaultTimestamp,
		DefaultFileName:  body.FileName,
	}
	attributes, err := getObjectAttributes(ctx.Request().Context(), a.networkInfoGetter, body.Attributes, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to get object attributes", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var hdr object.Object
	hdr.SetContainerID(cnrID)
	attachOwner(&hdr, btoken)
	hdr.SetAttributes(attributes...)

	objID, err := a.putObject(ctx, hdr, btoken, func(w io.Writer) error {
		_, err := w.Write(payload)
		return err
	})
	if err != nil {
		return err
	}

	var resp apiserver.Address
	resp.ContainerId = body.ContainerId
	resp.ObjectId = objID.String()

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// GetObjectInfo handler that get object info.
func (a *RestAPI) GetObjectInfo(ctx echo.Context, containerID apiserver.ContainerId, objectID apiserver.ObjectId, params apiserver.GetObjectInfoParams) error {
	addr, err := parseAddress(containerID, objectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
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

	var prm client.PrmObjectHead
	attachBearer(&prm, btoken)

	header, err := a.pool.ObjectHead(ctx.Request().Context(), addr.Container(), addr.Object(), a.signer, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("head object", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var resp apiserver.ObjectInfo
	resp.ContainerId = containerID
	resp.ObjectId = objectID
	resp.OwnerId = header.Owner().String()
	resp.Attributes = make([]apiserver.Attribute, len(header.Attributes()))
	resp.ObjectSize = header.PayloadSize()

	for i, attr := range header.Attributes() {
		resp.Attributes[i] = apiserver.Attribute{
			Key:   attr.Key(),
			Value: attr.Value(),
		}
	}

	if header.PayloadSize() == 0 {
		ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
		return ctx.JSON(http.StatusOK, resp)
	}

	offset, length, err := prepareOffsetLength(params, header.PayloadSize())
	if err != nil {
		errResp := a.logAndGetErrorResponse("invalid range param", err)
		return ctx.JSON(http.StatusBadRequest, errResp)
	}

	if params.MaxPayloadSize != nil && uint64(*params.MaxPayloadSize) < length {
		ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
		return ctx.JSON(http.StatusOK, resp)
	}

	var prmRange client.PrmObjectRange
	attachBearer(&prmRange, btoken)

	rangeRes, err := a.pool.ObjectRangeInit(ctx.Request().Context(), addr.Container(), addr.Object(), offset, length, a.signer, prmRange)
	if err != nil {
		errResp := a.logAndGetErrorResponse("range object", err)
		return ctx.JSON(http.StatusBadRequest, errResp)
	}

	defer func() {
		if err = rangeRes.Close(); err != nil {
			zap.L().Error("close range result", zap.Error(err))
		}
	}()

	sb := new(strings.Builder)
	encoder := base64.NewEncoder(base64.StdEncoding, sb)
	payloadSize, err := io.Copy(encoder, rangeRes)
	if err != nil {
		errResp := a.logAndGetErrorResponse("encode object payload", err)
		return ctx.JSON(http.StatusBadRequest, errResp)
	}
	if err = encoder.Close(); err != nil {
		errResp := a.logAndGetErrorResponse("close encoder", err)
		return ctx.JSON(http.StatusBadRequest, errResp)
	}

	resp.Payload = util.NewString(sb.String())
	resp.PayloadSize = payloadSize

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// DeleteObject handler that removes object from NeoFS.
func (a *RestAPI) DeleteObject(ctx echo.Context, containerID apiserver.ContainerId, objectID apiserver.ObjectId, params apiserver.DeleteObjectParams) error {
	addr, err := parseAddress(containerID, objectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
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

	var prm client.PrmObjectDelete
	if btoken != nil {
		prm.WithBearerToken(*btoken)
	}

	cl, err := a.pool.RawClient()
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to get client", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if _, err = cl.ObjectDelete(ctx.Request().Context(), addr.Container(), addr.Object(), a.signer, prm); err != nil {
		resp := a.logAndGetErrorResponse("failed to delete object", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// SearchObjects handler that searches object in NeoFS.
func (a *RestAPI) SearchObjects(ctx echo.Context, containerID apiserver.ContainerId, params apiserver.SearchObjectsParams) error {
	var cnrID cid.ID
	if err := cnrID.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
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

	var searchFilters apiserver.SearchFilters
	if err = ctx.Bind(&searchFilters); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err))
	}

	filters, err := util.ToNativeFilters(searchFilters)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to transform to native", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var prm client.PrmObjectSearch
	attachBearer(&prm, btoken)
	prm.SetFilters(filters)

	resSearch, err := a.pool.ObjectSearchInit(ctx.Request().Context(), cnrID, a.signer, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to search objects", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	offset, limit, err := getOffsetAndLimit(params.Offset, params.Limit)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid parameter", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var iterateErr error
	var obj *apiserver.ObjectBaseInfo
	var objects []apiserver.ObjectBaseInfo

	i := 0
	err = resSearch.Iterate(func(id oid.ID) bool {
		if i < offset {
			i++
			return false
		}

		if obj, iterateErr = headObjectBaseInfo(ctx.Request().Context(), a.pool, cnrID, id, btoken, a.signer); iterateErr != nil {
			return true
		}

		if obj != nil {
			objects = append(objects, *obj)
		}

		return len(objects) == limit
	})
	if err == nil {
		err = iterateErr
	}
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to search objects", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	list := &apiserver.ObjectList{
		Size:    len(objects),
		Objects: objects,
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, list)
}

// GetContainerObject handler that returns object (using container ID and object ID).
func (a *RestAPI) GetContainerObject(ctx echo.Context, containerID apiserver.ContainerId, objectID apiserver.ObjectId, params apiserver.GetContainerObjectParams) error {
	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	addr, err := parseAddress(containerID, objectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var btoken *bearer.Token
	if principal != "" {
		btoken, err = getBearerTokenFromString(principal)
		if err != nil {
			resp := a.logAndGetErrorResponse("get bearer token", err)
			return ctx.JSON(http.StatusBadRequest, resp)
		}
	}
	return a.getByAddress(ctx, addr, params.Download, btoken, false)
}

// getByAddress returns object (using container ID and object ID).
func (a *RestAPI) getByAddress(ctx echo.Context, addr oid.Address, downloadParam *string, btoken *bearer.Token, useJSON bool) error {
	var prm client.PrmObjectGet
	if btoken != nil {
		attachBearer(&prm, btoken)
	}

	header, payloadReader, err := a.pool.ObjectGetInit(ctx.Request().Context(), addr.Container(), addr.Object(), a.signer, prm)
	if err != nil {
		if isNotFoundError(err) {
			resp := a.logAndGetErrorResponse("not found", err)
			return ctx.JSON(http.StatusNotFound, resp)
		}
		resp := a.logAndGetErrorResponse("get object", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	payloadSize := header.PayloadSize()
	param := setAttributeParams{
		cid:         addr.Container().String(),
		oid:         addr.Object().String(),
		payloadSize: payloadSize,
		download:    downloadParam,
		useJSON:     useJSON,
		header:      header,
	}
	contentType := a.setAttributes(ctx, param)
	payload := io.ReadCloser(payloadReader)

	if len(contentType) == 0 {
		if payloadSize > 0 {
			// determine the Content-Type from the payload head
			var payloadHead []byte

			contentType, payloadHead, err = readContentType(payloadSize, func(uint64) (io.Reader, error) {
				return payload, nil
			})
			if err != nil {
				resp := a.logAndGetErrorResponse("invalid  ContentType", err)
				return ctx.JSON(http.StatusBadRequest, resp)
			}

			// reset payload reader since a part of the data has been read
			var headReader io.Reader = bytes.NewReader(payloadHead)

			if uint64(len(payloadHead)) != payloadSize { // otherwise, we've already read full payload
				headReader = io.MultiReader(headReader, payload)
			}

			payload = readCloser{headReader, payload}
		} else {
			contentType = http.DetectContentType(nil)
		}
	}
	ctx.Response().Header().Set("Content-Type", contentType)
	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	ctx.Response().Header().Set("Accept-Ranges", "bytes")

	return ctx.Stream(http.StatusOK, contentType, payload)
}

// HeadContainerObject handler that returns object info (using container ID and object ID).
func (a *RestAPI) HeadContainerObject(ctx echo.Context, containerID apiserver.ContainerId, objectID apiserver.ObjectId, params apiserver.HeadContainerObjectParams) error {
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

	var btoken *bearer.Token
	if principal != "" {
		btoken, err = getBearerTokenFromString(principal)
		if err != nil {
			resp := a.logAndGetErrorResponse("get bearer token", err)
			return ctx.JSON(http.StatusBadRequest, resp)
		}
	}

	return a.headByAddress(ctx, addr, params.Download, btoken, false)
}

// headByAddress returns object info (using container ID and object ID).
func (a *RestAPI) headByAddress(ctx echo.Context, addr oid.Address, downloadParam *string, btoken *bearer.Token, useJSON bool) error {
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
	param := setAttributeParams{
		cid:         addr.Container().String(),
		oid:         addr.Object().String(),
		payloadSize: payloadSize,
		download:    downloadParam,
		useJSON:     useJSON,
		header:      *header,
	}
	contentType := a.setAttributes(ctx, param)
	if len(contentType) == 0 {
		if payloadSize > 0 {
			contentType, _, err = readContentType(payloadSize, func(sz uint64) (io.Reader, error) {
				var prmRange client.PrmObjectRange
				attachBearer(&prmRange, btoken)

				resObj, err := a.pool.ObjectRangeInit(ctx.Request().Context(), addr.Container(), addr.Object(), 0, sz, a.signer, prmRange)
				if err != nil {
					return nil, err
				}
				return resObj, nil
			})
			if err != nil {
				resp := a.logAndGetErrorResponse("invalid  ContentType", err)
				return ctx.JSON(http.StatusBadRequest, resp)
			}
		} else {
			contentType = http.DetectContentType(nil)
		}
	}
	ctx.Response().Header().Set("Content-Type", contentType)
	ctx.Response().Header().Set("Accept-Ranges", "bytes")

	return nil
}

func isNotFoundError(err error) bool {
	return errors.Is(err, apistatus.ErrObjectNotFound) ||
		errors.Is(err, apistatus.ErrContainerNotFound) ||
		errors.Is(err, apistatus.ErrObjectAlreadyRemoved)
}

func (a *RestAPI) setAttributes(ctx echo.Context, params setAttributeParams) string {
	ctx.Response().Header().Set("Content-Length", strconv.FormatUint(params.payloadSize, 10))

	attrJSON := make(map[string]string)
	ctx.Response().Header().Set("X-Container-Id", params.cid)
	ctx.Response().Header().Set("X-Object-Id", params.oid)
	ctx.Response().Header().Set("X-Owner-Id", params.header.Owner().EncodeToString())

	var (
		contentType string
		dis         = "inline"
		attributes  = params.header.Attributes()
	)

	if paramIsPositive(params.download) {
		dis = "attachment"
	}
	ctx.Response().Header().Set("Content-Disposition", dis)

	if len(attributes) > 0 {
		for _, attr := range attributes {
			key := attr.Key()
			val := attr.Value()
			if !isValidToken(key) || !isValidValue(val) {
				continue
			}

			switch key {
			case object.AttributeFileName:
				// Add FileName to Content-Disposition
				ctx.Response().Header().Set("Content-Disposition", ctx.Response().Header().Get("Content-Disposition")+"; filename="+path.Base(val))
				if params.useJSON {
					attrJSON[key] = val
				} else {
					ctx.Response().Header().Set(userAttributeHeaderPrefix+key, val)
				}
			case object.AttributeTimestamp:
				attrTimestamp, err := strconv.ParseInt(val, 10, 64)
				if err != nil {
					a.log.Info("attribute timestamp parsing error",
						zap.String("container ID", params.cid),
						zap.String("object ID", params.oid),
						zap.Error(err))
					continue
				}
				if params.useJSON {
					attrJSON[key] = val
				} else {
					ctx.Response().Header().Set(userAttributeHeaderPrefix+key, val)
				}
				ctx.Response().Header().Set("Last-Modified", time.Unix(attrTimestamp, 0).UTC().Format(http.TimeFormat))
			case object.AttributeContentType:
				contentType = val
			default:
				if params.useJSON {
					attrJSON[key] = attr.Value()
				} else {
					if strings.HasPrefix(key, SystemAttributePrefix) {
						key = systemBackwardTranslator(key)
					}
					ctx.Response().Header().Set(userAttributeHeaderPrefix+key, attr.Value())
				}
			}
		}
	}

	if params.useJSON {
		// Marshal the map to a JSON string
		s, err := json.Marshal(attrJSON)
		if err != nil {
			a.log.Info("marshal attributes error",
				zap.String("container ID", params.cid),
				zap.String("object ID", params.oid),
				zap.Error(err))
		}
		ctx.Response().Header().Set(userAttributesHeader, string(s))
	}

	return contentType
}

// initializes io.Reader with the limited size and detects Content-Type from it.
// Returns r's error directly. Also returns the processed data.
func readContentType(maxSize uint64, rInit func(uint64) (io.Reader, error)) (string, []byte, error) {
	if maxSize > sizeToDetectType {
		maxSize = sizeToDetectType
	}

	buf := make([]byte, maxSize)

	r, err := rInit(maxSize)
	if err != nil {
		return "", nil, err
	}

	n, err := io.ReadFull(r, buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", nil, err
	}

	buf = buf[:n]

	return http.DetectContentType(buf), buf, nil
}

func isValidToken(s string) bool {
	for _, c := range s {
		if c <= ' ' || c > 127 {
			return false
		}
		if strings.ContainsRune("()<>@,;:\\\"/[]?={}", c) {
			return false
		}
	}
	return true
}

func isValidValue(s string) bool {
	for _, c := range s {
		// HTTP specification allows for more technically, but we don't want to escape things.
		if c < ' ' || c > 127 || c == '"' {
			return false
		}
	}
	return true
}

// systemBackwardTranslator is used to convert headers looking like '__NEOFS__ATTR_NAME' to 'Neofs-Attr-Name'.
func systemBackwardTranslator(key string) string {
	// trim specified prefix '__NEOFS__'
	key = strings.TrimPrefix(key, SystemAttributePrefix)

	var res strings.Builder
	res.WriteString(neofsAttributeHeaderPrefix)

	strs := strings.Split(key, "_")
	for i, s := range strs {
		s = title(strings.ToLower(s))
		res.WriteString(s)
		if i != len(strs)-1 {
			res.WriteString("-")
		}
	}

	return res.String()
}

func title(str string) string {
	if str == "" {
		return ""
	}

	r, size := utf8.DecodeRuneInString(str)
	r0 := unicode.ToTitle(r)
	return string(r0) + str[size:]
}

func headObjectBaseInfo(ctx context.Context, p *pool.Pool, cnrID cid.ID, objID oid.ID, btoken *bearer.Token, signer user.Signer) (*apiserver.ObjectBaseInfo, error) {
	var prm client.PrmObjectHead
	attachBearer(&prm, btoken)

	header, err := p.ObjectHead(ctx, cnrID, objID, signer, prm)
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}

	resp := &apiserver.ObjectBaseInfo{
		Address: apiserver.Address{
			ContainerId: cnrID.String(),
			ObjectId:    objID.String(),
		},
	}

	for _, attr := range header.Attributes() {
		switch attr.Key() {
		case object.AttributeFileName:
			v := attr.Value()
			resp.Name = &v
		case object.AttributeFilePath:
			v := attr.Value()
			resp.FilePath = &v
		}
	}

	return resp, nil
}

func parseAddress(containerID, objectID string) (oid.Address, error) {
	var cnrID cid.ID
	if err := cnrID.DecodeString(containerID); err != nil {
		return oid.Address{}, fmt.Errorf("invalid container id: %w", err)
	}
	var objID oid.ID
	if err := objID.DecodeString(objectID); err != nil {
		return oid.Address{}, fmt.Errorf("invalid object id: %w", err)
	}

	var addr oid.Address
	addr.SetContainer(cnrID)
	addr.SetObject(objID)

	return addr, nil
}

func getBearerToken(token string, signature, key *string, isWalletConnect bool) (*bearer.Token, error) {
	if token == "" {
		return nil, nil
	}

	isFullToken := false
	bt := &BearerToken{Token: token}

	if signature != nil && key != nil {
		bt.Signature = *signature
		bt.Key = *key
	} else if signature == nil && key == nil {
		isFullToken = true
	} else {
		return nil, errors.New("missed signature or key header")
	}

	return prepareBearerToken(bt, isWalletConnect, isFullToken)
}

func prepareBearerToken(bt *BearerToken, isWalletConnect, isFullToken bool) (*bearer.Token, error) {
	data, err := base64.StdEncoding.DecodeString(bt.Token)
	if err != nil {
		return nil, fmt.Errorf("can't base64-decode bearer token: %w", err)
	}

	var btoken bearer.Token
	if isFullToken {
		if err = btoken.Unmarshal(data); err != nil {
			return nil, fmt.Errorf("couldn't unmarshall bearer token: %w", err)
		}
		if !btoken.VerifySignature() {
			return nil, errors.New("invalid signature")
		}

		return &btoken, nil
	}

	signature, err := hex.DecodeString(bt.Signature)
	if err != nil {
		return nil, fmt.Errorf("couldn't decode bearer signature: %w", err)
	}

	pub, err := hex.DecodeString(bt.Key)
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch bearer token owner key: %w", err)
	}
	if _, err = keys.NewPublicKeyFromBytes(pub, elliptic.P256()); err != nil {
		return nil, fmt.Errorf("couldn't fetch bearer token owner key: %w", err)
	}

	if err = btoken.UnmarshalSignedData(data); err != nil {
		return nil, fmt.Errorf("can't unmarshal bearer token body: %w", err)
	}

	var scheme neofscrypto.Scheme
	if isWalletConnect {
		scheme = neofscrypto.ECDSA_WALLETCONNECT
	} else {
		scheme = neofscrypto.ECDSA_SHA512
	}

	btoken.AttachSignature(neofscrypto.NewSignatureFromRawKey(scheme, pub, signature))

	if !btoken.VerifySignature() {
		return nil, errors.New("invalid signature")
	}

	return &btoken, nil
}

func getBearerTokenFromString(token string) (*bearer.Token, error) {
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("can't base64-decode bearer token: %w", err)
	}

	var btoken bearer.Token
	if err = btoken.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("couldn't unmarshall bearer token: %w", err)
	}
	if !btoken.VerifySignature() {
		return nil, errors.New("invalid signature")
	}

	return &btoken, nil
}

func prepareOffsetLength(params apiserver.GetObjectInfoParams, objSize uint64) (uint64, uint64, error) {
	var offset, length uint64
	if params.RangeOffset != nil || params.RangeLength != nil {
		if params.RangeOffset == nil || params.RangeLength == nil {
			return 0, 0, errors.New("both offset and length must be provided")
		}
		offset = uint64(*params.RangeOffset)
		length = uint64(*params.RangeLength)
	} else {
		length = objSize
	}

	if offset >= objSize {
		return 0, 0, fmt.Errorf("offset '%d' must be less than object size '%d'", offset, objSize)
	}

	if offset+length > objSize {
		return 0, 0, fmt.Errorf("end of range '%d' must be less or equal object size '%d'", offset+length, objSize)
	}

	return offset, length, nil
}

type prmWithBearer interface {
	WithBearerToken(t bearer.Token)
}

func attachBearer(prm prmWithBearer, btoken *bearer.Token) {
	if btoken != nil {
		prm.WithBearerToken(*btoken)
	}
}
func attachOwner(obj *object.Object, btoken *bearer.Token) {
	if btoken != nil {
		obj.SetOwner(btoken.ResolveIssuer())
	}
}

// UploadContainerObject handler that upload file as object with attributes to NeoFS.
func (a *RestAPI) UploadContainerObject(ctx echo.Context, containerID apiserver.ContainerId, _ apiserver.UploadContainerObjectParams) error {
	var (
		header *multipart.FileHeader
		file   multipart.File
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

	if err = ctx.Request().ParseMultipartForm(defaultMaxMemory); err != nil {
		resp := a.logAndGetErrorResponse("parse multi form", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if ctx.Request().MultipartForm == nil {
		resp := a.logAndGetErrorResponse("multi form is nil", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var fileKey string
	for fileKey = range ctx.Request().MultipartForm.File {
		file, header, err = ctx.Request().FormFile(fileKey)
		if err != nil {
			resp := a.logAndGetErrorResponse(fmt.Sprintf("get file %q from HTTP request", fileKey), err)
			return ctx.JSON(http.StatusBadRequest, resp)
		}
		defer func() {
			err := file.Close()
			a.log.Debug(
				"close temporary multipart/form file",
				zap.Stringer("address", addr),
				zap.String("filename", header.Filename),
				zap.Error(err),
			)
		}()

		break
	}

	if fileKey == "" {
		resp := a.logAndGetErrorResponse("no multipart/form file", http.ErrMissingFile)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	filtered, err := filterHeaders(a.log, ctx.Request().Header)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not process headers", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if needParseExpiration(filtered) {
		epochDuration, err := getEpochDurations(ctx.Request().Context(), a.networkInfoGetter)
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
	// sets FileName attribute if it wasn't set from header
	if _, ok := filtered[object.AttributeFileName]; !ok {
		filename := object.NewAttribute(object.AttributeFileName, header.Filename)
		attributes = append(attributes, *filename)
	}
	// sets Content-Type attribute if it wasn't set from header
	if _, ok := filtered[object.AttributeContentType]; !ok {
		if contentTypes, ok := header.Header["Content-Type"]; ok && len(contentTypes) > 0 {
			contentType := contentTypes[0]
			cType := object.NewAttribute(object.AttributeContentType, contentType)
			attributes = append(attributes, *cType)
		}
	}
	// sets Timestamp attribute if it wasn't set from header and enabled by settings
	if _, ok := filtered[object.AttributeTimestamp]; !ok && a.defaultTimestamp {
		timestamp := object.NewAttribute(object.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
		attributes = append(attributes, *timestamp)
	}

	var hdr object.Object
	hdr.SetContainerID(idCnr)
	a.setOwner(&hdr, btoken)
	hdr.SetAttributes(attributes...)

	idObj, err := a.putObject(ctx, hdr, btoken, func(w io.Writer) error {
		var buf []byte
		if header.Size > 0 && uint64(header.Size) < a.payloadBufferSize {
			buf = make([]byte, header.Size)
		} else {
			// Size field is not documented, so we cannot be sure what exactly non-positive
			// values mean. Thus, it's better to keep default behavior for them.
			buf = make([]byte, a.payloadBufferSize)
		}
		_, err = io.CopyBuffer(w, file, buf)
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

func (a *RestAPI) setOwner(obj *object.Object, btoken *bearer.Token) {
	if btoken != nil {
		obj.SetOwner(btoken.ResolveIssuer())
	} else {
		obj.SetOwner(a.signer.UserID())
	}
}

// GetByAttribute handler that returns object (payload and attributes) by a specific attribute.
func (a *RestAPI) GetByAttribute(ctx echo.Context, containerID apiserver.ContainerId, attrKey apiserver.AttrKey, attrVal apiserver.AttrVal, params apiserver.GetByAttributeParams) error {
	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	var cnrID cid.ID
	if err = cnrID.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var btoken *bearer.Token
	if principal != "" {
		btoken, err = getBearerTokenFromString(principal)
		if err != nil {
			resp := a.logAndGetErrorResponse("get bearer token", err)
			return ctx.JSON(http.StatusBadRequest, resp)
		}
	}

	res, err := a.search(ctx.Request().Context(), btoken, cnrID, attrKey, attrVal, object.MatchStringEqual)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not search for objects", err)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
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
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	var addrObj oid.Address
	addrObj.SetContainer(cnrID)
	addrObj.SetObject(buf[0])

	return a.getByAddress(ctx, addrObj, params.Download, btoken, false)
}

// HeadByAttribute handler that returns object info (payload and attributes) by a specific attribute.
func (a *RestAPI) HeadByAttribute(ctx echo.Context, containerID apiserver.ContainerId, attrKey apiserver.AttrKey, attrVal apiserver.AttrVal, params apiserver.HeadByAttributeParams) error {
	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	var cnrID cid.ID
	if err = cnrID.DecodeString(containerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var btoken *bearer.Token
	if principal != "" {
		btoken, err = getBearerTokenFromString(principal)
		if err != nil {
			resp := a.logAndGetErrorResponse("get bearer token", err)
			return ctx.JSON(http.StatusBadRequest, resp)
		}
	}

	res, err := a.search(ctx.Request().Context(), btoken, cnrID, attrKey, attrVal, object.MatchStringEqual)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not search for objects", err)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
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
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	var addrObj oid.Address
	addrObj.SetContainer(cnrID)
	addrObj.SetObject(buf[0])

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")

	return a.headByAddress(ctx, addrObj, params.Download, btoken, false)
}

func (a *RestAPI) search(ctx context.Context, btoken *bearer.Token, cid cid.ID, key, val string, op object.SearchMatchType) (*client.ObjectListReader, error) {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()
	filters.AddFilter(key, val, op)

	var prm client.PrmObjectSearch
	prm.SetFilters(filters)

	if btoken != nil {
		attachBearer(&prm, btoken)
	}

	return a.pool.ObjectSearchInit(ctx, cid, a.signer, prm)
}
