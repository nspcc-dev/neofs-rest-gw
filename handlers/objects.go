package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-api-go/v2/container"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

const (
	sizeToDetectType          = 512
	userAttributeHeaderPrefix = "X-Attribute-"

	attributeFilepathHTTP = "Filepath"
	attributeFilenameHTTP = "Filename"
)

type readCloser struct {
	io.Reader
	io.Closer
}

// PutObjects handler that uploads object to NeoFS.
func (a *API) PutObjects(params operations.PutObjectParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewPutObjectBadRequest()
	ctx := params.HTTPRequest.Context()

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, *params.WalletConnect, *params.FullBearer)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid bearer token", err)
		return errorResponse.WithPayload(resp)
	}

	var cnrID cid.ID
	if err = cnrID.DecodeString(*params.Object.ContainerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return errorResponse.WithPayload(resp)
	}

	payload, err := base64.StdEncoding.DecodeString(params.Object.Payload)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid object payload", err)
		return errorResponse.WithPayload(resp)
	}

	prm := PrmAttributes{
		DefaultTimestamp: a.defaultTimestamp,
		DefaultFileName:  *params.Object.FileName,
	}
	attributes, err := GetObjectAttributes(ctx, a.pool, params.Object.Attributes, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to get object attributes", err)
		return errorResponse.WithPayload(resp)
	}

	var obj object.Object
	obj.SetContainerID(cnrID)
	attachOwner(&obj, btoken)
	obj.SetAttributes(attributes...)

	var prmPutInit client.PrmObjectPutInit
	if btoken != nil {
		prmPutInit.WithBearerToken(*btoken)
	}

	writer, err := a.pool.ObjectPutInit(ctx, obj, a.signer, prmPutInit)
	if err != nil {
		resp := a.logAndGetErrorResponse("put object init", err)
		return errorResponse.WithPayload(resp)
	}

	var objID oid.ID

	data := bytes.NewReader(payload)
	chunk := make([]byte, a.maxObjectSize)
	_, err = io.CopyBuffer(writer, data, chunk)
	if err != nil {
		resp := a.logAndGetErrorResponse("write", err)
		return errorResponse.WithPayload(resp)
	}

	if err = writer.Close(); err != nil {
		resp := a.logAndGetErrorResponse("writer close", err)
		return errorResponse.WithPayload(resp)
	}

	objID = writer.GetResult().StoredObjectID()

	var resp models.Address
	resp.ContainerID = params.Object.ContainerID
	resp.ObjectID = util.NewString(objID.String())

	return operations.NewPutObjectOK().
		WithPayload(&resp).
		WithAccessControlAllowOrigin("*")
}

// GetObjectInfo handler that get object info.
func (a *API) GetObjectInfo(params operations.GetObjectInfoParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewGetObjectInfoBadRequest()
	ctx := params.HTTPRequest.Context()

	addr, err := parseAddress(params.ContainerID, params.ObjectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err)
		return errorResponse.WithPayload(resp)
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, *params.WalletConnect, *params.FullBearer)
	if err != nil {
		resp := a.logAndGetErrorResponse("get bearer token", err)
		return errorResponse.WithPayload(resp)
	}

	var prm client.PrmObjectHead
	attachBearer(&prm, btoken)

	header, err := a.pool.ObjectHead(ctx, addr.Container(), addr.Object(), a.signer, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("head object", err)
		return errorResponse.WithPayload(resp)
	}

	var resp models.ObjectInfo
	resp.ContainerID = util.NewString(params.ContainerID)
	resp.ObjectID = util.NewString(params.ObjectID)
	resp.OwnerID = util.NewString(header.OwnerID().String())
	resp.Attributes = make([]*models.Attribute, len(header.Attributes()))
	resp.ObjectSize = util.NewInteger(int64(header.PayloadSize()))
	resp.PayloadSize = util.NewInteger(0)

	for i, attr := range header.Attributes() {
		resp.Attributes[i] = &models.Attribute{
			Key:   util.NewString(attr.Key()),
			Value: util.NewString(attr.Value()),
		}
	}

	if header.PayloadSize() == 0 {
		return operations.NewGetObjectInfoOK().WithPayload(&resp)
	}

	offset, length, err := prepareOffsetLength(params, header.PayloadSize())
	if err != nil {
		errResp := a.logAndGetErrorResponse("invalid range param", err)
		return errorResponse.WithPayload(errResp)
	}

	if uint64(*params.MaxPayloadSize) < length {
		return operations.NewGetObjectInfoOK().WithPayload(&resp)
	}

	var prmRange client.PrmObjectRange
	attachBearer(&prmRange, btoken)

	rangeRes, err := a.pool.ObjectRangeInit(ctx, addr.Container(), addr.Object(), offset, length, a.signer, prmRange)
	if err != nil {
		errResp := a.logAndGetErrorResponse("range object", err)
		return errorResponse.WithPayload(errResp)
	}

	defer func() {
		if err = rangeRes.Close(); err != nil {
			a.log.Error("close range result", zap.Error(err))
		}
	}()

	sb := new(strings.Builder)
	encoder := base64.NewEncoder(base64.StdEncoding, sb)
	payloadSize, err := io.Copy(encoder, rangeRes)
	if err != nil {
		errResp := a.logAndGetErrorResponse("encode object payload", err)
		return errorResponse.WithPayload(errResp)
	}
	if err = encoder.Close(); err != nil {
		errResp := a.logAndGetErrorResponse("close encoder", err)
		return errorResponse.WithPayload(errResp)
	}

	resp.Payload = sb.String()
	resp.PayloadSize = util.NewInteger(payloadSize)

	return operations.NewGetObjectInfoOK().
		WithPayload(&resp).
		WithAccessControlAllowOrigin("*")
}

// DeleteObject handler that removes object from NeoFS.
func (a *API) DeleteObject(params operations.DeleteObjectParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewDeleteObjectBadRequest()
	ctx := params.HTTPRequest.Context()

	addr, err := parseAddress(params.ContainerID, params.ObjectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err)
		return errorResponse.WithPayload(resp)
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, *params.WalletConnect, *params.FullBearer)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to get bearer token", err)
		return errorResponse.WithPayload(resp)
	}

	var prm client.PrmObjectDelete
	prm.WithBearerToken(*btoken)

	cl, err := a.pool.RawClient()
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to get client", err)
		return errorResponse.WithPayload(resp)
	}

	if _, err = cl.ObjectDelete(ctx, addr.Container(), addr.Object(), a.signer, prm); err != nil {
		resp := a.logAndGetErrorResponse("failed to delete object", err)
		return errorResponse.WithPayload(resp)
	}

	return operations.NewDeleteObjectOK().
		WithPayload(util.NewSuccessResponse()).
		WithAccessControlAllowOrigin("*")
}

// SearchObjects handler that removes object from NeoFS.
func (a *API) SearchObjects(params operations.SearchObjectsParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewSearchObjectsBadRequest()
	ctx := params.HTTPRequest.Context()

	var cnrID cid.ID
	if err := cnrID.DecodeString(params.ContainerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return errorResponse.WithPayload(resp)
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, *params.WalletConnect, *params.FullBearer)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to get bearer token", err)
		return errorResponse.WithPayload(resp)
	}

	filters, err := util.ToNativeFilters(params.SearchFilters)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to transform to native", err)
		return errorResponse.WithPayload(resp)
	}

	var prm client.PrmObjectSearch
	attachBearer(&prm, btoken)
	prm.SetFilters(filters)

	resSearch, err := a.pool.ObjectSearchInit(ctx, cnrID, a.signer, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to search objects", err)
		return errorResponse.WithPayload(resp)
	}

	offset := int(*params.Offset)
	size := int(*params.Limit)

	var iterateErr error
	var obj *models.ObjectBaseInfo
	var objects []*models.ObjectBaseInfo

	i := 0
	err = resSearch.Iterate(func(id oid.ID) bool {
		if i < offset {
			i++
			return false
		}

		if obj, iterateErr = headObjectBaseInfo(ctx, a.pool, cnrID, id, btoken, a.signer); iterateErr != nil {
			return true
		}

		objects = append(objects, obj)

		return len(objects) == size
	})
	if err == nil {
		err = iterateErr
	}
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to search objects", err)
		return errorResponse.WithPayload(resp)
	}

	list := &models.ObjectList{
		Size:    util.NewInteger(int64(len(objects))),
		Objects: objects,
	}

	return operations.NewSearchObjectsOK().
		WithPayload(list).
		WithAccessControlAllowOrigin("*")
}

// GetContainerObject handler that returns object (using container ID and object ID).
func (a *API) GetContainerObject(params operations.GetContainerObjectParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewGetContainerObjectBadRequest()
	ctx := params.HTTPRequest.Context()

	addr, err := parseAddress(params.ContainerID, params.ObjectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err)
		return errorResponse.WithPayload(resp)
	}

	return a.getByAddress(ctx, NewGetContainerObjectBadRequestWrapper, addr, params.HTTPRequest.URL.Query().Get("download"), principal)
}

// getByAddress returns object (using container ID and object ID).
func (a *API) getByAddress(ctx context.Context, createErrorResponse ErrorResponseCreator, addr oid.Address, downloadParam string, principal *models.Principal) middleware.Responder {
	errorResponse := createErrorResponse() // Use the passed function to create the error response

	var prm client.PrmObjectGet

	if principal != nil {
		btoken, err := getBearerTokenFromString(string(*principal))
		if err != nil {
			resp := a.logAndGetErrorResponse("get bearer token", err)
			return errorResponse.WithPayload(resp)
		}
		attachBearer(&prm, btoken)
	}

	header, payloadReader, err := a.pool.ObjectGetInit(ctx, addr.Container(), addr.Object(), a.signer, prm)
	if err != nil {
		if isNotFoundError(err) {
			resp := a.logAndGetErrorResponse("not found", err)
			return operations.NewGetContainerObjectNotFound().WithPayload(resp)
		}
		resp := a.logAndGetErrorResponse("get object", err)
		return errorResponse.WithPayload(resp)
	}

	payloadSize := header.PayloadSize()
	res := operations.NewGetContainerObjectOK()

	responder := a.setAttributes(res, payloadSize, addr.Container().String(), addr.Object().String(), header, downloadParam)
	contentType := res.ContentType
	var payload io.ReadCloser = payloadReader
	if len(contentType) == 0 {
		if payloadSize > 0 {
			// determine the Content-Type from the payload head
			var payloadHead []byte

			contentType, payloadHead, err = readContentType(payloadSize, func(uint64) (io.Reader, error) {
				return payload, nil
			})
			if err != nil {
				resp := a.logAndGetErrorResponse("invalid  ContentType", err)
				return errorResponse.WithPayload(resp)
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

	res.WithContentType(contentType).
		WithPayload(payload)

	if responder != nil {
		return responder
	}

	return res
}

// HeadContainerObject handler that returns object info (using container ID and object ID).
func (a *API) HeadContainerObject(params operations.HeadContainerObjectParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewHeadContainerObjectBadRequest()
	ctx := params.HTTPRequest.Context()

	addr, err := parseAddress(params.ContainerID, params.ObjectID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid address", err)
		return errorResponse.WithPayload(resp)
	}

	return a.headByAddress(ctx, NewHeadContainerObjectBadRequestWrapper, addr, params.HTTPRequest.URL.Query().Get("download"), principal)
}

// headByAddress returns object info (using container ID and object ID).
func (a *API) headByAddress(ctx context.Context, createErrorResponse ErrorResponseCreator, addr oid.Address, downloadParam string, principal *models.Principal) middleware.Responder {
	errorResponse := createErrorResponse() // Use the passed function to create the error response
	var prm client.PrmObjectHead

	if principal != nil {
		btoken, err := getBearerTokenFromString(string(*principal))
		if err != nil {
			resp := a.logAndGetErrorResponse("get bearer token", err)
			return errorResponse.WithPayload(resp)
		}
		attachBearer(&prm, btoken)
	}

	header, err := a.pool.ObjectHead(ctx, addr.Container(), addr.Object(), a.signer, prm)
	if err != nil {
		if isNotFoundError(err) {
			resp := a.logAndGetErrorResponse("not found", err)
			return operations.NewHeadContainerObjectNotFound().WithPayload(resp)
		}
		resp := a.logAndGetErrorResponse("head object", err)
		return errorResponse.WithPayload(resp)
	}

	payloadSize := header.PayloadSize()
	res := operations.NewHeadContainerObjectOK()

	responder := a.setAttributes(res, payloadSize, addr.Container().String(), addr.Object().String(), *header, downloadParam)
	contentType := res.ContentType
	if len(contentType) == 0 {
		if payloadSize > 0 {
			contentType, _, err = readContentType(payloadSize, func(sz uint64) (io.Reader, error) {
				var prmRange client.PrmObjectRange

				resObj, err := a.pool.ObjectRangeInit(ctx, addr.Container(), addr.Object(), 0, sz, a.signer, prmRange)
				if err != nil {
					return nil, err
				}
				return resObj, nil
			})
			if err != nil {
				resp := a.logAndGetErrorResponse("invalid  ContentType", err)
				return errorResponse.WithPayload(resp)
			}
		} else {
			contentType = http.DetectContentType(nil)
		}
	}

	res.WithContentType(contentType)

	if responder != nil {
		return responder
	}

	return res
}

func isNotFoundError(err error) bool {
	return errors.Is(err, apistatus.ErrObjectNotFound) ||
		errors.Is(err, apistatus.ErrContainerNotFound) ||
		errors.Is(err, apistatus.ErrObjectAlreadyRemoved)
}

type attributeSetter interface {
	SetContentLength(contentLength string)
	SetContentType(contentType string)
	SetXContainerID(xContainerID string)
	SetXObjectID(xObjectID string)
	SetXOwnerID(xOwnerID string)
	SetContentDisposition(contentDisposition string)
	SetXAttributeFileName(xAttributeFileName string)
	SetXAttributeTimestamp(xAttributeTimestamp int64)
	SetLastModified(lastModified string)
	WriteResponse(rw http.ResponseWriter, producer runtime.Producer)
}

func (a *API) setAttributes(res attributeSetter, payloadSize uint64, cid string, oid string, header object.Object, download string) middleware.Responder {
	res.SetContentLength(strconv.FormatUint(payloadSize, 10))
	res.SetXContainerID(cid)
	res.SetXObjectID(oid)
	res.SetXOwnerID(header.OwnerID().EncodeToString())

	var responder middleware.Responder
	dis := "inline"
	attributes := header.Attributes()
	if len(attributes) > 0 {
		responder = middleware.ResponderFunc(func(rw http.ResponseWriter, pr runtime.Producer) {
			for _, attr := range attributes {
				key := attr.Key()
				val := attr.Value()
				if !isValidToken(key) || !isValidValue(val) {
					continue
				}
				switch key {
				case object.AttributeFileName:
					switch download {
					case "1", "t", "T", "true", "TRUE", "True", "y", "yes", "Y", "YES", "Yes":
						dis = "attachment"
					}
					res.SetContentDisposition(dis + "; filename=" + path.Base(val))
					res.SetXAttributeFileName(val)
				case object.AttributeTimestamp:
					attrTimestamp, err := strconv.ParseInt(val, 10, 64)
					if err != nil {
						a.log.Info("attribute timestamp parsing error",
							zap.String("container ID", cid),
							zap.String("object ID", oid),
							zap.Error(err))
						continue
					}
					res.SetXAttributeTimestamp(attrTimestamp)
					res.SetLastModified(time.Unix(attrTimestamp, 0).UTC().Format(http.TimeFormat))
				case object.AttributeContentType:
					res.SetContentType(val)
				default:
					if strings.HasPrefix(key, container.SysAttributePrefix) {
						key = systemBackwardTranslator(key)
					}
					rw.Header().Set(userAttributeHeaderPrefix+key, attr.Value())
				}
			}
			res.WriteResponse(rw, pr)
		})
	}
	return responder
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
	key = strings.TrimPrefix(key, container.SysAttributePrefix)

	var res strings.Builder
	res.WriteString("Neofs-")

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

func headObjectBaseInfo(ctx context.Context, p *pool.Pool, cnrID cid.ID, objID oid.ID, btoken *bearer.Token, signer user.Signer) (*models.ObjectBaseInfo, error) {
	var prm client.PrmObjectHead
	attachBearer(&prm, btoken)

	header, err := p.ObjectHead(ctx, cnrID, objID, signer, prm)
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}

	resp := &models.ObjectBaseInfo{
		Address: &models.Address{
			ContainerID: util.NewString(cnrID.String()),
			ObjectID:    util.NewString(objID.String()),
		},
	}

	for _, attr := range header.Attributes() {
		switch attr.Key() {
		case object.AttributeFileName:
			resp.Name = attr.Value()
		case object.AttributeFilePath:
			resp.FilePath = attr.Value()
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

func getBearerToken(token *models.Principal, signature, key *string, isWalletConnect, isFullToken bool) (*bearer.Token, error) {
	if token == nil {
		return nil, nil
	}

	bt := &BearerToken{Token: string(*token)}

	if !isFullToken {
		if signature == nil || key == nil {
			return nil, errors.New("missed signature or key header")
		}

		bt.Signature = *signature
		bt.Key = *key
	}

	return prepareBearerToken(bt, isWalletConnect, isFullToken)
}

func prepareBearerToken(bt *BearerToken, isWalletConnect, isFullToken bool) (*bearer.Token, error) {
	data, err := base64.StdEncoding.DecodeString(bt.Token)
	if err != nil {
		return nil, fmt.Errorf("can't base64-decode bearer token: %w", err)
	}

	if isFullToken {
		var btoken bearer.Token
		if err = btoken.Unmarshal(data); err != nil {
			return nil, fmt.Errorf("couldn't unmarshall bearer token: %w", err)
		}
		if !btoken.VerifySignature() {
			return nil, fmt.Errorf("invalid signature")
		}

		return &btoken, nil
	}

	signature, err := hex.DecodeString(bt.Signature)
	if err != nil {
		return nil, fmt.Errorf("couldn't decode bearer signature: %w", err)
	}

	ownerKey, err := keys.NewPublicKeyFromString(bt.Key)
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch bearer token owner key: %w", err)
	}

	body := new(acl.BearerTokenBody)
	if err = body.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("can't unmarshal bearer token body: %w", err)
	}

	v2signature := new(refs.Signature)
	v2signature.SetScheme(refs.ECDSA_SHA512)
	if isWalletConnect {
		v2signature.SetScheme(refs.ECDSA_RFC6979_SHA256_WALLET_CONNECT)
	}
	v2signature.SetSign(signature)
	v2signature.SetKey(ownerKey.Bytes())

	var v2btoken acl.BearerToken
	v2btoken.SetBody(body)
	v2btoken.SetSignature(v2signature)

	var btoken bearer.Token
	if err = btoken.ReadFromV2(v2btoken); err != nil {
		return nil, fmt.Errorf("read from v2 token: %w", err)
	}

	if !btoken.VerifySignature() {
		return nil, fmt.Errorf("invalid signature")
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
		return nil, fmt.Errorf("invalid signature")
	}

	return &btoken, nil
}

func prepareOffsetLength(params operations.GetObjectInfoParams, objSize uint64) (uint64, uint64, error) {
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
		owner := btoken.ResolveIssuer()
		obj.SetOwnerID(&owner)
	}
}

// UploadContainerObject handler that upload file as object with attributes to NeoFS.
func (a *API) UploadContainerObject(params operations.UploadContainerObjectParams, principal *models.Principal) middleware.Responder {
	var (
		header *multipart.FileHeader
		file   multipart.File
		err    error
		idObj  oid.ID
		addr   oid.Address
		btoken *bearer.Token
	)
	errorResponse := operations.NewUploadContainerObjectBadRequest()
	ctx := params.HTTPRequest.Context()

	var idCnr cid.ID
	if err := idCnr.DecodeString(params.ContainerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return errorResponse.WithPayload(resp)
	}

	if principal != nil {
		btoken, err = getBearerTokenFromString(string(*principal))
		if err != nil {
			resp := a.logAndGetErrorResponse("get bearer token", err)
			return errorResponse.WithPayload(resp)
		}
	}

	if swagFile, ok := params.Payload.(*swag.File); ok {
		header = swagFile.Header
		file = swagFile.Data
	} else {
		var fileKey string
		for fileKey = range params.HTTPRequest.MultipartForm.File {
			file, header, err = params.HTTPRequest.FormFile(fileKey)
			if err != nil {
				resp := a.logAndGetErrorResponse(fmt.Sprintf("get file %q from HTTP request", fileKey), err)
				return errorResponse.WithPayload(resp)
			}
			break
		}
		if fileKey == "" {
			resp := a.logAndGetErrorResponse("no multipart/form file", http.ErrMissingFile)
			return errorResponse.WithPayload(resp)
		}
	}

	defer func() {
		if file == nil {
			return
		}
		err := file.Close()
		a.log.Debug(
			"close temporary multipart/form file",
			zap.Stringer("address", addr),
			zap.String("filename", header.Filename),
			zap.Error(err),
		)
	}()

	filtered, err := filterHeaders(a.log, params.HTTPRequest.Header)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not process headers", err)
		return errorResponse.WithPayload(resp)
	}

	if needParseExpiration(filtered) {
		epochDuration, err := getEpochDurations(ctx, a.pool)
		if err != nil {
			resp := a.logAndGetErrorResponse("could not get epoch durations from network info", err)
			return errorResponse.WithPayload(resp)
		}

		now := time.Now()
		if rawHeader := params.HTTPRequest.Header.Get("Date"); rawHeader != "" {
			if parsed, err := time.Parse(http.TimeFormat, rawHeader); err != nil {
				a.log.Warn("could not parse client time", zap.String("Date header", rawHeader), zap.Error(err))
			} else {
				now = parsed
			}
		}

		if err = prepareExpirationHeader(filtered, epochDuration, now); err != nil {
			resp := a.logAndGetErrorResponse("could not parse expiration header", err)
			return errorResponse.WithPayload(resp)
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

	var obj object.Object
	obj.SetContainerID(idCnr)
	a.setOwner(&obj, btoken)
	obj.SetAttributes(attributes...)

	var prmPutInit client.PrmObjectPutInit
	if btoken != nil {
		prmPutInit.WithBearerToken(*btoken)
	}

	writer, err := a.pool.ObjectPutInit(ctx, obj, a.signer, prmPutInit)
	if err != nil {
		resp := a.logAndGetErrorResponse("put object init", err)
		return errorResponse.WithPayload(resp)
	}

	chunk := make([]byte, a.maxObjectSize)
	_, err = io.CopyBuffer(writer, file, chunk)
	if err != nil {
		resp := a.logAndGetErrorResponse("write", err)
		return errorResponse.WithPayload(resp)
	}

	if err = writer.Close(); err != nil {
		resp := a.logAndGetErrorResponse("writer close", err)
		return errorResponse.WithPayload(resp)
	}

	idObj = writer.GetResult().StoredObjectID()
	addr.SetObject(idObj)
	addr.SetContainer(idCnr)

	var resp models.AddressForUpload
	resp.ContainerID = &params.ContainerID
	resp.ObjectID = util.NewString(idObj.String())

	return operations.NewUploadContainerObjectOK().
		WithPayload(&resp).
		WithAccessControlAllowOrigin("*")
}

func (a *API) setOwner(obj *object.Object, btoken *bearer.Token) {
	if btoken != nil {
		owner := btoken.ResolveIssuer()
		obj.SetOwnerID(&owner)
	} else {
		ownerID := a.signer.UserID()
		obj.SetOwnerID(&ownerID)
	}
}

// GetByAttribute handler that returns object (payload and attributes) by a specific attribute.
func (a *API) GetByAttribute(params operations.GetByAttributeParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewGetByAttributeBadRequest()
	ctx := params.HTTPRequest.Context()

	var cnrID cid.ID
	if err := cnrID.DecodeString(params.ContainerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return errorResponse.WithPayload(resp)
	}

	res, err := a.search(ctx, principal, cnrID, params.AttrKey, params.AttrVal, object.MatchStringEqual)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not search for objects", err)
		return operations.NewGetContainerObjectNotFound().WithPayload(resp)
	}

	defer func() {
		if err = res.Close(); err != nil {
			a.log.Error("failed to close resource", zap.Error(err))
		}
	}()

	buf := make([]oid.ID, 1)

	n, _ := res.Read(buf)
	if n == 0 {
		err = res.Close()

		if err == nil || errors.Is(err, io.EOF) {
			resp := a.logAndGetErrorResponse("object not found", err)
			return operations.NewGetContainerObjectNotFound().WithPayload(resp)
		}

		resp := a.logAndGetErrorResponse("read object list failed", err)
		return operations.NewGetContainerObjectNotFound().WithPayload(resp)
	}

	var addrObj oid.Address
	addrObj.SetContainer(cnrID)
	addrObj.SetObject(buf[0])

	return a.getByAddress(ctx, NewGetByAttributeBadRequestWrapper, addrObj, params.HTTPRequest.URL.Query().Get("download"), principal)
}

// HeadByAttribute handler that returns object info (payload and attributes) by a specific attribute.
func (a *API) HeadByAttribute(params operations.HeadByAttributeParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewHeadByAttributeBadRequest()
	ctx := params.HTTPRequest.Context()

	var cnrID cid.ID
	if err := cnrID.DecodeString(params.ContainerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return errorResponse.WithPayload(resp)
	}

	res, err := a.search(ctx, principal, cnrID, params.AttrKey, params.AttrVal, object.MatchStringEqual)
	if err != nil {
		resp := a.logAndGetErrorResponse("could not search for objects", err)
		return operations.NewHeadContainerObjectNotFound().WithPayload(resp)
	}

	defer func() {
		if err = res.Close(); err != nil {
			a.log.Error("failed to close resource", zap.Error(err))
		}
	}()

	buf := make([]oid.ID, 1)

	n, _ := res.Read(buf)
	if n == 0 {
		err = res.Close()

		if err == nil || errors.Is(err, io.EOF) {
			resp := a.logAndGetErrorResponse("object not found", err)
			return operations.NewHeadContainerObjectNotFound().WithPayload(resp)
		}

		resp := a.logAndGetErrorResponse("read object list failed", err)
		return operations.NewHeadContainerObjectNotFound().WithPayload(resp)
	}

	var addrObj oid.Address
	addrObj.SetContainer(cnrID)
	addrObj.SetObject(buf[0])

	return a.headByAddress(ctx, NewHeadByAttributeBadRequestWrapper, addrObj, params.HTTPRequest.URL.Query().Get("download"), principal)
}

func (a *API) search(ctx context.Context, principal *models.Principal, cid cid.ID, key, val string, op object.SearchMatchType) (*client.ObjectListReader, error) {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()
	filters.AddFilter(key, val, op)

	var prm client.PrmObjectSearch
	prm.SetFilters(filters)

	if principal != nil {
		btoken, err := getBearerTokenFromString(string(*principal))
		if err != nil {
			return nil, err
		}
		attachBearer(&prm, btoken)
	}

	return a.pool.ObjectSearchInit(ctx, cid, a.signer, prm)
}
