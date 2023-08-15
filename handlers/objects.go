package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-openapi/runtime/middleware"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

const (
	attributeFilePath = "FilePath"
)

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

	objInfo, err := a.pool.ObjectHead(ctx, addr.Container(), addr.Object(), a.signer, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("head object", err)
		return errorResponse.WithPayload(resp)
	}

	var header object.Object
	if !objInfo.ReadHeader(&header) {
		resp := a.logAndGetErrorResponse("header is empty", nil)
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

func headObjectBaseInfo(ctx context.Context, p *pool.Pool, cnrID cid.ID, objID oid.ID, btoken *bearer.Token, signer user.Signer) (*models.ObjectBaseInfo, error) {
	var prm client.PrmObjectHead
	attachBearer(&prm, btoken)

	objInfo, err := p.ObjectHead(ctx, cnrID, objID, signer, prm)
	if err != nil {
		return nil, err
	}

	var header object.Object
	if !objInfo.ReadHeader(&header) {
		return nil, errors.New("header is empty")
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
		case attributeFilePath:
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
