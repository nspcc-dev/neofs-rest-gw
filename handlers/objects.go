package handlers

import (
	"context"
	"crypto/ecdsa"
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
	walletconnect "github.com/nspcc-dev/neofs-rest-gw/internal/wallet-connect"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/token"
	"go.uber.org/zap"
)

// PutObjects handler that uploads object to NeoFS.
func (a *API) PutObjects(params operations.PutObjectParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewPutObjectBadRequest()
	ctx := params.HTTPRequest.Context()

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, *params.WalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid bearer token", err)
		return errorResponse.WithPayload(resp)
	}

	var cnrID cid.ID
	if err = cnrID.Parse(*params.Object.ContainerID); err != nil {
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

	obj := object.New()
	obj.SetContainerID(&cnrID)
	obj.SetOwnerID(btoken.OwnerID())
	obj.SetPayload(payload)
	obj.SetAttributes(attributes...)

	var prmPut pool.PrmObjectPut
	prmPut.SetHeader(*obj)
	prmPut.UseBearer(btoken)

	objID, err := a.pool.PutObject(ctx, prmPut)
	if err != nil {
		resp := a.logAndGetErrorResponse("put object", err)
		return errorResponse.WithPayload(resp)
	}

	var resp models.Address
	resp.ContainerID = params.Object.ContainerID
	resp.ObjectID = util.NewString(objID.String())

	return operations.NewPutObjectOK().WithPayload(&resp)
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

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, *params.WalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("get bearer token", err)
		return errorResponse.WithPayload(resp)
	}

	var prm pool.PrmObjectHead
	prm.SetAddress(*addr)
	prm.UseBearer(btoken)

	objInfo, err := a.pool.HeadObject(ctx, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("head object", err)
		return errorResponse.WithPayload(resp)
	}

	var resp models.ObjectInfo
	resp.ContainerID = util.NewString(params.ContainerID)
	resp.ObjectID = util.NewString(params.ObjectID)
	resp.OwnerID = util.NewString(objInfo.OwnerID().String())
	resp.Attributes = make([]*models.Attribute, len(objInfo.Attributes()))
	resp.ObjectSize = util.NewInteger(int64(objInfo.PayloadSize()))
	resp.PayloadSize = util.NewInteger(0)

	for i, attr := range objInfo.Attributes() {
		resp.Attributes[i] = &models.Attribute{
			Key:   util.NewString(attr.Key()),
			Value: util.NewString(attr.Value()),
		}
	}

	var prmRange pool.PrmObjectRange
	prmRange.SetAddress(*addr)
	prmRange.UseBearer(btoken)

	var offset, length uint64
	if params.RangeOffset != nil || params.RangeLength != nil {
		if params.RangeOffset == nil || params.RangeLength == nil {
			errResp := a.logAndGetErrorResponse("invalid range param", errors.New("both offset and length musded"))
			return errorResponse.WithPayload(errResp)
		}
		offset = uint64(*params.RangeOffset)
		length = uint64(*params.RangeLength)
	} else {
		length = objInfo.PayloadSize()
	}
	prmRange.SetOffset(offset)
	prmRange.SetLength(length)

	if uint64(*params.MaxPayloadSize) < length {
		return operations.NewGetObjectInfoOK().WithPayload(&resp)
	}

	rangeRes, err := a.pool.ObjectRange(ctx, prmRange)
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

	return operations.NewGetObjectInfoOK().WithPayload(&resp)
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

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, *params.WalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to get bearer token", err)
		return errorResponse.WithPayload(resp)
	}

	var prm pool.PrmObjectDelete
	prm.SetAddress(*addr)
	prm.UseBearer(btoken)

	if err = a.pool.DeleteObject(ctx, prm); err != nil {
		resp := a.logAndGetErrorResponse("failed to delete object", err)
		return errorResponse.WithPayload(resp)
	}

	return operations.NewDeleteObjectOK().WithPayload(util.NewSuccessResponse())
}

// SearchObjects handler that removes object from NeoFS.
func (a *API) SearchObjects(params operations.SearchObjectsParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewSearchObjectsBadRequest()
	ctx := params.HTTPRequest.Context()

	var cnrID cid.ID
	if err := cnrID.Parse(params.ContainerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return errorResponse.WithPayload(resp)
	}

	btoken, err := getBearerToken(principal, params.XBearerSignature, params.XBearerSignatureKey, *params.WalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to get bearer token", err)
		return errorResponse.WithPayload(resp)
	}

	filters, err := util.ToNativeFilters(params.SearchFilters)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to transform to native", err)
		return errorResponse.WithPayload(resp)
	}

	var prm pool.PrmObjectSearch
	prm.SetContainerID(cnrID)
	prm.UseBearer(btoken)
	prm.SetFilters(filters)

	resSearch, err := a.pool.SearchObjects(ctx, prm)
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

		if obj, iterateErr = headObjectBaseInfo(ctx, a.pool, &cnrID, &id, btoken); iterateErr != nil {
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

	return operations.NewSearchObjectsOK().WithPayload(list)
}

func headObjectBaseInfo(ctx context.Context, p *pool.Pool, cnrID *cid.ID, objID *oid.ID, btoken *token.BearerToken) (*models.ObjectBaseInfo, error) {
	addr := address.NewAddress()
	addr.SetContainerID(cnrID)
	addr.SetObjectID(objID)

	var prm pool.PrmObjectHead
	prm.SetAddress(*addr)
	prm.UseBearer(btoken)

	objInfo, err := p.HeadObject(ctx, prm)
	if err != nil {
		return nil, err
	}

	resp := &models.ObjectBaseInfo{
		Address: &models.Address{
			ContainerID: util.NewString(cnrID.String()),
			ObjectID:    util.NewString(objID.String()),
		},
	}

	for _, attr := range objInfo.Attributes() {
		if attr.Key() == object.AttributeFileName {
			resp.Name = attr.Value()
			break
		}
	}

	return resp, nil
}

func parseAddress(containerID, objectID string) (*address.Address, error) {
	var cnrID cid.ID
	if err := cnrID.Parse(containerID); err != nil {
		return nil, fmt.Errorf("invalid container id: %w", err)
	}
	var objID oid.ID
	if err := objID.Parse(objectID); err != nil {
		return nil, fmt.Errorf("invalid object id: %w", err)
	}

	addr := address.NewAddress()
	addr.SetContainerID(&cnrID)
	addr.SetObjectID(&objID)

	return addr, nil
}

func getBearerToken(token *models.Principal, signature, key string, isWalletConnect bool) (*token.BearerToken, error) {
	bt := &BearerToken{
		Token:     string(*token),
		Signature: signature,
		Key:       key,
	}

	return prepareBearerToken(bt, isWalletConnect)
}

func prepareBearerToken(bt *BearerToken, isWalletConnect bool) (*token.BearerToken, error) {
	data, err := base64.StdEncoding.DecodeString(bt.Token)
	if err != nil {
		return nil, fmt.Errorf("can't base64-decode bearer token: %w", err)
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
		return nil, fmt.Errorf("can't unmarshal bearer token: %w", err)
	}

	btoken := new(token.BearerToken)
	btoken.ToV2().SetBody(body)

	v2signature := new(refs.Signature)
	v2signature.SetScheme(refs.ECDSA_SHA512)
	if isWalletConnect {
		v2signature.SetScheme(2)
	}
	v2signature.SetSign(signature)
	v2signature.SetKey(ownerKey.Bytes())
	btoken.ToV2().SetSignature(v2signature)

	if isWalletConnect {
		if !walletconnect.Verify((*ecdsa.PublicKey)(ownerKey), data, signature) {
			return nil, fmt.Errorf("invalid signature")
		}
	} else if err = btoken.VerifySignature(); err != nil {
		return nil, fmt.Errorf("invalid signature")
	}

	return btoken, nil
}
