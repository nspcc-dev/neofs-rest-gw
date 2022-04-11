package handlers

import (
	"encoding/base64"
	"fmt"

	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"go.uber.org/zap"

	"github.com/go-openapi/runtime/middleware"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/token"
)

// PutObjects handler that uploads object to NeoFS.
func (a *API) PutObjects(params operations.PutObjectParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewPutObjectBadRequest()
	ctx := params.HTTPRequest.Context()

	bt := &BearerToken{
		Token:     string(*principal),
		Signature: params.XNeofsTokenSignature,
		Key:       params.XNeofsTokenSignatureKey,
	}

	btoken, err := prepareBearerToken(bt)
	if err != nil {
		return errorResponse.WithPayload(models.Error(err.Error()))
	}

	var cnrID cid.ID
	if err = cnrID.Parse(*params.Object.ContainerID); err != nil {
		a.log.Error("invalid container id", zap.Error(err))
		return errorResponse.WithPayload("invalid container id")
	}

	payload, err := base64.StdEncoding.DecodeString(params.Object.Payload)
	if err != nil {
		return errorResponse.WithPayload(models.Error(err.Error()))
	}

	prm := PrmAttributes{
		DefaultTimestamp: a.defaultTimestamp,
		DefaultFileName:  *params.Object.FileName,
	}
	attributes, err := GetObjectAttributes(ctx, params.HTTPRequest.Header, a.pool, prm)
	if err != nil {
		return errorResponse.WithPayload(models.Error(err.Error()))
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
		return errorResponse.WithPayload(NewError(err))
	}

	var resp operations.PutObjectOKBody
	resp.ContainerID = params.Object.ContainerID
	resp.ObjectID = NewString(objID.String())

	return operations.NewPutObjectOK().WithPayload(&resp)
}

// GetObjectInfo handler that get object info.
func (a *API) GetObjectInfo(params operations.GetObjectInfoParams, principal *models.Principal) middleware.Responder {
	errorResponse := operations.NewGetObjectInfoBadRequest()
	ctx := params.HTTPRequest.Context()

	var cnrID cid.ID
	if err := cnrID.Parse(params.ContainerID); err != nil {
		a.log.Error("invalid container id", zap.Error(err))
		return errorResponse.WithPayload("invalid container id")
	}
	var objID oid.ID
	if err := objID.Parse(params.ObjectID); err != nil {
		a.log.Error("invalid object id", zap.Error(err))
		return errorResponse.WithPayload("invalid object id")
	}

	bt := &BearerToken{
		Token:     string(*principal),
		Signature: params.XNeofsTokenSignature,
		Key:       params.XNeofsTokenSignatureKey,
	}

	btoken, err := prepareBearerToken(bt)
	if err != nil {
		return errorResponse.WithPayload(NewError(err))
	}

	var prm pool.PrmObjectHead
	addr := address.NewAddress()
	addr.SetContainerID(&cnrID)
	addr.SetObjectID(&objID)
	prm.SetAddress(*addr)
	prm.UseBearer(btoken)

	objInfo, err := a.pool.HeadObject(ctx, prm)
	if err != nil {
		return errorResponse.WithPayload(NewError(err))
	}

	var resp models.ObjectInfo
	resp.ContainerID = NewString(params.ContainerID)
	resp.ObjectID = NewString(params.ObjectID)
	resp.OwnerID = NewString(objInfo.OwnerID().String())
	resp.Attributes = make([]*models.Attribute, len(objInfo.Attributes()))

	for i, attr := range objInfo.Attributes() {
		resp.Attributes[i] = &models.Attribute{
			Key:   NewString(attr.Key()),
			Value: NewString(attr.Value()),
		}
	}

	return operations.NewGetObjectInfoOK().WithPayload(&resp)
}

func prepareBearerToken(bt *BearerToken) (*token.BearerToken, error) {
	btoken, err := getBearerToken(bt.Token)
	if err != nil {
		return nil, fmt.Errorf("could not fetch bearer token: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(bt.Signature)
	if err != nil {
		return nil, fmt.Errorf("couldn't decode bearer signature: %w", err)
	}

	ownerKey, err := keys.NewPublicKeyFromString(bt.Key)
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch bearer token owner key: %w", err)
	}

	v2signature := new(refs.Signature)
	v2signature.SetScheme(refs.ECDSA_SHA512)
	v2signature.SetSign(signature)
	v2signature.SetKey(ownerKey.Bytes())
	btoken.ToV2().SetSignature(v2signature)

	return btoken, btoken.VerifySignature()
}

func getBearerToken(auth string) (*token.BearerToken, error) {
	data, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return nil, fmt.Errorf("can't base64-decode bearer token: %w", err)
	}

	body := new(acl.BearerTokenBody)
	if err = body.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("can't unmarshal bearer token: %w", err)
	}

	tkn := new(token.BearerToken)
	tkn.ToV2().SetBody(body)

	return tkn, nil
}
