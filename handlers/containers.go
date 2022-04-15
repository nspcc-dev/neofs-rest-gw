package handlers

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	walletconnect "github.com/nspcc-dev/neofs-rest-gw/wallet-connect"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	sessionv2 "github.com/nspcc-dev/neofs-api-go/v2/session"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	"github.com/nspcc-dev/neofs-sdk-go/acl"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/policy"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"go.uber.org/zap"
)

const (
	defaultPlacementPolicy = "REP 3"
	defaultBasicACL        = acl.PrivateBasicName
)

// PutContainers handler that creates container in NeoFS.
func (a *API) PutContainers(params operations.PutContainerParams, principal *models.Principal) middleware.Responder {
	bt := &BearerToken{
		Token:     string(*principal),
		Signature: params.XBearerSignature,
		Key:       params.XBearerSignatureKey,
	}
	stoken, err := prepareSessionToken(bt, *params.WalletConnect)
	if err != nil {
		return wrapError(err)
	}

	userAttributes := prepareUserAttributes(params.HTTPRequest.Header)

	cnrID, err := createContainer(params.HTTPRequest.Context(), a.pool, stoken, &params, userAttributes)
	if err != nil {
		return wrapError(err)
	}

	var resp operations.PutContainerOKBody
	resp.ContainerID = NewString(cnrID.String())

	return operations.NewPutContainerOK().WithPayload(&resp)
}

// GetContainer handler that returns container info.
func (a *API) GetContainer(params operations.GetContainerParams) middleware.Responder {
	cnr, err := getContainer(params.HTTPRequest.Context(), a.pool, params.ContainerID)
	if err != nil {
		return wrapError(err)
	}

	attrs := make([]*models.Attribute, len(cnr.Attributes()))
	for i, attr := range cnr.Attributes() {
		attrs[i] = &models.Attribute{
			Key:   NewString(attr.Key()),
			Value: NewString(attr.Value()),
		}
	}

	resp := &models.ContainerInfo{
		ContainerID:     NewString(params.ContainerID),
		Version:         NewString(cnr.Version().String()),
		OwnerID:         NewString(cnr.OwnerID().String()),
		BasicACL:        NewString(acl.BasicACL(cnr.BasicACL()).String()),
		PlacementPolicy: NewString(strings.Join(policy.Encode(cnr.PlacementPolicy()), " ")),
		Attributes:      attrs,
	}

	return operations.NewGetContainerOK().WithPayload(resp)
}

// PutContainerEACL handler that update container eacl.
func (a *API) PutContainerEACL(params operations.PutContainerEACLParams, principal *models.Principal) middleware.Responder {
	cnrID, err := parseContainerID(params.ContainerID)
	if err != nil {
		a.log.Error("invalid container id", zap.Error(err))
		return operations.NewPutContainerEACLBadRequest().WithPayload("invalid container id")
	}

	bt := &BearerToken{
		Token:     string(*principal),
		Signature: params.XBearerSignature,
		Key:       params.XBearerSignatureKey,
	}
	stoken, err := prepareSessionToken(bt, *params.WalletConnect)
	if err != nil {
		return wrapError(err)
	}

	if err = setContainerEACL(params.HTTPRequest.Context(), a.pool, cnrID, stoken, params.Eacl); err != nil {
		a.log.Error("failed set container eacl", zap.Error(err))
		return operations.NewPutContainerEACLBadRequest().WithPayload(NewError(err))
	}

	return operations.NewPutContainerEACLOK()
}

// GetContainerEACL handler that returns container eacl.
func (a *API) GetContainerEACL(params operations.GetContainerEACLParams) middleware.Responder {
	cnrID, err := parseContainerID(params.ContainerID)
	if err != nil {
		a.log.Error("invalid container id", zap.Error(err))
		return operations.NewGetContainerEACLBadRequest().WithPayload("invalid container id")
	}

	resp, err := getContainerEACL(params.HTTPRequest.Context(), a.pool, cnrID)
	if err != nil {
		a.log.Error("failed to get container eacl", zap.Error(err))
		return operations.NewGetContainerEACLBadRequest().WithPayload("failed to get container eacl")
	}

	return operations.NewGetContainerEACLOK().WithPayload(resp)
}

// ListContainer handler that returns containers.
func (a *API) ListContainer(params operations.ListContainersParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()

	var ownerID owner.ID
	if err := ownerID.Parse(params.OwnerID); err != nil {
		a.log.Error("invalid owner id", zap.Error(err))
		return operations.NewListContainersBadRequest().WithPayload("invalid owner id")
	}

	var prm pool.PrmContainerList
	prm.SetOwnerID(ownerID)

	ids, err := a.pool.ListContainers(ctx, prm)
	if err != nil {
		a.log.Error("list containers", zap.Error(err))
		return operations.NewListContainersBadRequest().WithPayload("failed to get containers")
	}

	offset := int(*params.Offset)
	size := int(*params.Limit)

	if offset > len(ids)-1 {
		res := &models.ContainerList{
			Size:       NewInteger(0),
			Containers: []*models.ContainerBaseInfo{},
		}
		return operations.NewListContainersOK().WithPayload(res)
	}

	if offset+size > len(ids) {
		size = len(ids) - offset
	}

	res := &models.ContainerList{
		Size:       NewInteger(int64(size)),
		Containers: make([]*models.ContainerBaseInfo, 0, size),
	}

	for _, id := range ids[offset : offset+size] {
		baseInfo, err := getContainerBaseInfo(ctx, a.pool, id)
		if err != nil {
			a.log.Error("get container", zap.String("cid", id.String()), zap.Error(err))
			return operations.NewListContainersBadRequest().WithPayload("failed to get container")
		}
		res.Containers = append(res.Containers, baseInfo)
	}

	return operations.NewListContainersOK().WithPayload(res)
}

// DeleteContainer handler that returns container info.
func (a *API) DeleteContainer(params operations.DeleteContainerParams, principal *models.Principal) middleware.Responder {
	bt := &BearerToken{
		Token:     string(*principal),
		Signature: params.XBearerSignature,
		Key:       params.XBearerSignatureKey,
	}
	stoken, err := prepareSessionToken(bt, *params.WalletConnect)
	if err != nil {
		a.log.Error("failed parse session token", zap.Error(err))
		return operations.NewDeleteContainerBadRequest().WithPayload(NewError(err))
	}

	cnrID, err := parseContainerID(params.ContainerID)
	if err != nil {
		a.log.Error("failed get container id", zap.Error(err))
		return operations.NewDeleteContainerBadRequest().WithPayload(NewError(err))
	}

	var prm pool.PrmContainerDelete
	prm.SetContainerID(*cnrID)
	prm.SetSessionToken(*stoken)

	if err = a.pool.DeleteContainer(params.HTTPRequest.Context(), prm); err != nil {
		a.log.Error("failed delete container", zap.String("container", params.ContainerID), zap.Error(err))
		return operations.NewDeleteContainerBadRequest().WithPayload(NewError(err))
	}

	return operations.NewDeleteContainerNoContent()
}

func getContainerBaseInfo(ctx context.Context, p *pool.Pool, cnrID cid.ID) (*models.ContainerBaseInfo, error) {
	var prm pool.PrmContainerGet
	prm.SetContainerID(cnrID)

	cnr, err := p.GetContainer(ctx, prm)
	if err != nil {
		return nil, err
	}

	baseInfo := &models.ContainerBaseInfo{ContainerID: NewString(cnrID.String())}

	for _, attr := range cnr.Attributes() {
		if attr.Key() == container.AttributeName {
			baseInfo.Name = attr.Value()
		}
	}

	return baseInfo, nil
}

func prepareUserAttributes(header http.Header) map[string]string {
	filtered := filterHeaders(header)
	delete(filtered, container.AttributeName)
	delete(filtered, container.AttributeTimestamp)
	return filtered
}

func getContainer(ctx context.Context, p *pool.Pool, containerID string) (*container.Container, error) {
	cnrID, err := parseContainerID(containerID)
	if err != nil {
		return nil, err
	}

	var prm pool.PrmContainerGet
	prm.SetContainerID(*cnrID)

	return p.GetContainer(ctx, prm)
}

func parseContainerID(containerID string) (*cid.ID, error) {
	var cnrID cid.ID
	if err := cnrID.Parse(containerID); err != nil {
		return nil, fmt.Errorf("parse container id '%s': %w", containerID, err)
	}

	return &cnrID, nil
}

func setContainerEACL(ctx context.Context, p *pool.Pool, cnrID *cid.ID, stoken *session.Token, eaclPrm *models.Eacl) error {
	table, err := ToNativeTable(eaclPrm.Records)
	if err != nil {
		return err
	}

	table.SetCID(cnrID)
	table.SetSessionToken(stoken)

	var prm pool.PrmContainerSetEACL
	prm.SetTable(*table)

	return p.SetEACL(ctx, prm)
}

func getContainerEACL(ctx context.Context, p *pool.Pool, cnrID *cid.ID) (*models.Eacl, error) {
	var prm pool.PrmContainerEACL
	prm.SetContainerID(*cnrID)

	table, err := p.GetEACL(ctx, prm)
	if err != nil {
		return nil, err
	}

	tableResp := &models.Eacl{
		ContainerID: cnrID.String(),
		Records:     make([]*models.Record, len(table.Records())),
	}

	for i, rec := range table.Records() {
		record, err := FromNativeRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("couldn't transform record from native: %w", err)
		}
		tableResp.Records[i] = record
	}

	return tableResp, nil
}

func createContainer(ctx context.Context, p *pool.Pool, stoken *session.Token, params *operations.PutContainerParams, userAttrs map[string]string) (*cid.ID, error) {
	request := params.Container

	if request.PlacementPolicy == "" {
		request.PlacementPolicy = defaultPlacementPolicy
	}
	pp, err := policy.Parse(request.PlacementPolicy)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse placement policy: %w", err)
	}

	if request.BasicACL == "" {
		request.BasicACL = defaultBasicACL
	}
	basicACL, err := acl.ParseBasicACL(request.BasicACL)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse basic acl: %w", err)
	}

	cnrOptions := []container.Option{
		container.WithPolicy(pp),
		container.WithCustomBasicACL(basicACL),
		container.WithAttribute(container.AttributeName, *request.ContainerName),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10)),
	}

	for key, val := range userAttrs {
		cnrOptions = append(cnrOptions, container.WithAttribute(key, val))
	}

	cnr := container.New(cnrOptions...)
	cnr.SetOwnerID(stoken.OwnerID())
	cnr.SetSessionToken(stoken)

	if !*params.SkipNativeName { // we don't check for nil because there is default false value
		container.SetNativeName(cnr, *request.ContainerName)
	}

	var prm pool.PrmContainerPut
	prm.SetContainer(*cnr)

	cnrID, err := p.PutContainer(ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("could put object to neofs: %w", err)
	}

	return cnrID, nil
}

func prepareSessionToken(bt *BearerToken, isWalletConnect bool) (*session.Token, error) {
	data, err := base64.StdEncoding.DecodeString(bt.Token)
	if err != nil {
		return nil, fmt.Errorf("can't base64-decode bearer token: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(bt.Signature)
	if err != nil {
		return nil, fmt.Errorf("couldn't decode bearer signature: %w", err)
	}

	ownerKey, err := keys.NewPublicKeyFromString(bt.Key)
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch bearer token owner key: %w", err)
	}

	body := new(sessionv2.TokenBody)
	if err = body.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("can't unmarshal bearer token: %w", err)
	}

	stoken := new(session.Token)
	stoken.ToV2().SetBody(body)

	v2signature := new(refs.Signature)
	v2signature.SetScheme(refs.ECDSA_SHA512)
	if isWalletConnect {
		v2signature.SetScheme(2)
	}
	v2signature.SetSign(signature)
	v2signature.SetKey(ownerKey.Bytes())
	stoken.ToV2().SetSignature(v2signature)

	if isWalletConnect {
		if !walletconnect.Verify((*ecdsa.PublicKey)(ownerKey), data, signature) {
			return nil, fmt.Errorf("invalid signature")
		}
	} else if !stoken.VerifySignature() {
		return nil, fmt.Errorf("invalid signature")
	}

	return stoken, err
}

func wrapError(err error) middleware.Responder {
	return operations.NewPutContainerBadRequest().WithPayload(models.Error(err.Error()))
}
