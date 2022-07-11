package handlers

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	walletconnect "github.com/nspcc-dev/neofs-rest-gw/internal/wallet-connect"
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
	st := &SessionToken{
		BearerToken: BearerToken{
			Token:     string(*principal),
			Signature: params.XBearerSignature,
			Key:       params.XBearerSignatureKey,
		},
		Verb: sessionv2.ContainerVerbPut,
	}
	stoken, err := prepareSessionToken(st, *params.WalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token", err)
		return operations.NewPutContainerBadRequest().WithPayload(resp)
	}

	userAttributes := prepareUserAttributes(params.HTTPRequest.Header)

	cnrID, err := createContainer(params.HTTPRequest.Context(), a.pool, stoken, &params, userAttributes)
	if err != nil {
		resp := a.logAndGetErrorResponse("create container", err)
		return operations.NewPutContainerBadRequest().WithPayload(resp)
	}

	var resp operations.PutContainerOKBody
	resp.ContainerID = util.NewString(cnrID.String())

	return operations.NewPutContainerOK().WithPayload(&resp)
}

// GetContainer handler that returns container info.
func (a *API) GetContainer(params operations.GetContainerParams) middleware.Responder {
	cnrID, err := parseContainerID(params.ContainerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return operations.NewGetContainerBadRequest().WithPayload(resp)
	}

	cnrInfo, err := getContainerInfo(params.HTTPRequest.Context(), a.pool, *cnrID)
	if err != nil {
		resp := a.logAndGetErrorResponse("get container", err)
		return operations.NewGetContainerBadRequest().WithPayload(resp)
	}

	return operations.NewGetContainerOK().WithPayload(cnrInfo)
}

// PutContainerEACL handler that update container eacl.
func (a *API) PutContainerEACL(params operations.PutContainerEACLParams, principal *models.Principal) middleware.Responder {
	cnrID, err := parseContainerID(params.ContainerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return operations.NewPutContainerEACLBadRequest().WithPayload(resp)
	}

	st := &SessionToken{
		BearerToken: BearerToken{
			Token:     string(*principal),
			Signature: params.XBearerSignature,
			Key:       params.XBearerSignatureKey,
		},
		Verb: sessionv2.ContainerVerbSetEACL,
	}
	stoken, err := prepareSessionToken(st, *params.WalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token", err)
		return operations.NewPutContainerEACLBadRequest().WithPayload(resp)
	}

	if err = setContainerEACL(params.HTTPRequest.Context(), a.pool, cnrID, stoken, params.Eacl); err != nil {
		resp := a.logAndGetErrorResponse("failed set container eacl", err)
		return operations.NewPutContainerEACLBadRequest().WithPayload(resp)
	}

	return operations.NewPutContainerEACLOK().WithPayload(util.NewSuccessResponse())
}

// GetContainerEACL handler that returns container eacl.
func (a *API) GetContainerEACL(params operations.GetContainerEACLParams) middleware.Responder {
	cnrID, err := parseContainerID(params.ContainerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return operations.NewGetContainerEACLBadRequest().WithPayload(resp)
	}

	resp, err := getContainerEACL(params.HTTPRequest.Context(), a.pool, cnrID)
	if err != nil {
		errResp := a.logAndGetErrorResponse("failed to get container eacl", err)
		return operations.NewGetContainerEACLBadRequest().WithPayload(errResp)
	}

	return operations.NewGetContainerEACLOK().WithPayload(resp)
}

// ListContainer handler that returns containers.
func (a *API) ListContainer(params operations.ListContainersParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()

	var ownerID owner.ID
	if err := ownerID.Parse(params.OwnerID); err != nil {
		resp := a.logAndGetErrorResponse("invalid owner id", err)
		return operations.NewListContainersBadRequest().WithPayload(resp)
	}

	var prm pool.PrmContainerList
	prm.SetOwnerID(ownerID)

	ids, err := a.pool.ListContainers(ctx, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("list containers", err)
		return operations.NewListContainersBadRequest().WithPayload(resp)
	}

	offset := int(*params.Offset)
	size := int(*params.Limit)

	if offset > len(ids)-1 {
		res := &models.ContainerList{
			Size:       util.NewInteger(0),
			Containers: []*models.ContainerInfo{},
		}
		return operations.NewListContainersOK().WithPayload(res)
	}

	if offset+size > len(ids) {
		size = len(ids) - offset
	}

	res := &models.ContainerList{
		Size:       util.NewInteger(int64(size)),
		Containers: make([]*models.ContainerInfo, 0, size),
	}

	for _, id := range ids[offset : offset+size] {
		cnrInfo, err := getContainerInfo(ctx, a.pool, id)
		if err != nil {
			resp := a.logAndGetErrorResponse("get container", err, zap.String("cid", id.String()))
			return operations.NewListContainersBadRequest().WithPayload(resp)
		}
		res.Containers = append(res.Containers, cnrInfo)
	}

	return operations.NewListContainersOK().WithPayload(res)
}

// DeleteContainer handler that returns container info.
func (a *API) DeleteContainer(params operations.DeleteContainerParams, principal *models.Principal) middleware.Responder {
	st := &SessionToken{
		BearerToken: BearerToken{
			Token:     string(*principal),
			Signature: params.XBearerSignature,
			Key:       params.XBearerSignatureKey,
		},
		Verb: sessionv2.ContainerVerbDelete,
	}
	stoken, err := prepareSessionToken(st, *params.WalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token", err)
		return operations.NewDeleteContainerBadRequest().WithPayload(resp)
	}

	cnrID, err := parseContainerID(params.ContainerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return operations.NewDeleteContainerBadRequest().WithPayload(resp)
	}

	var prm pool.PrmContainerDelete
	prm.SetContainerID(*cnrID)
	prm.SetSessionToken(*stoken)

	if err = a.pool.DeleteContainer(params.HTTPRequest.Context(), prm); err != nil {
		resp := a.logAndGetErrorResponse("delete container", err, zap.String("container", params.ContainerID))
		return operations.NewDeleteContainerBadRequest().WithPayload(resp)
	}

	return operations.NewDeleteContainerOK().WithPayload(util.NewSuccessResponse())
}

func getContainerInfo(ctx context.Context, p *pool.Pool, cnrID cid.ID) (*models.ContainerInfo, error) {
	var prm pool.PrmContainerGet
	prm.SetContainerID(cnrID)

	cnr, err := p.GetContainer(ctx, prm)
	if err != nil {
		return nil, err
	}

	attrs := make([]*models.Attribute, len(cnr.Attributes()))
	for i, attr := range cnr.Attributes() {
		attrs[i] = &models.Attribute{
			Key:   util.NewString(attr.Key()),
			Value: util.NewString(attr.Value()),
		}
	}

	return &models.ContainerInfo{
		ContainerID:     util.NewString(cnrID.String()),
		Version:         util.NewString(cnr.Version().String()),
		OwnerID:         util.NewString(cnr.OwnerID().String()),
		BasicACL:        util.NewString(acl.BasicACL(cnr.BasicACL()).String()),
		PlacementPolicy: util.NewString(strings.Join(policy.Encode(cnr.PlacementPolicy()), " ")),
		Attributes:      attrs,
	}, nil
}

func prepareUserAttributes(header http.Header) map[string]string {
	filtered := filterHeaders(header)
	delete(filtered, container.AttributeName)
	delete(filtered, container.AttributeTimestamp)
	return filtered
}

func parseContainerID(containerID string) (*cid.ID, error) {
	var cnrID cid.ID
	if err := cnrID.Parse(containerID); err != nil {
		return nil, fmt.Errorf("parse container id '%s': %w", containerID, err)
	}

	return &cnrID, nil
}

func setContainerEACL(ctx context.Context, p *pool.Pool, cnrID *cid.ID, stoken *session.Token, eaclPrm *models.Eacl) error {
	table, err := util.ToNativeTable(eaclPrm.Records)
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
		return nil, fmt.Errorf("get eacl: %w", err)
	}

	tableResp := &models.Eacl{
		ContainerID: cnrID.String(),
		Records:     make([]*models.Record, len(table.Records())),
	}

	for i, rec := range table.Records() {
		record, err := util.FromNativeRecord(rec)
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
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10)),
	}

	if request.ContainerName != "" {
		container.WithAttribute(container.AttributeName, request.ContainerName)
	}

	for key, val := range userAttrs {
		cnrOptions = append(cnrOptions, container.WithAttribute(key, val))
	}

	cnr := container.New(cnrOptions...)
	cnr.SetOwnerID(stoken.OwnerID())
	cnr.SetSessionToken(stoken)

	if *params.NameScopeGlobal { // we don't check for nil because there is default false value
		if err = checkNNSContainerName(request.ContainerName); err != nil {
			return nil, fmt.Errorf("invalid container name: %w", err)
		}
		container.SetNativeName(cnr, request.ContainerName)
	}

	var prm pool.PrmContainerPut
	prm.SetContainer(*cnr)

	cnrID, err := p.PutContainer(ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("put container: %w", err)
	}

	return cnrID, nil
}

func checkNNSContainerName(name string) error {
	length := len(name)
	if length < 3 || 255 < length {
		return fmt.Errorf("invalid length: %d", length)
	}
	fragments := strings.Split(name, ".")

	for _, fragment := range fragments {
		fLength := len(fragment)
		if fLength < 1 || 63 < fLength {
			return fmt.Errorf("invalid fragment length: %d", fLength)
		}

		if !isAlNum(fragment[0]) || !isAlNum(fragment[fLength-1]) {
			return fmt.Errorf("invalid fragment: '%s'", fragment)
		}

		for i := 1; i < fLength-1; i++ {
			if fragment[i] != '-' && !isAlNum(fragment[i]) {
				return fmt.Errorf("invalid fragment: '%s'", fragment)
			}
		}
	}

	return nil
}

func isAlNum(c uint8) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func prepareSessionToken(st *SessionToken, isWalletConnect bool) (*session.Token, error) {
	data, err := base64.StdEncoding.DecodeString(st.Token)
	if err != nil {
		return nil, fmt.Errorf("can't base64-decode session token: %w", err)
	}

	signature, err := hex.DecodeString(st.Signature)
	if err != nil {
		return nil, fmt.Errorf("couldn't decode signature: %w", err)
	}

	ownerKey, err := keys.NewPublicKeyFromString(st.Key)
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch session token owner key: %w", err)
	}

	body := new(sessionv2.TokenBody)
	if err = body.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("can't unmarshal session token: %w", err)
	}

	if sessionContext, ok := body.GetContext().(*sessionv2.ContainerSessionContext); !ok {
		return nil, errors.New("expected container session context but got something different")
	} else if sessionContext.Verb() != st.Verb {
		return nil, fmt.Errorf("invalid container session verb '%s', expected: '%s'", sessionContext.Verb().String(), st.Verb.String())
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
		if !walletconnect.Verify((*ecdsa.PublicKey)(ownerKey), []byte(st.Token), signature) {
			return nil, fmt.Errorf("invalid signature")
		}
	} else if !stoken.VerifySignature() {
		return nil, fmt.Errorf("invalid signature")
	}

	return stoken, err
}
