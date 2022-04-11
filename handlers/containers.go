package handlers

import (
	"context"
	"encoding/base64"
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
	"github.com/nspcc-dev/neofs-sdk-go/acl"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/policy"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
)

const (
	defaultPlacementPolicy = "REP 3"
	defaultBasicACL        = acl.PrivateBasicName
)

// PutContainers handler that creates container in NeoFS.
func (a *API) PutContainers(params operations.PutContainerParams, principal *models.Principal) middleware.Responder {
	bt := &BearerToken{
		Token:     string(*principal),
		Signature: params.XNeofsTokenSignature,
		Key:       params.XNeofsTokenSignatureKey,
	}
	stoken, err := prepareSessionToken(bt)
	if err != nil {
		return wrapError(err)
	}

	userAttributes := prepareUserAttributes(params.HTTPRequest.Header)

	cnrID, err := createContainer(params.HTTPRequest.Context(), a.pool, stoken, &params.Container, userAttributes)
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

func prepareUserAttributes(header http.Header) map[string]string {
	filtered := filterHeaders(header)
	delete(filtered, container.AttributeName)
	delete(filtered, container.AttributeTimestamp)
	return filtered
}

func getContainer(ctx context.Context, p *pool.Pool, containerID string) (*container.Container, error) {
	var cnrID cid.ID
	if err := cnrID.Parse(containerID); err != nil {
		return nil, fmt.Errorf("parse container id '%s': %w", containerID, err)
	}

	var prm pool.PrmContainerGet
	prm.SetContainerID(cnrID)

	return p.GetContainer(ctx, prm)
}

func createContainer(ctx context.Context, p *pool.Pool, stoken *session.Token, request *operations.PutContainerBody, userAttrs map[string]string) (*cid.ID, error) {
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

	container.SetNativeName(cnr, *request.ContainerName)

	var prm pool.PrmContainerPut
	prm.SetContainer(*cnr)

	cnrID, err := p.PutContainer(ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("could put object to neofs: %w", err)
	}

	return cnrID, nil
}

func prepareSessionToken(bt *BearerToken) (*session.Token, error) {
	stoken, err := GetSessionToken(bt.Token)
	if err != nil {
		return nil, fmt.Errorf("could not fetch session token: %w", err)
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
	stoken.ToV2().SetSignature(v2signature)

	if !stoken.VerifySignature() {
		err = fmt.Errorf("invalid signature")
	}

	return stoken, err
}

func GetSessionToken(auth string) (*session.Token, error) {
	data, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return nil, fmt.Errorf("can't base64-decode bearer token: %w", err)
	}

	body := new(sessionv2.TokenBody)
	if err = body.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("can't unmarshal bearer token: %w", err)
	}

	tkn := new(session.Token)
	tkn.ToV2().SetBody(body)

	return tkn, nil
}

func wrapError(err error) middleware.Responder {
	return operations.NewPutContainerBadRequest().WithPayload(models.Error(err.Error()))
}
