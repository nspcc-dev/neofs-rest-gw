package handlers

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/waiter"
	"go.uber.org/zap"
)

const (
	defaultPlacementPolicy = "REP 3"
	defaultBasicACL        = acl.NamePrivate
	attributeName          = "Name"
	attributeTimestamp     = "Timestamp"
)

// PutContainer handler that creates container in NeoFS.
func (a *RestAPI) PutContainer(ctx echo.Context, params apiserver.PutContainerParams) error {
	var body apiserver.ContainerPutInfo
	if err := ctx.Bind(&body); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err))
	}

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	st, err := formSessionTokenFromHeaders(principal, params.XBearerSignature, params.XBearerSignatureKey, session.VerbContainerPut)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token headers", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var isWalletConnect bool
	if params.WalletConnect != nil {
		isWalletConnect = *params.WalletConnect
	}

	stoken, err := prepareSessionToken(st, isWalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	cnrID, err := createContainer(ctx.Request().Context(), a.pool, stoken, body, params, a.signer)
	if err != nil {
		resp := a.logAndGetErrorResponse("create container", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	resp := apiserver.PutContainerOK{
		ContainerId: cnrID.EncodeToString(),
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// GetContainer handler that returns container info.
func (a *RestAPI) GetContainer(ctx echo.Context, containerID apiserver.ContainerId) error {
	cnrID, err := parseContainerID(containerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	cnrInfo, err := getContainerInfo(ctx.Request().Context(), a.pool, cnrID)
	if err != nil {
		resp := a.logAndGetErrorResponse("get container", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, cnrInfo)
}

// PutContainerEACL handler that update container eacl.
func (a *RestAPI) PutContainerEACL(ctx echo.Context, containerID apiserver.ContainerId, params apiserver.PutContainerEACLParams) error {
	var body apiserver.Eacl
	if err := ctx.Bind(&body); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err))
	}

	cnrID, err := parseContainerID(containerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if err = checkContainerExtendable(ctx.Request().Context(), a.pool, cnrID); err != nil {
		resp := a.logAndGetErrorResponse("check acl allowance", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	st, err := formSessionTokenFromHeaders(principal, params.XBearerSignature, params.XBearerSignatureKey, session.VerbContainerSetEACL)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token headers", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var isWalletConnect bool
	if params.WalletConnect != nil {
		isWalletConnect = *params.WalletConnect
	}

	stoken, err := prepareSessionToken(st, isWalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if err = setContainerEACL(ctx.Request().Context(), a.pool, cnrID, stoken, body, a.signer); err != nil {
		resp := a.logAndGetErrorResponse("failed set container eacl", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// GetContainerEACL handler that returns container eacl.
func (a *RestAPI) GetContainerEACL(ctx echo.Context, containerID apiserver.ContainerId) error {
	cnrID, err := parseContainerID(containerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	resp, err := getContainerEACL(ctx.Request().Context(), a.pool, cnrID)
	if err != nil {
		errResp := a.logAndGetErrorResponse("failed to get container eacl", err)
		return ctx.JSON(http.StatusBadRequest, errResp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// ListContainers handler that returns containers.
func (a *RestAPI) ListContainers(ctx echo.Context, params apiserver.ListContainersParams) error {
	var ownerID user.ID
	if err := ownerID.DecodeString(params.OwnerId); err != nil {
		resp := a.logAndGetErrorResponse("invalid owner id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var prm client.PrmContainerList

	ids, err := a.pool.ContainerList(ctx.Request().Context(), ownerID, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("list containers", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	offset, limit, err := getOffsetAndLimit(params.Offset, params.Limit)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid parameter", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if offset > len(ids)-1 {
		res := &apiserver.ContainerList{
			Containers: []apiserver.ContainerInfo{},
		}

		ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
		return ctx.JSON(http.StatusOK, res)
	}

	if offset+limit > len(ids) {
		limit = len(ids) - offset
	}

	res := &apiserver.ContainerList{
		Size:       limit,
		Containers: make([]apiserver.ContainerInfo, 0, limit),
	}

	for _, id := range ids[offset : offset+limit] {
		cnrInfo, err := getContainerInfo(ctx.Request().Context(), a.pool, id)
		if err != nil {
			resp := a.logAndGetErrorResponse("get container", err, zap.String("cid", id.String()))
			return ctx.JSON(http.StatusBadRequest, resp)
		}

		if cnrInfo != nil {
			res.Containers = append(res.Containers, *cnrInfo)
		} else {
			zap.L().Warn("getContainerInfo not error, but container info is empty", zap.Stringer("cid", id))
		}
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, res)
}

// DeleteContainer handler that returns container info.
func (a *RestAPI) DeleteContainer(ctx echo.Context, containerID apiserver.ContainerId, params apiserver.DeleteContainerParams) error {
	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	st, err := formSessionTokenFromHeaders(principal, params.XBearerSignature, params.XBearerSignatureKey, session.VerbContainerDelete)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token headers", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var isWalletConnect bool
	if params.WalletConnect != nil {
		isWalletConnect = *params.WalletConnect
	}

	stoken, err := prepareSessionToken(st, isWalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	cnrID, err := parseContainerID(containerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var prm client.PrmContainerDelete
	prm.WithinSession(stoken)

	wait := waiter.NewContainerDeleteWaiter(a.pool, waiter.DefaultPollInterval)
	if err = wait.ContainerDelete(ctx.Request().Context(), cnrID, a.signer, prm); err != nil {
		resp := a.logAndGetErrorResponse("delete container", err, zap.String("container", containerID))
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

func checkContainerExtendable(ctx context.Context, p *pool.Pool, cnrID cid.ID) error {
	cnr, err := getContainer(ctx, p, cnrID)
	if err != nil {
		return fmt.Errorf("get container: %w", err)
	}

	if !cnr.BasicACL().Extendable() {
		return errors.New("container acl isn't extendable")
	}

	return nil
}

func getContainer(ctx context.Context, p *pool.Pool, cnrID cid.ID) (container.Container, error) {
	return p.ContainerGet(ctx, cnrID, client.PrmContainerGet{})
}

func getContainerInfo(ctx context.Context, p *pool.Pool, cnrID cid.ID) (*apiserver.ContainerInfo, error) {
	cnr, err := getContainer(ctx, p, cnrID)
	if err != nil {
		return nil, err
	}

	var attrs []apiserver.Attribute
	cnr.IterateAttributes(func(key, val string) {
		attrs = append(attrs, apiserver.Attribute{
			Key:   key,
			Value: val,
		})
	})

	var sb strings.Builder
	if err = cnr.PlacementPolicy().WriteStringTo(&sb); err != nil {
		return nil, fmt.Errorf("writer policy to string: %w", err)
	}

	return &apiserver.ContainerInfo{
		ContainerId:     cnrID.String(),
		ContainerName:   cnr.Name(),
		OwnerId:         cnr.Owner().String(),
		BasicAcl:        cnr.BasicACL().EncodeToString(),
		CannedAcl:       util.NewString(friendlyBasicACL(cnr.BasicACL())),
		PlacementPolicy: sb.String(),
		Attributes:      attrs,
		Version:         cnr.Version().String(),
	}, nil
}

func friendlyBasicACL(basicACL acl.Basic) string {
	switch basicACL {
	case acl.Private:
		return acl.NamePrivate
	case acl.PrivateExtended:
		return acl.NamePrivateExtended
	case acl.PublicRO:
		return acl.NamePublicRO
	case acl.PublicROExtended:
		return acl.NamePublicROExtended
	case acl.PublicRW:
		return acl.NamePublicRW
	case acl.PublicRWExtended:
		return acl.NamePublicRWExtended
	case acl.PublicAppend:
		return acl.NamePublicAppend
	case acl.PublicAppendExtended:
		return acl.NamePublicAppendExtended
	default:
		return ""
	}
}

func parseContainerID(containerID string) (cid.ID, error) {
	var cnrID cid.ID
	if err := cnrID.DecodeString(containerID); err != nil {
		return cid.ID{}, fmt.Errorf("parse container id '%s': %w", containerID, err)
	}

	return cnrID, nil
}

func setContainerEACL(ctx context.Context, p *pool.Pool, cnrID cid.ID, stoken session.Container, eaclPrm apiserver.Eacl, signer user.Signer) error {
	table, err := util.ToNativeTable(eaclPrm.Records)
	if err != nil {
		return err
	}

	table.SetCID(cnrID)

	var prm client.PrmContainerSetEACL
	prm.WithinSession(stoken)

	wait := waiter.NewContainerSetEACLWaiter(p, waiter.DefaultPollInterval)
	return wait.ContainerSetEACL(ctx, *table, signer, prm)
}

func getContainerEACL(ctx context.Context, p *pool.Pool, cnrID cid.ID) (*apiserver.Eacl, error) {
	table, err := p.ContainerEACL(ctx, cnrID, client.PrmContainerEACL{})
	if err != nil {
		return nil, fmt.Errorf("get eacl: %w", err)
	}

	tableResp := &apiserver.Eacl{
		ContainerId: cnrID.EncodeToString(),
		Records:     make([]apiserver.Record, len(table.Records())),
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

func createContainer(ctx context.Context, p *pool.Pool, stoken session.Container, request apiserver.ContainerPutInfo, params apiserver.PutContainerParams, signer user.Signer) (cid.ID, error) {
	if request.PlacementPolicy == "" {
		request.PlacementPolicy = defaultPlacementPolicy
	}
	var policy netmap.PlacementPolicy
	err := policy.DecodeString(request.PlacementPolicy)
	if err != nil {
		return cid.ID{}, fmt.Errorf("couldn't parse placement policy: %w", err)
	}

	if request.BasicAcl == "" {
		request.BasicAcl = defaultBasicACL
	}

	basicACL, err := decodeBasicACL(request.BasicAcl)
	if err != nil {
		return cid.ID{}, fmt.Errorf("couldn't parse basic acl: %w", err)
	}

	var cnr container.Container
	cnr.Init()
	cnr.SetPlacementPolicy(policy)
	cnr.SetBasicACL(basicACL)
	cnr.SetOwner(stoken.Issuer())

	cnr.SetCreationTime(time.Now())

	if request.ContainerName != "" {
		cnr.SetName(request.ContainerName)
	}

	for _, attr := range request.Attributes {
		switch attr.Key {
		case attributeName, attributeTimestamp,
			containerDomainNameAttribute, containerDomainZoneAttribute:
		default:
			cnr.SetAttribute(attr.Key, attr.Value)
		}
	}

	if params.NameScopeGlobal != nil && *params.NameScopeGlobal {
		if err = checkNNSContainerName(request.ContainerName); err != nil {
			return cid.ID{}, fmt.Errorf("invalid container name: %w", err)
		}

		var domain container.Domain
		domain.SetName(request.ContainerName)
		cnr.WriteDomain(domain)
	}

	var prm client.PrmContainerPut
	prm.WithinSession(stoken)

	wait := waiter.NewContainerPutWaiter(p, waiter.DefaultPollInterval)

	cnrID, err := wait.ContainerPut(ctx, cnr, signer, prm)
	if err != nil {
		return cid.ID{}, fmt.Errorf("put container: %w", err)
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

func prepareSessionToken(st *SessionToken, isWalletConnect bool) (session.Container, error) {
	data, err := base64.StdEncoding.DecodeString(st.Token)
	if err != nil {
		return session.Container{}, fmt.Errorf("can't base64-decode session token: %w", err)
	}

	signature, err := hex.DecodeString(st.Signature)
	if err != nil {
		return session.Container{}, fmt.Errorf("couldn't decode signature: %w", err)
	}

	ownerKey, err := keys.NewPublicKeyFromString(st.Key)
	if err != nil {
		return session.Container{}, fmt.Errorf("couldn't fetch session token owner key: %w", err)
	}

	var stoken session.Container
	if err = stoken.UnmarshalSignedData(data); err != nil {
		return session.Container{}, fmt.Errorf("can't unmarshal session token: %w", err)
	}

	if !stoken.AssertVerb(st.Verb) {
		return session.Container{}, errors.New("wrong container session verb")
	}

	var scheme neofscrypto.Scheme
	var pubKey neofscrypto.PublicKey
	if isWalletConnect {
		scheme = neofscrypto.ECDSA_WALLETCONNECT
		pubKey = (*neofsecdsa.PublicKeyWalletConnect)(ownerKey)
	} else {
		scheme = neofscrypto.ECDSA_SHA512
		pubKey = (*neofsecdsa.PublicKey)(ownerKey)
	}

	err = stoken.Sign(user.NewSigner(neofscrypto.NewStaticSigner(scheme, signature, pubKey), stoken.Issuer()))
	if err != nil {
		// should never happen
		return session.Container{}, fmt.Errorf("set pre-calculated signature of the token: %w", err)
	}

	if !stoken.VerifySignature() {
		return session.Container{}, errors.New("invalid signature")
	}

	return stoken, err
}
