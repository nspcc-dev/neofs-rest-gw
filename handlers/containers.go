package handlers

import (
	"context"
	"crypto/elliptic"
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
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
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

var (
	errNeoFSRequestFailed = errors.New("neofs request failed")
)

// PutContainer handler that creates container in NeoFS.
func (a *RestAPI) PutContainer(ctx echo.Context, params apiserver.PutContainerParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.PutContainerDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "PutContainer"))

	var body apiserver.ContainerPostInfo
	if err := ctx.Bind(&body); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	st, err := formSessionTokenFromHeaders(principal, params.XBearerSignature, params.XBearerSignatureKey, session.VerbContainerPut)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token headers", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var isWalletConnect bool
	if params.WalletConnect != nil {
		isWalletConnect = *params.WalletConnect
		log = log.With(zap.Bool("walletConnect", isWalletConnect))
	}

	stoken, err := prepareSessionToken(st, isWalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	wCtx, cancel := context.WithTimeout(ctx.Request().Context(), a.waiterOperationTimeout)
	defer cancel()

	// PutContainer will be removed in the next release. We may update old method to use new structures.
	cnrID, err := createContainer(wCtx, a.containerWaiter, stoken, body, apiserver.PostContainerParams(params), a.signer, a.networkInfoGetter)
	if err != nil {
		resp := a.logAndGetErrorResponse("create container", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	resp := apiserver.PostContainerOK{
		ContainerId: cnrID.EncodeToString(),
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// PostContainer handler that creates container in NeoFS.
func (a *RestAPI) PostContainer(ctx echo.Context, params apiserver.PostContainerParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.PostContainerDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "PostContainer"))

	var body apiserver.ContainerPostInfo
	if err := ctx.Bind(&body); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	st, err := formSessionTokenFromHeaders(principal, params.XBearerSignature, params.XBearerSignatureKey, session.VerbContainerPut)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token headers", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var isWalletConnect bool
	if params.WalletConnect != nil {
		isWalletConnect = *params.WalletConnect
	}

	stoken, err := prepareSessionToken(st, isWalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	wCtx, cancel := context.WithTimeout(ctx.Request().Context(), a.waiterOperationTimeout)
	defer cancel()

	cnrID, err := createContainer(wCtx, a.containerWaiter, stoken, body, params, a.signer, a.networkInfoGetter)
	if err != nil {
		resp := a.logAndGetErrorResponse("create container", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	resp := apiserver.PostContainerOK{
		ContainerId: cnrID.EncodeToString(),
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	ctx.Response().Header().Set(locationHeader, LocationHeader(cnrID))
	return ctx.JSON(http.StatusCreated, resp)
}

// GetContainer handler that returns container info.
func (a *RestAPI) GetContainer(ctx echo.Context, containerID apiserver.ContainerId) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.GetContainerDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "GetContainer"), zap.String("containerID", containerID))

	cnrID, err := parseContainerID(containerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	cnrInfo, err := getContainerInfo(ctx.Request().Context(), a.pool, cnrID)
	if err != nil {
		resp := a.logAndGetErrorResponse("get container", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, cnrInfo)
}

// PutContainerEACL handler that update container eacl.
func (a *RestAPI) PutContainerEACL(ctx echo.Context, containerID apiserver.ContainerId, params apiserver.PutContainerEACLParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.PutContainerEACLDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "PutContainerEACL"), zap.String("containerID", containerID))

	var body apiserver.Eacl
	if err := ctx.Bind(&body); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	cnrID, err := parseContainerID(containerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	cnr, err := getContainer(ctx.Request().Context(), a.pool, cnrID)
	if err != nil {
		resp := a.logAndGetErrorResponse("get container", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	if !cnr.BasicACL().Extendable() {
		resp := a.logAndGetErrorResponse("extended ACL is disabled for this container", err, log)
		return ctx.JSON(http.StatusConflict, resp)
	}

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	st, err := formSessionTokenFromHeaders(principal, params.XBearerSignature, params.XBearerSignatureKey, session.VerbContainerSetEACL)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token headers", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var isWalletConnect bool
	if params.WalletConnect != nil {
		isWalletConnect = *params.WalletConnect
	}

	stoken, err := prepareSessionToken(st, isWalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	wCtx, cancel := context.WithTimeout(ctx.Request().Context(), a.waiterOperationTimeout)
	defer cancel()

	table, err := util.ToNativeTable(body.Records)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed to convert EACL", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	table.SetCID(cnrID)

	var prm client.PrmContainerSetEACL
	prm.WithinSession(stoken)

	err = a.containerWaiter.ContainerSetEACL(wCtx, *table, a.signer, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("failed set container eacl", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
}

// GetContainerEACL handler that returns container eacl.
func (a *RestAPI) GetContainerEACL(ctx echo.Context, containerID apiserver.ContainerId) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.GetContainerEACLDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "GetContainerEACL"), zap.String("containerID", containerID))

	cnrID, err := parseContainerID(containerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	resp, err := getContainerEACL(ctx.Request().Context(), a.pool, cnrID)
	if err != nil {
		errResp := a.logAndGetErrorResponse("failed to get container eacl", err, log)
		if errors.Is(err, errNeoFSRequestFailed) {
			return ctx.JSON(getResponseCodeFromStatus(err), errResp)
		}

		return ctx.JSON(http.StatusInternalServerError, errResp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// ListContainers handler that returns containers.
func (a *RestAPI) ListContainers(ctx echo.Context, params apiserver.ListContainersParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.ListContainersDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "ListContainers"), zap.String("ownerID", params.OwnerId))

	var ownerID user.ID
	if err := ownerID.DecodeString(params.OwnerId); err != nil {
		resp := a.logAndGetErrorResponse("invalid owner id", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var prm client.PrmContainerList

	ids, err := a.pool.ContainerList(ctx.Request().Context(), ownerID, prm)
	if err != nil {
		resp := a.logAndGetErrorResponse("list containers", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	offset, limit, err := getOffsetAndLimit(params.Offset, params.Limit)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid offset/limit", err, log)
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
			resp := a.logAndGetErrorResponse("get container", err, log.With(zap.String("cid", id.String())))
			return ctx.JSON(getResponseCodeFromStatus(err), resp)
		}

		if cnrInfo != nil {
			res.Containers = append(res.Containers, *cnrInfo)
		} else {
			log.Warn("getContainerInfo not error, but container info is empty", zap.Stringer("cid", id))
		}
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, res)
}

// DeleteContainer handler that returns container info.
func (a *RestAPI) DeleteContainer(ctx echo.Context, containerID apiserver.ContainerId, params apiserver.DeleteContainerParams) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.DeleteContainerDuration)()
	}

	log := a.log.With(zap.String(handlerFieldName, "DeleteContainer"), zap.String("containerID", containerID))

	principal, err := getPrincipal(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, util.NewErrorResponse(err))
	}

	st, err := formSessionTokenFromHeaders(principal, params.XBearerSignature, params.XBearerSignatureKey, session.VerbContainerDelete)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token headers", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var isWalletConnect bool
	if params.WalletConnect != nil {
		isWalletConnect = *params.WalletConnect
	}

	stoken, err := prepareSessionToken(st, isWalletConnect)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid session token", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	cnrID, err := parseContainerID(containerID)
	if err != nil {
		resp := a.logAndGetErrorResponse("invalid container id", err, log)
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	var prm client.PrmContainerDelete
	prm.WithinSession(stoken)

	wCtx, cancel := context.WithTimeout(ctx.Request().Context(), a.waiterOperationTimeout)
	defer cancel()

	if err = a.containerWaiter.ContainerDelete(wCtx, cnrID, a.signer, prm); err != nil {
		resp := a.logAndGetErrorResponse("delete container", err, log)
		return ctx.JSON(getResponseCodeFromStatus(err), resp)
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, util.NewSuccessResponse())
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
	for key, val := range cnr.Attributes() {
		attrs = append(attrs, apiserver.Attribute{
			Key:   key,
			Value: val,
		})
	}

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

func getContainerEACL(ctx context.Context, p *pool.Pool, cnrID cid.ID) (*apiserver.Eacl, error) {
	table, err := p.ContainerEACL(ctx, cnrID, client.PrmContainerEACL{})
	if err != nil {
		return nil, fmt.Errorf("get eacl: %w", errors.Join(errNeoFSRequestFailed, err))
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

func createContainer(ctx context.Context, p *waiter.Waiter, stoken session.Container, request apiserver.ContainerPostInfo, params apiserver.PostContainerParams, signer user.Signer, networkInfoGetter networkInfoGetter) (cid.ID, error) {
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

	ni, err := networkInfoGetter.NetworkInfo(ctx)
	if err != nil {
		return cid.ID{}, fmt.Errorf("couldn't get network info: %w", err)
	}

	if ni.HomomorphicHashingDisabled() {
		cnr.DisableHomomorphicHashing()
	}

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

	cnrID, err := p.ContainerPut(ctx, cnr, signer, prm)
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

	for fragment := range strings.SplitSeq(name, ".") {
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

	pub, err := hex.DecodeString(st.Key)
	if err != nil {
		return session.Container{}, fmt.Errorf("couldn't fetch session token owner key: %w", err)
	}
	if _, err = keys.NewPublicKeyFromBytes(pub, elliptic.P256()); err != nil {
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
	if isWalletConnect {
		scheme = neofscrypto.ECDSA_WALLETCONNECT
	} else {
		scheme = neofscrypto.ECDSA_SHA512
	}

	stoken.AttachSignature(neofscrypto.NewSignatureFromRawKey(scheme, pub, signature))

	if !stoken.VerifySignature() {
		return session.Container{}, errors.New("invalid signature")
	}

	return stoken, err
}
