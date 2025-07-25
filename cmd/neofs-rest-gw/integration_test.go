package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	dockerContainer "github.com/docker/docker/api/types/container"
	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/object/slicer"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/waiter"
	middleware "github.com/oapi-codegen/echo-middleware"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	devenvPrivateKey  = "1dd37fba80fec4e6a6f13fd708d8dcb3b29def768017052f6c930fa1c5d90bbb"
	testListenAddress = "localhost:8082"
	testHost          = "http://" + testListenAddress
	testContainerNode = "localhost:8080"
	testLocalNode     = "s01.neofs.devenv:8080"
	containerName     = "test-container"

	walletConnectQuery = "walletConnect"
	fullBearerQuery    = "fullBearer"
	// XBearerSignature header contains base64 encoded signature of the token body.
	XBearerSignature = "X-Bearer-Signature"
	// XBearerSignatureKey header contains hex encoded public key that corresponds the signature of the token body.
	XBearerSignatureKey = "X-Bearer-Signature-Key"
	// XBearerOwnerID header contains owner id (wallet address) that corresponds the signature of the token body.
	XBearerOwnerID = "X-Bearer-Owner-Id"
	// XBearerForAllUsers header specifies if we want all users can use token or only specific gate.
	XBearerForAllUsers = "X-Bearer-For-All-Users"
	xNonce             = "nonce"

	// tests configuration.
	useWalletConnect    = true
	useLocalEnvironment = false
)

type dockerImage struct {
	image   string
	version string
}

func TestIntegration(t *testing.T) {
	ctx := context.Background()
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	if useLocalEnvironment {
		runLocalTests(ctx, t, key)
	} else {
		runTestInContainer(ctx, t, key)
	}
}

func runLocalTests(ctx context.Context, t *testing.T, key *keys.PrivateKey) {
	t.Run("local", func(t *testing.T) { runTests(ctx, t, key, testLocalNode) })
}

func runTestInContainer(rootCtx context.Context, t *testing.T, key *keys.PrivateKey) {
	versions := []dockerImage{
		{image: "nspccdev/neofs-aio", version: "latest"},
		{image: "nspccdev/neofs-aio", version: "0.45.0"},
	}

	for _, version := range versions {
		image := fmt.Sprintf("%s:%s", version.image, version.version)

		t.Run(image, func(t *testing.T) {
			ctx, cancel := context.WithCancel(rootCtx)
			aioContainer := createDockerContainer(ctx, t, image, version.version)

			runTests(ctx, t, key, testContainerNode)

			err := aioContainer.Terminate(ctx)
			require.NoError(t, err)
			cancel()
			<-ctx.Done()
		})
	}
}

func runTests(ctx context.Context, t *testing.T, key *keys.PrivateKey, node string) {
	cancel := runServer(ctx, t, node)
	defer cancel()

	signer := user.NewAutoIDSignerRFC6979(key.PrivateKey)
	owner := signer.UserID()

	clientPool := getPool(ctx, t, key, node)
	cnrID := createContainer(ctx, t, clientPool, owner, containerName, signer)
	restrictByEACL(ctx, t, clientPool, cnrID, signer)

	t.Run("rest auth several tokens", func(t *testing.T) { authTokens(ctx, t) })
	t.Run("rest form full binary bearer", func(t *testing.T) { formFullBinaryBearer(ctx, t) })

	t.Run("rest put container invalid", func(t *testing.T) { restContainerPutInvalid(ctx, t) })
	t.Run("rest post container invalid", func(t *testing.T) { restContainerPostInvalid(ctx, t) })
	t.Run("rest put container", func(t *testing.T) { restContainerPut(ctx, t, clientPool) })
	t.Run("rest post container", func(t *testing.T) { restContainerPost(ctx, t, clientPool) })
	t.Run("rest get container", func(t *testing.T) { restContainerGet(ctx, t, owner, cnrID) })
	t.Run("rest delete container", func(t *testing.T) { restContainerDelete(ctx, t, clientPool, owner, signer) })
	t.Run("rest put container eacl", func(t *testing.T) { restContainerEACLPut(ctx, t, clientPool, owner, signer) })
	t.Run("rest get container eacl", func(t *testing.T) { restContainerEACLGet(ctx, t, clientPool, cnrID) })
	t.Run("rest list containers", func(t *testing.T) { restContainerList(ctx, t, clientPool, owner, cnrID) })

	t.Run("rest put object", func(t *testing.T) { restObjectPut(ctx, t, clientPool, cnrID, signer) })
	t.Run("rest get object", func(t *testing.T) { restObjectGet(ctx, t, clientPool, &owner, cnrID, signer) })
	t.Run("rest get object unauthenticated", func(t *testing.T) { restObjectGetUnauthenticated(ctx, t, clientPool, &owner, cnrID, signer) })
	t.Run("rest get object full bearer", func(t *testing.T) { restObjectGetFullBearer(ctx, t, clientPool, &owner, cnrID, signer) })
	t.Run("rest get object with bearer in cookie", func(t *testing.T) { restObjectGetBearerCookie(ctx, t, clientPool, &owner, cnrID, signer) })
	t.Run("rest delete object", func(t *testing.T) { restObjectDelete(ctx, t, clientPool, &owner, cnrID, signer) })
	t.Run("rest search objects", func(t *testing.T) { restObjectsSearch(ctx, t, clientPool, &owner, cnrID, signer) })
	t.Run("rest search objects v2", func(t *testing.T) { restObjectsSearchV2(ctx, t, clientPool, &owner, cnrID, signer) })
	t.Run("rest search objects v2 cursor and limit", func(t *testing.T) { restObjectsSearchV2CursorAndLimit(ctx, t, clientPool, &owner, signer) })
	t.Run("rest search objects v2 filters", func(t *testing.T) { restObjectsSearchV2Filters(ctx, t, clientPool, &owner, signer) })
	t.Run("rest upload object", func(t *testing.T) { restObjectUpload(ctx, t, clientPool, cnrID, signer) })
	t.Run("rest upload object with bearer in cookie", func(t *testing.T) { restObjectUploadCookie(ctx, t, clientPool, cnrID, signer) })
	t.Run("rest head object", func(t *testing.T) { restObjectHead(ctx, t, clientPool, &owner, cnrID, signer) })
	t.Run("rest head by attribute", func(t *testing.T) { restObjectHeadByAttribute(ctx, t, clientPool, &owner, cnrID, signer) })
	t.Run("rest get by attribute", func(t *testing.T) { restObjectGetByAttribute(ctx, t, clientPool, &owner, cnrID, signer) })

	t.Run("rest check mix tokens up", func(t *testing.T) { mixTokens(ctx, t, cnrID) })

	t.Run("rest balance", func(t *testing.T) { restBalance(ctx, t) })

	t.Run("rest new upload object", func(t *testing.T) { restNewObjectUpload(ctx, t, clientPool, cnrID, signer) })
	t.Run("rest new upload object with bearer in cookie", func(t *testing.T) { restNewObjectUploadCookie(ctx, t, clientPool, cnrID, signer) })
	t.Run("rest new upload object with wallet connect", func(t *testing.T) { restNewObjectUploadWC(ctx, t, clientPool, cnrID, signer) })
	t.Run("rest new head object", func(t *testing.T) { restNewObjectHead(ctx, t, clientPool, &owner, cnrID, signer, false) })
	t.Run("rest new head object with wallet connect", func(t *testing.T) { restNewObjectHead(ctx, t, clientPool, &owner, cnrID, signer, true) })
	t.Run("rest new head by attribute", func(t *testing.T) { restNewObjectHeadByAttribute(ctx, t, clientPool, &owner, cnrID, signer, false) })
	t.Run("rest new head by attribute with wallet connect", func(t *testing.T) { restNewObjectHeadByAttribute(ctx, t, clientPool, &owner, cnrID, signer, true) })
	t.Run("rest new get by attribute", func(t *testing.T) {
		restNewObjectGetByAttribute(ctx, t, clientPool, &owner, cnrID, signer, false, false)
	})
	t.Run("rest new get by attribute with wallet connect", func(t *testing.T) {
		restNewObjectGetByAttribute(ctx, t, clientPool, &owner, cnrID, signer, true, false)
	})
	t.Run("rest new get by attribute with range", func(t *testing.T) {
		restNewObjectGetByAttribute(ctx, t, clientPool, &owner, cnrID, signer, false, true)
	})
}

func createDockerContainer(ctx context.Context, t *testing.T, image, version string) testcontainers.Container {
	req := testcontainers.ContainerRequest{
		Image:      image,
		WaitingFor: wait.NewLogStrategy("aio container started").WithStartupTimeout(2 * time.Minute),
		Name:       "restgw-aio-test-" + version,
		Hostname:   "aio",
		HostConfigModifier: func(hostConfig *dockerContainer.HostConfig) {
			hostConfig.NetworkMode = "host"
		},
	}
	aioC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	return aioC
}

func runServer(ctx context.Context, t *testing.T, node string) context.CancelFunc {
	cancelCtx, cancel := context.WithCancel(ctx)

	v := getDefaultConfig(node)
	l := newLogger(v)

	neofsAPI, err := newNeofsAPI(cancelCtx, l, v)
	require.NoError(t, err)

	swagger, err := apiserver.GetSwagger()
	require.NoError(t, err)

	e := echo.New()
	e.HideBanner = true

	e.Group(baseURL, middleware.OapiRequestValidator(swagger))
	apiserver.RegisterHandlersWithBaseURL(e, neofsAPI, baseURL)

	go func() {
		err := e.Start(testListenAddress)
		require.ErrorIs(t, err, http.ErrServerClosed)
	}()

	return func() {
		cancel()
		err := e.Shutdown(cancelCtx)
		require.NoError(t, err)
	}
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second}
}

func getDefaultConfig(node string) *viper.Viper {
	v := config()
	v.SetDefault(cfgPeers+".0.address", node)
	v.SetDefault(cfgPeers+".0.weight", 1)
	v.SetDefault(cfgPeers+".0.priority", 1)
	v.SetDefault(cfgServerSection+cmdListenAddress, testListenAddress)
	v.SetDefault(cfgServerSection+cfgEndpointWriteTimeout, 60*time.Second)

	return v
}

func getPool(ctx context.Context, t *testing.T, key *keys.PrivateKey, node string) *pool.Pool {
	var prm pool.InitParameters
	prm.AddNode(pool.NewNodeParam(1, node, 1))
	prm.SetSigner(user.NewAutoIDSignerRFC6979(key.PrivateKey))
	prm.SetHealthcheckTimeout(5 * time.Second)
	prm.SetNodeDialTimeout(5 * time.Second)

	clientPool, err := pool.NewPool(prm)
	require.NoError(t, err)
	err = clientPool.Dial(ctx)
	require.NoError(t, err)

	return clientPool
}

func getRestrictBearerRecords() []apiserver.Record {
	return []apiserver.Record{
		formRestrictRecord(apiserver.OperationGET),
		formRestrictRecord(apiserver.OperationHEAD),
		formRestrictRecord(apiserver.OperationPUT),
		formRestrictRecord(apiserver.OperationDELETE),
		formRestrictRecord(apiserver.OperationSEARCH),
		formRestrictRecord(apiserver.OperationRANGE),
		formRestrictRecord(apiserver.OperationRANGEHASH),
	}
}

func formRestrictRecord(op apiserver.Operation) apiserver.Record {
	return apiserver.Record{
		Operation: op,
		Action:    apiserver.DENY,
		Filters:   []apiserver.Filter{},
		Targets: []apiserver.Target{{
			Role: apiserver.OTHERS,
			Keys: []string{},
		}}}
}

func formAllowRecord(op apiserver.Operation) apiserver.Record {
	return apiserver.Record{
		Operation: op,
		Action:    apiserver.ALLOW,
		Filters:   []apiserver.Filter{},
		Targets: []apiserver.Target{{
			Role: apiserver.OTHERS,
			Keys: []string{},
		}}}
}

func authTokens(ctx context.Context, t *testing.T) {
	bearers := []apiserver.Bearer{
		{
			Name: "all-object",
			Object: []apiserver.Record{{
				Operation: apiserver.OperationPUT,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			}},
		},
		{
			Name: "put-container",
			Container: &apiserver.Rule{
				Verb: apiserver.VerbPUT,
			},
		},
		{
			Name: "seteacl-container",
			Container: &apiserver.Rule{
				Verb: apiserver.VerbSETEACL,
			},
		},
		{
			Name: "delete-container",
			Container: &apiserver.Rule{
				Verb: apiserver.VerbDELETE,
			},
		},
	}

	httpClient := defaultHTTPClient()
	makeAuthTokenRequest(ctx, t, bearers, httpClient, false)
}

func mixTokens(ctx context.Context, t *testing.T, cnrID cid.ID) {
	bearers := []apiserver.Bearer{
		{
			Name: "all-object",
			Object: []apiserver.Record{{
				Operation: apiserver.OperationPUT,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			}},
		},
		{
			Name: "put-container",
			Container: &apiserver.Rule{
				Verb: apiserver.VerbPUT,
			},
		},
		{
			Name: "seteacl-container",
			Container: &apiserver.Rule{
				Verb: apiserver.VerbSETEACL,
			},
		},
	}

	httpClient := defaultHTTPClient()
	tokens := makeAuthTokenRequest(ctx, t, bearers, httpClient, false)
	objectToken := tokens[0]
	containerPutToken := tokens[1]
	containerSetEACLToken := tokens[2]

	// check reject object token when container tokens is required
	checkPostContainerWithError(t, httpClient, objectToken)

	// check reject wrong verb container token
	checkPostContainerWithError(t, httpClient, containerSetEACLToken)

	// check reject wrong verb container token
	checkDeleteContainerWithError(t, httpClient, cnrID, containerSetEACLToken)

	// check reject wrong verb container token
	checkSetEACLContainerWithError(t, httpClient, cnrID, containerPutToken)

	// check reject container token when object tokens is required
	checkPutObjectWithError(t, httpClient, cnrID, containerSetEACLToken)
}

func formFullBinaryBearer(ctx context.Context, t *testing.T) {
	bearers := []apiserver.Bearer{
		{
			Name: "all-object",
			Object: []apiserver.Record{{
				Operation: apiserver.OperationPUT,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			}},
		},
		{
			Name: "put-container",
			Container: &apiserver.Rule{
				Verb: apiserver.VerbPUT,
			},
		},
	}

	httpClient := defaultHTTPClient()
	tokens := makeAuthTokenRequest(ctx, t, bearers, httpClient, false)
	objectToken := tokens[0]
	containerPutToken := tokens[1]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	// check that container token isn't valid
	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, containerPutToken)
	checkGWErrorResponse(t, httpClient, request)

	// check that object bearer token is valid
	request, err = http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, objectToken)
	resp := &apiserver.BinaryBearer{}
	doRequest(t, httpClient, request, http.StatusOK, resp)

	actualTokenRaw, err := base64.StdEncoding.DecodeString(resp.Token)
	require.NoError(t, err)

	var actualToken bearer.Token
	err = actualToken.Unmarshal(actualTokenRaw)
	require.NoError(t, err)

	require.True(t, actualToken.VerifySignature())
	require.Len(t, actualToken.EACLTable().Records(), 1)
	actualRecord := actualToken.EACLTable().Records()[0]
	require.Equal(t, eacl.OperationPut, actualRecord.Operation())
	require.Equal(t, eacl.ActionAllow, actualRecord.Action())
	require.Empty(t, actualRecord.Filters())
	require.Len(t, actualRecord.Targets(), 1)
	actualTarget := actualRecord.Targets()[0]
	require.Empty(t, actualTarget.Accounts())
	require.Equal(t, eacl.RoleOthers, actualTarget.Role())
}

func checkPostContainerWithError(t *testing.T, httpClient *http.Client, token *handlers.BearerToken) {
	reqURL, err := url.Parse(testHost + "/v1/containers")
	require.NoError(t, err)
	body, err := json.Marshal(&apiserver.ContainerPostInfo{ContainerName: "container"})
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, reqURL.String(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, token)

	checkGWErrorResponse(t, httpClient, request)
}

func checkDeleteContainerWithError(t *testing.T, httpClient *http.Client, cnrID cid.ID, token *handlers.BearerToken) {
	reqURL, err := url.Parse(testHost + "/v1/containers/" + cnrID.EncodeToString())
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodDelete, reqURL.String(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, token)

	checkGWErrorResponse(t, httpClient, request)
}

func checkSetEACLContainerWithError(t *testing.T, httpClient *http.Client, cnrID cid.ID, token *handlers.BearerToken) {
	req := apiserver.Eacl{Records: []apiserver.Record{}}
	body, err := json.Marshal(&req)
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPut, testHost+"/v1/containers/"+cnrID.EncodeToString()+"/eacl", bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, token)

	checkGWErrorResponse(t, httpClient, request)
}

func checkPutObjectWithError(t *testing.T, httpClient *http.Client, cnrID cid.ID, token *handlers.BearerToken) {
	p := base64.StdEncoding.EncodeToString([]byte("content"))
	req := &apiserver.ObjectUpload{
		ContainerId: cnrID.EncodeToString(),
		FileName:    "newFile.txt",
		Payload:     &p,
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)

	request, err := http.NewRequest(http.MethodPut, testHost+"/v1/objects?", bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, token)

	checkGWErrorResponse(t, httpClient, request)
}

func checkGWErrorResponse(t *testing.T, httpClient *http.Client, request *http.Request) {
	resp := &apiserver.ErrorResponse{}
	doRequest(t, httpClient, request, http.StatusBadRequest, resp)
	require.Equal(t, uint32(0), resp.Code)
	require.Equal(t, apiserver.GW, resp.Type)
}

func restObjectPut(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID cid.ID, signer user.Signer) {
	bearer := apiserver.Bearer{
		Object: []apiserver.Record{{
			Operation: apiserver.OperationPUT,
			Action:    apiserver.ALLOW,
			Filters:   []apiserver.Filter{},
			Targets: []apiserver.Target{{
				Role: apiserver.OTHERS,
				Keys: []string{},
			}},
		}},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	content := "content of file"
	attrKey, attrValue := "User-Attribute", "user value"

	attributes := map[string]string{
		object.AttributeFileName: "newFile.txt",
		attrKey:                  attrValue,
	}

	req := &apiserver.ObjectUpload{
		ContainerId: cnrID.EncodeToString(),
		FileName:    "newFile.txt",
		Payload:     util.NewString(base64.StdEncoding.EncodeToString([]byte(content))),
		Attributes: []apiserver.Attribute{{
			Key:   attrKey,
			Value: attrValue,
		}},
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodPut, testHost+"/v1/objects?"+query.Encode(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	addr := &apiserver.Address{}
	doRequest(t, httpClient, request, http.StatusOK, addr)

	var CID cid.ID
	err = CID.DecodeString(addr.ContainerId)
	require.NoError(t, err)
	var id oid.ID
	err = id.DecodeString(addr.ObjectId)
	require.NoError(t, err)

	var prm client.PrmObjectGet
	res, payloadReader, err := clientPool.ObjectGetInit(ctx, CID, id, signer, prm)
	require.NoError(t, err)

	payload := bytes.NewBuffer(nil)
	_, err = io.Copy(payload, payloadReader)
	require.NoError(t, err)
	require.Equal(t, content, payload.String())

	for _, attribute := range res.Attributes() {
		require.Equal(t, attributes[attribute.Key()], attribute.Value(), attribute.Key())
	}
}

func restObjectGetByAttribute(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer) {
	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			{
				Operation: apiserver.OperationGET,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
			{
				Operation: apiserver.OperationSEARCH,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)
	resp := &apiserver.BinaryBearer{}
	doRequest(t, httpClient, request, http.StatusOK, resp)

	var (
		content      = []byte("some content")
		fileNameAttr = "get-obj-by-attr-name-echo"
		createTS     = time.Now().Unix()
		attributes   = map[string]string{
			object.AttributeFileName:  fileNameAttr,
			object.AttributeTimestamp: strconv.FormatInt(createTS, 10),
			"user-attribute":          "user value",
		}
	)

	t.Run("get", func(t *testing.T) {
		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		request, err = http.NewRequest(http.MethodGet, testHost+"/v1/get_by_attribute/"+cnrID.EncodeToString()+"/"+object.AttributeFileName+"/"+fileNameAttr+"?"+query.Encode(), nil)
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)
		request.Header.Set("Authorization", "Bearer "+resp.Token)

		headers, rawPayload := doRequest(t, httpClient, request, http.StatusOK, nil)
		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attribute-Filename":
				require.Equal(t, fileNameAttr, vals[0])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Attribute-Timestamp":
				require.Equal(t, strconv.FormatInt(createTS, 10), vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				require.Equal(t, strconv.FormatInt(int64(len(content)), 10), vals[0])
			case "Content-Type":
				require.Equal(t, "text/plain; charset=utf-8", vals[0])
			}
		}

		require.Equal(t, content, rawPayload)
	})

	t.Run("get multi-segment path attribute", func(t *testing.T) {
		multiSegmentName := "path/" + fileNameAttr
		attributes[object.AttributeFileName] = multiSegmentName

		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		request, err = http.NewRequest(http.MethodGet, testHost+"/v1/get_by_attribute/"+cnrID.EncodeToString()+"/"+object.AttributeFileName+"/"+multiSegmentName+"?"+query.Encode(), nil)
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)
		request.Header.Set("Authorization", "Bearer "+resp.Token)

		headers, rawPayload := doRequest(t, httpClient, request, http.StatusOK, nil)
		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attribute-Filename":
				require.Equal(t, multiSegmentName, vals[0])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Attribute-Timestamp":
				require.Equal(t, strconv.FormatInt(createTS, 10), vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				require.Equal(t, strconv.FormatInt(int64(len(content)), 10), vals[0])
			case "Content-Type":
				require.Equal(t, "text/plain; charset=utf-8", vals[0])
			}
		}

		require.Equal(t, content, rawPayload)
	})
}

func restObjectHeadByAttribute(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer) {
	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			{
				Operation: apiserver.OperationHEAD,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
			{
				Operation: apiserver.OperationRANGE,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
			{
				Operation: apiserver.OperationSEARCH,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)
	resp := &apiserver.BinaryBearer{}
	doRequest(t, httpClient, request, http.StatusOK, resp)

	var (
		content      = []byte("some content")
		fileNameAttr = "head-obj-by-attr-name-echo"
		createTS     = time.Now().Unix()
		attributes   = map[string]string{
			object.AttributeFileName:  fileNameAttr,
			object.AttributeTimestamp: strconv.FormatInt(createTS, 10),
			"user-attribute":          "user value",
		}
	)

	t.Run("head", func(t *testing.T) {
		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		request, err = http.NewRequest(http.MethodHead, testHost+"/v1/get_by_attribute/"+cnrID.EncodeToString()+"/"+object.AttributeFileName+"/"+fileNameAttr+"?"+query.Encode(), nil)
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)
		request.Header.Set("Authorization", "Bearer "+resp.Token)

		headers, _ := doRequest(t, httpClient, request, http.StatusOK, nil)
		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attribute-Filename":
				require.Equal(t, fileNameAttr, vals[0])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Attribute-Timestamp":
				require.Equal(t, strconv.FormatInt(createTS, 10), vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				require.Equal(t, strconv.FormatInt(int64(len(content)), 10), vals[0])
			case "Content-Type":
				require.Equal(t, "text/plain; charset=utf-8", vals[0])
			}
		}
	})

	t.Run("head multi-segment path attribute", func(t *testing.T) {
		multiSegmentName := "path/" + fileNameAttr
		attributes[object.AttributeFileName] = multiSegmentName

		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		request, err = http.NewRequest(http.MethodHead, testHost+"/v1/get_by_attribute/"+cnrID.EncodeToString()+"/"+object.AttributeFileName+"/"+multiSegmentName+"?"+query.Encode(), nil)
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)
		request.Header.Set("Authorization", "Bearer "+resp.Token)

		headers, _ := doRequest(t, httpClient, request, http.StatusOK, nil)
		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attribute-Filename":
				require.Equal(t, multiSegmentName, vals[0])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Attribute-Timestamp":
				require.Equal(t, strconv.FormatInt(createTS, 10), vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				require.Equal(t, strconv.FormatInt(int64(len(content)), 10), vals[0])
			case "Content-Type":
				require.Equal(t, "text/plain; charset=utf-8", vals[0])
			}
		}
	})
}

func restObjectHead(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer) {
	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			{
				Operation: apiserver.OperationHEAD,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
			{
				Operation: apiserver.OperationRANGE,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)
	resp := &apiserver.BinaryBearer{}
	doRequest(t, httpClient, request, http.StatusOK, resp)

	var (
		content      = []byte("some content")
		fileNameAttr = "head-obj-name-echo"
		createTS     = time.Now().Unix()
		attributes   = map[string]string{
			object.AttributeFileName:  fileNameAttr,
			object.AttributeTimestamp: strconv.FormatInt(createTS, 10),
			"user-attribute":          "user value",
		}
	)

	t.Run("head", func(t *testing.T) {
		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		request, err = http.NewRequest(http.MethodHead, testHost+"/v1/get/"+cnrID.EncodeToString()+"/"+objID.EncodeToString()+"?"+query.Encode(), nil)
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)
		request.Header.Set("Authorization", "Bearer "+resp.Token)

		headers, _ := doRequest(t, httpClient, request, http.StatusOK, nil)
		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attribute-Filename":
				require.Equal(t, fileNameAttr, vals[0])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Attribute-Timestamp":
				require.Equal(t, strconv.FormatInt(createTS, 10), vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				require.Equal(t, strconv.FormatInt(int64(len(content)), 10), vals[0])
			case "Content-Type":
				require.Equal(t, "text/plain; charset=utf-8", vals[0])
			}
		}
	})

	t.Run("custom content-type", func(t *testing.T) {
		customContentType := "some/type"
		attributes[object.AttributeContentType] = customContentType

		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		request, err = http.NewRequest(http.MethodHead, testHost+"/v1/get/"+cnrID.EncodeToString()+"/"+objID.EncodeToString()+"?"+query.Encode(), nil)
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)
		request.Header.Set("Authorization", "Bearer "+resp.Token)

		headers, _ := doRequest(t, httpClient, request, http.StatusOK, nil)
		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attribute-Filename":
				require.Equal(t, fileNameAttr, vals[0])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Attribute-Timestamp":
				require.Equal(t, strconv.FormatInt(createTS, 10), vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				require.Equal(t, strconv.FormatInt(int64(len(content)), 10), vals[0])
			case "Content-Type":
				require.Equal(t, customContentType, vals[0])
			}
		}
	})
}

func restObjectGet(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer) {
	content := []byte("some content")
	attributes := map[string]string{
		object.AttributeFileName: "get-obj-name",
		"user-attribute":         "user value",
	}

	objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			{
				Operation: apiserver.OperationHEAD,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
			{
				Operation: apiserver.OperationRANGE,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/"+objID.EncodeToString()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	objInfo := &apiserver.ObjectInfo{}
	doRequest(t, httpClient, request, http.StatusOK, objInfo)

	require.Equal(t, cnrID.EncodeToString(), objInfo.ContainerId)
	require.Equal(t, objID.EncodeToString(), objInfo.ObjectId)
	require.Equal(t, ownerID.EncodeToString(), objInfo.OwnerId)
	require.Equal(t, len(attributes), len(objInfo.Attributes))
	require.Equal(t, uint64(len(content)), objInfo.ObjectSize)

	contentData, err := base64.StdEncoding.DecodeString(*objInfo.Payload)
	require.NoError(t, err)
	require.Equal(t, content, contentData)

	for _, attr := range objInfo.Attributes {
		require.Equal(t, attributes[attr.Key], attr.Value)
	}

	// check max-payload-size params
	query = make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	query.Add("max-payload-size", "0")

	request, err = http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/"+objID.EncodeToString()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	objInfo = &apiserver.ObjectInfo{}
	doRequest(t, httpClient, request, http.StatusOK, objInfo)
	require.Empty(t, objInfo.Payload)
	require.Equal(t, int64(0), objInfo.PayloadSize)

	// check range params
	rangeLength := 4
	query = make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	query.Add("range-offset", "0")
	query.Add("range-length", strconv.Itoa(rangeLength))

	request, err = http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/"+objID.EncodeToString()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	objInfo = &apiserver.ObjectInfo{}
	doRequest(t, httpClient, request, http.StatusOK, objInfo)
	require.Equal(t, int64(rangeLength), objInfo.PayloadSize)

	contentData, err = base64.StdEncoding.DecodeString(*objInfo.Payload)
	require.NoError(t, err)
	require.Equal(t, content[:rangeLength], contentData)

	// check empty object
	objID2 := createObject(ctx, t, p, ownerID, cnrID, map[string]string{}, []byte{}, signer)

	query2 := make(url.Values)
	query2.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request2, err := http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/"+objID2.EncodeToString()+"?"+query2.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request2.Header, bearerToken)

	objInfo2 := &apiserver.ObjectInfo{}
	doRequest(t, httpClient, request2, http.StatusOK, objInfo2)

	require.Equal(t, cnrID.EncodeToString(), objInfo2.ContainerId)
	require.Equal(t, objID2.EncodeToString(), objInfo2.ObjectId)
	require.Equal(t, ownerID.EncodeToString(), objInfo2.OwnerId)
	require.Equal(t, 0, len(objInfo2.Attributes))
	require.Equal(t, uint64(0), objInfo2.ObjectSize)
}

func restObjectGetUnauthenticated(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer) {
	content := []byte("some content")
	attributes := map[string]string{
		object.AttributeFileName: "get-obj-unauth-name",
		"user-attribute":         "user value",
	}

	objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

	httpClient := defaultHTTPClient()

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/"+objID.EncodeToString(), nil)
	require.NoError(t, err)

	request.Header.Add("Content-Type", "application/json")

	resp := &apiserver.ErrorResponse{}
	doRequest(t, httpClient, request, http.StatusForbidden, resp)
	require.Equal(t, uint32(2048), resp.Code)
	require.Equal(t, apiserver.API, resp.Type)

	// set empty eacl table to be able to do unauthenticated request
	allowByEACL(ctx, t, p, cnrID, signer)

	request, err = http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/"+objID.EncodeToString(), nil)
	require.NoError(t, err)
	objInfo := &apiserver.ObjectInfo{}
	doRequest(t, httpClient, request, http.StatusOK, objInfo)

	require.Equal(t, cnrID.EncodeToString(), objInfo.ContainerId)
	require.Equal(t, objID.EncodeToString(), objInfo.ObjectId)
	require.Equal(t, ownerID.EncodeToString(), objInfo.OwnerId)
	require.Equal(t, len(attributes), len(objInfo.Attributes))
	require.Equal(t, uint64(len(content)), objInfo.ObjectSize)

	contentData, err := base64.StdEncoding.DecodeString(*objInfo.Payload)
	require.NoError(t, err)
	require.Equal(t, content, contentData)

	for _, attr := range objInfo.Attributes {
		require.Equal(t, attributes[attr.Key], attr.Value)
	}

	// set eacl the same as was before test started
	restrictByEACL(ctx, t, p, cnrID, signer)
}

func restObjectGetFullBearer(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer) {
	restObjectGetWithBearer(ctx, t, p, ownerID, cnrID, signer, false)
}
func restObjectGetBearerCookie(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer) {
	restObjectGetWithBearer(ctx, t, p, ownerID, cnrID, signer, true)
}
func restObjectGetWithBearer(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer, cookie bool) {
	content := []byte("some content")
	attributes := map[string]string{
		object.AttributeFileName: "get-obj-name",
		"user-attribute":         "user value",
	}

	objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

	bearers := apiserver.Bearer{
		Object: []apiserver.Record{
			{
				Operation: apiserver.OperationHEAD,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
			{
				Operation: apiserver.OperationRANGE,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets: []apiserver.Target{{
					Role: apiserver.OTHERS,
					Keys: []string{},
				}},
			},
		},
	}
	bearers.Object = append(bearers.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearers}, httpClient, true)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)
	resp := &apiserver.BinaryBearer{}
	doRequest(t, httpClient, request, http.StatusOK, resp)
	actualTokenRaw, err := base64.StdEncoding.DecodeString(resp.Token)
	require.NoError(t, err)
	var actualToken bearer.Token
	err = actualToken.Unmarshal(actualTokenRaw)
	require.NoError(t, err)
	// check that is token for all users
	require.True(t, actualToken.AssertUser(user.ID{}))

	query.Add(fullBearerQuery, "true")

	request, err = http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/"+objID.EncodeToString()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	if cookie {
		request.Header.Add("Cookie", "Bearer="+resp.Token+";")
	} else {
		request.Header.Add("Authorization", "Bearer "+resp.Token)
	}

	objInfo := &apiserver.ObjectInfo{}
	doRequest(t, httpClient, request, http.StatusOK, objInfo)
	if objInfo.Payload != nil {
		contentData, err := base64.StdEncoding.DecodeString(*objInfo.Payload)
		require.NoError(t, err)
		require.Equal(t, content, contentData)
	}
}

func restObjectDelete(ctx context.Context, t *testing.T, p *pool.Pool, owner *user.ID, cnrID cid.ID, signer user.Signer) {
	objID := createObject(ctx, t, p, owner, cnrID, nil, []byte("some content"), signer)

	bearer := apiserver.Bearer{
		Object: []apiserver.Record{{
			Operation: apiserver.OperationDELETE,
			Action:    apiserver.ALLOW,
			Filters:   []apiserver.Filter{},
			Targets: []apiserver.Target{{
				Role: apiserver.OTHERS,
				Keys: []string{},
			}},
		}, {
			Operation: apiserver.OperationHEAD,
			Action:    apiserver.ALLOW,
			Filters:   []apiserver.Filter{},
			Targets: []apiserver.Target{{
				Role: apiserver.OTHERS,
				Keys: []string{},
			}},
		}},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodDelete, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/"+objID.EncodeToString()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	resp := &apiserver.SuccessResponse{}
	doRequest(t, httpClient, request, http.StatusOK, resp)
	require.True(t, resp.Success)

	var prm client.PrmObjectHead

	_, err = p.ObjectHead(ctx, cnrID, objID, signer, prm)
	require.Error(t, err)
}

func restObjectsSearch(ctx context.Context, t *testing.T, p *pool.Pool, owner *user.ID, cnrID cid.ID, signer user.Signer) {
	userKey, userValue := "User-Attribute", "user-attribute-value"
	objectName := "object-name"
	filePath := "path/to/object/object-name"
	headers := map[string]string{
		object.AttributeFileName: objectName,
		object.AttributeFilePath: filePath,
		userKey:                  userValue,
	}
	objID := createObject(ctx, t, p, owner, cnrID, headers, []byte("some content"), signer)
	headers[userKey] = "dummy"
	_ = createObject(ctx, t, p, owner, cnrID, headers, []byte("some content"), signer)

	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			{
				Operation: apiserver.OperationSEARCH,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
			{
				Operation: apiserver.OperationHEAD,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
			{
				Operation: apiserver.OperationGET,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	t.Run("with filter", func(t *testing.T) {
		search := &apiserver.SearchFilters{
			Filters: []apiserver.SearchFilter{
				{
					Key:   userKey,
					Match: apiserver.MatchStringEqual,
					Value: userValue,
				},
			},
		}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		query := make(url.Values)
		query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

		request, err := http.NewRequest(http.MethodPost, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectList{}
		doRequest(t, httpClient, request, http.StatusOK, resp)

		require.Equal(t, 1, resp.Size)
		require.Len(t, resp.Objects, 1)

		objBaseInfo := resp.Objects[0]
		require.Equal(t, cnrID.EncodeToString(), objBaseInfo.Address.ContainerId)
		require.Equal(t, objID.EncodeToString(), objBaseInfo.Address.ObjectId)
		require.Equal(t, objectName, *objBaseInfo.Name)
		require.Equal(t, filePath, *objBaseInfo.FilePath)
	})

	t.Run("no filters", func(t *testing.T) {
		search := &apiserver.SearchFilters{}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		query := make(url.Values)
		query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

		request, err := http.NewRequest(http.MethodPost, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectList{}
		doRequest(t, httpClient, request, http.StatusOK, resp)

		require.Greater(t, len(resp.Objects), 0)
	})
}

func restObjectsSearchV2(ctx context.Context, t *testing.T, p *pool.Pool, owner *user.ID, cnrID cid.ID, signer user.Signer) {
	var (
		userKey, userValue = strconv.FormatInt(time.Now().UnixNano(), 16), strconv.FormatInt(time.Now().UnixNano(), 16)
		objectName         = strconv.FormatInt(time.Now().UnixNano(), 16)
		filePath           = "path/to/object/" + objectName

		headers = map[string]string{
			object.AttributeFileName: objectName,
			object.AttributeFilePath: filePath,
			userKey:                  userValue,
			xNonce:                   strconv.FormatInt(time.Now().UnixNano(), 10),
		}
	)

	objID := createObject(ctx, t, p, owner, cnrID, headers, []byte("some content"), signer)
	// Objects created in the same timestamp, with identical attributes have the same ID. Make each object unique.
	headers[xNonce] = strconv.FormatInt(time.Now().UnixNano(), 10)
	objID2 := createObject(ctx, t, p, owner, cnrID, headers, []byte("some content"), signer)

	idsGroup := []string{objID.EncodeToString(), objID2.EncodeToString()}

	headers[userKey] = "dummy"
	_ = createObject(ctx, t, p, owner, cnrID, headers, []byte("some content"), signer)

	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			{
				Operation: apiserver.OperationSEARCH,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
			{
				Operation: apiserver.OperationHEAD,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
			{
				Operation: apiserver.OperationGET,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	search := &apiserver.SearchRequest{
		Filters: []apiserver.SearchFilter{
			{
				Key:   userKey,
				Match: apiserver.MatchStringEqual,
				Value: userValue,
			},
		},
		Attributes: []string{object.AttributeFileName, object.AttributeFilePath},
	}

	body, err := json.Marshal(search)
	require.NoError(t, err)

	var nextCursor string

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	query.Add("limit", "1")

	t.Run("check first object", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)
		nextCursor = resp.Cursor

		require.NotEmpty(t, nextCursor)
		require.Len(t, resp.Objects, 1)

		objBaseInfo := resp.Objects[0]
		require.Contains(t, idsGroup, objBaseInfo.ObjectId)
		require.Equal(t, userValue, objBaseInfo.Attributes[userKey])
		require.Equal(t, objectName, objBaseInfo.Attributes[object.AttributeFileName])
		require.Equal(t, filePath, objBaseInfo.Attributes[object.AttributeFilePath])
	})

	t.Run("check second object", func(t *testing.T) {
		query.Add("cursor", nextCursor)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)

		require.Empty(t, resp.Cursor)
		require.Len(t, resp.Objects, 1)

		objBaseInfo := resp.Objects[0]
		require.Contains(t, idsGroup, objBaseInfo.ObjectId)
		require.Equal(t, userValue, objBaseInfo.Attributes[userKey])
		require.Equal(t, objectName, objBaseInfo.Attributes[object.AttributeFileName])
		require.Equal(t, filePath, objBaseInfo.Attributes[object.AttributeFilePath])
	})

	t.Run("returning attribute limit", func(t *testing.T) {
		limitedSearch := &apiserver.SearchRequest{
			Filters: []apiserver.SearchFilter{
				{
					Key:   userKey,
					Match: apiserver.MatchStringEqual,
					Value: userValue,
				},
			},
			Attributes: []string{"a", "a", "a", "a", "a", "a", "a", "a"},
		}
		limitedBody, err := json.Marshal(limitedSearch)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search", bytes.NewReader(limitedBody))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusBadRequest, resp)
	})
}

func restObjectsSearchV2CursorAndLimit(ctx context.Context, t *testing.T, p *pool.Pool, owner *user.ID, signer user.Signer) {
	var (
		cnrID     = createContainer(ctx, t, p, *owner, strconv.FormatInt(time.Now().UnixNano(), 16), signer)
		fileNames = []string{"888.jpg", "IMG_1123.jpeg", "cat.jpg", "errfwre.jpg"}
	)

	restrictByEACL(ctx, t, p, cnrID, signer)

	for _, name := range fileNames {
		headers := map[string]string{
			object.AttributeFileName: name,
			object.AttributeFilePath: "path/to/object/" + name,
		}

		createObject(ctx, t, p, owner, cnrID, headers, []byte("some content"), signer)
	}

	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			{
				Operation: apiserver.OperationSEARCH,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
			{
				Operation: apiserver.OperationHEAD,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
			{
				Operation: apiserver.OperationGET,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	search := &apiserver.SearchRequest{
		Filters: []apiserver.SearchFilter{
			{
				Key:   object.AttributeFileName,
				Match: apiserver.MatchCommonPrefix,
				Value: "",
			},
		},
		Attributes: []string{object.AttributeFileName, object.AttributeFilePath},
	}

	body, err := json.Marshal(search)
	require.NoError(t, err)

	var nextCursor string

	for i, name := range fileNames {
		t.Run("limit 1, step="+strconv.Itoa(i), func(t *testing.T) {
			query := make(url.Values)
			query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
			query.Add("limit", "1")
			if i > 0 {
				query.Add("cursor", nextCursor)
			}

			request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
			require.NoError(t, err)
			prepareCommonHeaders(request.Header, bearerToken)

			resp := &apiserver.ObjectListV2{}
			doRequest(t, httpClient, request, http.StatusOK, resp)
			nextCursor = resp.Cursor

			if i < len(fileNames)-1 {
				require.NotEmpty(t, nextCursor)
			} else {
				require.Empty(t, nextCursor)
			}

			require.Len(t, resp.Objects, 1)
			require.Equal(t, name, resp.Objects[0].Attributes[object.AttributeFileName])
		})
	}

	for i := range 2 {
		t.Run("limit 3, step="+strconv.Itoa(i), func(t *testing.T) {
			query := make(url.Values)
			query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
			query.Add("limit", "3")
			if i > 0 {
				query.Add("cursor", nextCursor)
			}

			request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
			require.NoError(t, err)
			prepareCommonHeaders(request.Header, bearerToken)

			resp := &apiserver.ObjectListV2{}
			doRequest(t, httpClient, request, http.StatusOK, resp)
			nextCursor = resp.Cursor

			if i == 0 {
				require.NotEmpty(t, nextCursor)
				require.Len(t, resp.Objects, 3)
			} else {
				require.Empty(t, nextCursor)
				require.Len(t, resp.Objects, 1)
			}
		})
	}
}

func restObjectsSearchV2Filters(ctx context.Context, t *testing.T, p *pool.Pool, owner *user.ID, signer user.Signer) {
	var (
		cnrName         = strconv.FormatInt(time.Now().UnixNano(), 16)
		customAttribute = strconv.FormatInt(time.Now().UnixNano(), 16)
		fileName        = strconv.FormatInt(time.Now().UnixNano(), 16)

		headerList = []map[string]string{
			{
				object.AttributeFileName: fileName,
				customAttribute:          "0",
				xNonce:                   strconv.FormatInt(time.Now().UnixNano(), 10),
			},
			{
				object.AttributeFileName: fileName,
				customAttribute:          "1",
				xNonce:                   strconv.FormatInt(time.Now().UnixNano(), 10),
			},
			{
				object.AttributeFileName: fileName,
				customAttribute:          "2",
				xNonce:                   strconv.FormatInt(time.Now().UnixNano(), 10),
			},
			{
				object.AttributeFileName: fileName,
				customAttribute:          "3",
				xNonce:                   strconv.FormatInt(time.Now().UnixNano(), 10),
			},
			{
				object.AttributeFileName: strconv.FormatInt(time.Now().UnixNano(), 16),
				customAttribute:          "4",
				xNonce:                   strconv.FormatInt(time.Now().UnixNano(), 10),
			},
		}

		cnrID = createContainer(ctx, t, p, *owner, cnrName, signer)
	)

	for _, headers := range headerList {
		createObject(ctx, t, p, owner, cnrID, headers, []byte("some content"), signer)
	}

	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			{
				Operation: apiserver.OperationSEARCH,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
			{
				Operation: apiserver.OperationHEAD,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
			{
				Operation: apiserver.OperationGET,
				Action:    apiserver.ALLOW,
				Filters:   []apiserver.Filter{},
				Targets:   []apiserver.Target{{Role: apiserver.OTHERS, Keys: []string{}}},
			},
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	t.Run("search MatchStringEqual", func(t *testing.T) {
		search := &apiserver.SearchFilters{
			Filters: []apiserver.SearchFilter{
				{
					Key:   object.AttributeFileName,
					Match: apiserver.MatchStringEqual,
					Value: fileName,
				},
			},
		}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)
		require.Len(t, resp.Objects, 4)
	})

	t.Run("search MatchNotPresent", func(t *testing.T) {
		search := &apiserver.SearchFilters{
			Filters: []apiserver.SearchFilter{
				{
					Key:   object.AttributeFileName,
					Match: apiserver.MatchStringNotEqual,
					Value: fileName,
				},
			},
		}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)
		require.Len(t, resp.Objects, 1)
	})

	t.Run("search MatchNotPresent", func(t *testing.T) {
		search := &apiserver.SearchFilters{
			Filters: []apiserver.SearchFilter{
				{
					Key:   object.AttributeFilePath,
					Match: apiserver.MatchNotPresent,
				},
			},
		}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)
		require.Len(t, resp.Objects, len(headerList))
	})

	t.Run("search MatchCommonPrefix", func(t *testing.T) {
		search := &apiserver.SearchFilters{
			Filters: []apiserver.SearchFilter{
				{
					Key:   object.AttributeFileName,
					Match: apiserver.MatchCommonPrefix,
					Value: fileName,
				},
			},
		}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)
		require.Len(t, resp.Objects, 4)
	})

	t.Run("search MatchNumGT", func(t *testing.T) {
		search := &apiserver.SearchFilters{
			Filters: []apiserver.SearchFilter{
				{
					Key:   customAttribute,
					Match: apiserver.MatchNumGT,
					Value: "0",
				},
			},
		}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)
		require.Len(t, resp.Objects, len(headerList)-1)
	})

	t.Run("search MatchNumGE", func(t *testing.T) {
		search := &apiserver.SearchFilters{
			Filters: []apiserver.SearchFilter{
				{
					Key:   customAttribute,
					Match: apiserver.MatchNumGE,
					Value: "0",
				},
			},
		}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)
		require.Len(t, resp.Objects, len(headerList))
	})

	t.Run("search MatchNumLT", func(t *testing.T) {
		search := &apiserver.SearchFilters{
			Filters: []apiserver.SearchFilter{
				{
					Key:   customAttribute,
					Match: apiserver.MatchNumLT,
					Value: "1",
				},
			},
		}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)
		require.Len(t, resp.Objects, 1)
	})

	t.Run("search MatchNumLE", func(t *testing.T) {
		search := &apiserver.SearchFilters{
			Filters: []apiserver.SearchFilter{
				{
					Key:   customAttribute,
					Match: apiserver.MatchNumLE,
					Value: "1",
				},
			},
		}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)
		require.Len(t, resp.Objects, 2)
	})

	t.Run("search MatchNumLE invalid numeric filter", func(t *testing.T) {
		search := &apiserver.SearchFilters{
			Filters: []apiserver.SearchFilter{
				{
					Key:   customAttribute,
					Match: apiserver.MatchNumLE,
					Value: "1a",
				},
			},
		}

		body, err := json.Marshal(search)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusBadRequest, resp)
	})

	t.Run("search without filters", func(t *testing.T) {
		var search apiserver.SearchFilters

		body, err := json.Marshal(search)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, testHost+"/v2/objects/"+cnrID.EncodeToString()+"/search?"+query.Encode(), bytes.NewReader(body))
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)

		resp := &apiserver.ObjectListV2{}
		doRequest(t, httpClient, request, http.StatusOK, resp)
		require.Greater(t, len(resp.Objects), 0)
	})
}

func doRequest(t *testing.T, httpClient *http.Client, request *http.Request, expectedCode int, model any) (http.Header, []byte) {
	resp, err := httpClient.Do(request)
	require.NoError(t, err)
	defer func() {
		err := resp.Body.Close()
		require.NoError(t, err)
	}()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, expectedCode, resp.StatusCode, "resp: %s", respBody)

	if model == nil {
		return resp.Header, respBody
	}

	err = json.Unmarshal(respBody, model)
	require.NoError(t, err)
	return resp.Header, respBody
}

func restContainerGet(ctx context.Context, t *testing.T, owner user.ID, cnrID cid.ID) {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/containers/"+cnrID.EncodeToString(), nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)

	cnrInfo := &apiserver.ContainerInfo{}
	doRequest(t, httpClient, request, http.StatusOK, cnrInfo)

	require.Equal(t, cnrID.EncodeToString(), cnrInfo.ContainerId)
	require.Equal(t, owner.EncodeToString(), cnrInfo.OwnerId)
	require.Equal(t, containerName, cnrInfo.ContainerName)
	require.NotEmpty(t, cnrInfo.Version)
}

func restContainerDelete(ctx context.Context, t *testing.T, clientPool *pool.Pool, owner user.ID, signer user.Signer) {
	cnrID := createContainer(ctx, t, clientPool, owner, "for-delete", signer)

	bearer := apiserver.Bearer{
		Container: &apiserver.Rule{
			Verb: apiserver.VerbDELETE,
		},
	}

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodDelete, testHost+"/v1/containers/"+cnrID.EncodeToString()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)
	prepareCommonHeaders(request.Header, bearerToken)

	resp := &apiserver.SuccessResponse{}
	doRequest(t, httpClient, request, http.StatusOK, resp)
	require.True(t, resp.Success)

	_, err = clientPool.ContainerGet(ctx, cnrID, client.PrmContainerGet{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func restContainerEACLPut(ctx context.Context, t *testing.T, clientPool *pool.Pool, owner user.ID, signer user.Signer) {
	cnrID := createContainer(ctx, t, clientPool, owner, "for-eacl-put", signer)
	httpClient := &http.Client{Timeout: 60 * time.Second}
	bearer := apiserver.Bearer{
		Container: &apiserver.Rule{
			Verb: apiserver.VerbSETEACL,
		},
	}
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	req := apiserver.Eacl{
		Records: []apiserver.Record{{
			Action:    apiserver.DENY,
			Filters:   []apiserver.Filter{},
			Operation: apiserver.OperationDELETE,
			Targets: []apiserver.Target{{
				Keys: []string{"031a6c6fbbdf02ca351745fa86b9ba5a9452d785ac4f7fc2b7548ca2a46c4fcf4a"},
				Role: apiserver.OTHERS,
			}},
		}},
	}

	invalidBody, err := json.Marshal(&req)
	require.NoError(t, err)

	req.Records[0].Targets[0].Role = apiserver.KEYS
	body, err := json.Marshal(&req)
	require.NoError(t, err)

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	doSetEACLRequest(ctx, t, httpClient, cnrID, query, bearerToken, invalidBody, http.StatusInternalServerError, nil)

	resp := &apiserver.SuccessResponse{}
	doSetEACLRequest(ctx, t, httpClient, cnrID, query, bearerToken, body, http.StatusOK, resp)
	require.True(t, resp.Success)

	table, err := clientPool.ContainerEACL(ctx, cnrID, client.PrmContainerEACL{})
	require.NoError(t, err)

	expectedTable, err := util.ToNativeTable(req.Records)
	require.NoError(t, err)
	expectedTable.SetCID(cnrID)

	require.Equal(t, expectedTable.Marshal(), table.Marshal())
}

func doSetEACLRequest(ctx context.Context, t *testing.T, httpClient *http.Client, cnrID cid.ID, query url.Values, bearerToken *handlers.BearerToken, body []byte, status int, model any) {
	request, err := http.NewRequest(http.MethodPut, testHost+"/v1/containers/"+cnrID.EncodeToString()+"/eacl?"+query.Encode(), bytes.NewReader(body))
	require.NoError(t, err)
	request = request.WithContext(ctx)
	prepareCommonHeaders(request.Header, bearerToken)

	doRequest(t, httpClient, request, status, model)
}

func restContainerEACLGet(ctx context.Context, t *testing.T, p *pool.Pool, cnrID cid.ID) {
	expectedTable, err := p.ContainerEACL(ctx, cnrID, client.PrmContainerEACL{})
	require.NoError(t, err)

	httpClient := &http.Client{Timeout: 60 * time.Second}

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/containers/"+cnrID.EncodeToString()+"/eacl", nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)

	responseTable := &apiserver.Eacl{}
	doRequest(t, httpClient, request, http.StatusOK, responseTable)

	require.Equal(t, cnrID.EncodeToString(), responseTable.ContainerId)

	actualTable, err := util.ToNativeTable(responseTable.Records)
	require.NoError(t, err)
	actualTable.SetCID(cnrID)

	require.Equal(t, expectedTable.Marshal(), actualTable.Marshal())
}

func restContainerList(ctx context.Context, t *testing.T, p *pool.Pool, owner user.ID, cnrID cid.ID) {
	var prm client.PrmContainerList
	ids, err := p.ContainerList(ctx, owner, prm)
	require.NoError(t, err)

	httpClient := defaultHTTPClient()

	query := make(url.Values)
	query.Add("ownerId", owner.EncodeToString())

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/containers?"+query.Encode(), nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)

	list := &apiserver.ContainerList{}
	doRequest(t, httpClient, request, http.StatusOK, list)

	require.Equal(t, len(ids), list.Size)

	require.Truef(t, containsContainer(list.Containers, cnrID.EncodeToString(), containerName), "list doesn't contain cnr '%s' with name '%s'", cnrID.EncodeToString(), containerName)
}

func containsContainer(containers []apiserver.ContainerInfo, cnrID, cnrName string) bool {
	for _, cnrInfo := range containers {
		if cnrInfo.ContainerId == cnrID {
			for _, attr := range cnrInfo.Attributes {
				if attr.Key == "Name" && attr.Value == cnrName {
					return true
				}
			}

			fmt.Println("container found but name doesn't match")
			return false
		}
	}

	return false
}

func makeAuthTokenRequest(ctx context.Context, t *testing.T, bearers []apiserver.Bearer, httpClient *http.Client, forAllUsers bool) []*handlers.BearerToken {
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	signer := user.NewAutoIDSignerRFC6979(key.PrivateKey)
	ownerID := signer.UserID()

	data, err := json.Marshal(bearers)
	require.NoError(t, err)

	request, err := http.NewRequest(http.MethodPost, testHost+"/v1/auth", bytes.NewReader(data))
	require.NoError(t, err)
	request = request.WithContext(ctx)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(XBearerOwnerID, ownerID.String())
	request.Header.Add(XBearerForAllUsers, strconv.FormatBool(forAllUsers))

	var stokenResp []*apiserver.TokenResponse
	doRequest(t, httpClient, request, http.StatusOK, &stokenResp)

	fmt.Println("resp tokens:")

	respTokens := make([]*handlers.BearerToken, len(stokenResp))
	for i, tok := range stokenResp {
		isObject, err := handlers.IsObjectToken(bearers[i])
		require.NoError(t, err)

		require.Equal(t, bearers[i].Name, *tok.Name)

		if isObject {
			require.Equal(t, apiserver.Object, tok.Type)
		} else {
			require.Equal(t, apiserver.Container, tok.Type)
		}

		binaryData, err := base64.StdEncoding.DecodeString(tok.Token)
		require.NoError(t, err)

		var bt *handlers.BearerToken
		if useWalletConnect {
			bt = signTokenWalletConnect(t, key, binaryData)
		} else {
			bt = signToken(t, key, binaryData)
		}

		respTokens[i] = bt
		fmt.Printf("%+v\n", bt)
	}

	return respTokens
}

func signToken(t *testing.T, key *keys.PrivateKey, data []byte) *handlers.BearerToken {
	signer := neofsecdsa.Signer(key.PrivateKey)
	sign, err := signer.Sign(data)
	require.NoError(t, err)

	return &handlers.BearerToken{
		Token:     base64.StdEncoding.EncodeToString(data),
		Signature: hex.EncodeToString(sign),
		Key:       hex.EncodeToString(key.PublicKey().Bytes()),
	}
}

func signTokenWalletConnect(t *testing.T, key *keys.PrivateKey, data []byte) *handlers.BearerToken {
	signer := neofsecdsa.SignerWalletConnect(key.PrivateKey)
	signature, err := signer.Sign(data)
	require.NoError(t, err)

	return &handlers.BearerToken{
		Token:     base64.StdEncoding.EncodeToString(data),
		Signature: hex.EncodeToString(signature),
		Key:       hex.EncodeToString(key.PublicKey().Bytes()),
	}
}

func restContainerPutInvalid(ctx context.Context, t *testing.T) {
	bearer := apiserver.Bearer{
		Container: &apiserver.Rule{
			Verb: apiserver.VerbPUT,
		},
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	reqURL, err := url.Parse(testHost + "/v1/containers")
	require.NoError(t, err)
	query := reqURL.Query()
	query.Add("name-scope-global", "true")
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	reqURL.RawQuery = query.Encode()

	body, err := json.Marshal(&apiserver.ContainerPostInfo{ContainerName: "nameWithCapitalLetters"})
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPut, reqURL.String(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	resp := &apiserver.ErrorResponse{}
	doRequest(t, httpClient, request, http.StatusInternalServerError, resp)
	require.Equal(t, uint32(0), resp.Code)
	require.Equal(t, apiserver.GW, resp.Type)
}

func restContainerPostInvalid(ctx context.Context, t *testing.T) {
	bearer := apiserver.Bearer{
		Container: &apiserver.Rule{
			Verb: apiserver.VerbPUT,
		},
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	reqURL, err := url.Parse(testHost + "/v1/containers")
	require.NoError(t, err)
	query := reqURL.Query()
	query.Add("name-scope-global", "true")
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	reqURL.RawQuery = query.Encode()

	body, err := json.Marshal(&apiserver.ContainerPostInfo{ContainerName: "nameWithCapitalLetters"})
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, reqURL.String(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	resp := &apiserver.ErrorResponse{}
	doRequest(t, httpClient, request, http.StatusInternalServerError, resp)
	require.Equal(t, uint32(0), resp.Code)
	require.Equal(t, apiserver.GW, resp.Type)
}

func restContainerPut(ctx context.Context, t *testing.T, clientPool *pool.Pool) {
	bearer := apiserver.Bearer{
		Container: &apiserver.Rule{
			Verb: apiserver.VerbPUT,
		},
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	attrKey, attrValue := "User-Attribute", "user value"
	userAttributes := map[string]string{
		attrKey: attrValue,
	}

	// try to create container without name but with name-scope-global
	body, err := json.Marshal(&apiserver.ContainerPostInfo{})
	require.NoError(t, err)

	reqURL, err := url.Parse(testHost + "/v1/containers")
	require.NoError(t, err)
	query := reqURL.Query()
	query.Add("name-scope-global", "true")
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	reqURL.RawQuery = query.Encode()

	request, err := http.NewRequest(http.MethodPut, reqURL.String(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	doRequest(t, httpClient, request, http.StatusInternalServerError, nil)

	// create container with name in local scope
	containerPutInfo := &apiserver.ContainerPostInfo{
		Attributes: []apiserver.Attribute{{
			Key:   attrKey,
			Value: attrValue,
		}},
	}
	body, err = json.Marshal(containerPutInfo)
	require.NoError(t, err)

	reqURL, err = url.Parse(testHost + "/v1/containers")
	require.NoError(t, err)
	query = reqURL.Query()
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	reqURL.RawQuery = query.Encode()

	request, err = http.NewRequest(http.MethodPut, reqURL.String(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	addr := &apiserver.PostContainerOK{}
	doRequest(t, httpClient, request, http.StatusOK, addr)

	var CID cid.ID
	err = CID.DecodeString(addr.ContainerId)
	require.NoError(t, err)
	fmt.Println(CID.String())

	cnr, err := clientPool.ContainerGet(ctx, CID, client.PrmContainerGet{})
	require.NoError(t, err)

	cnrAttr := maps.Collect(cnr.Attributes())

	for key, val := range userAttributes {
		require.Equal(t, val, cnrAttr[key])
	}
}

func restContainerPost(ctx context.Context, t *testing.T, clientPool *pool.Pool) {
	bearer := apiserver.Bearer{
		Container: &apiserver.Rule{
			Verb: apiserver.VerbPUT,
		},
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	attrKey, attrValue := "User-Attribute", "user value"
	userAttributes := map[string]string{
		attrKey: attrValue,
	}

	// try to create container without name but with name-scope-global
	body, err := json.Marshal(&apiserver.ContainerPostInfo{})
	require.NoError(t, err)

	reqURL, err := url.Parse(testHost + "/v1/containers")
	require.NoError(t, err)
	query := reqURL.Query()
	query.Add("name-scope-global", "true")
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	reqURL.RawQuery = query.Encode()

	request, err := http.NewRequest(http.MethodPost, reqURL.String(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	doRequest(t, httpClient, request, http.StatusInternalServerError, nil)

	// create container with name in local scope
	containerPutInfo := &apiserver.ContainerPostInfo{
		Attributes: []apiserver.Attribute{{
			Key:   attrKey,
			Value: attrValue,
		}},
	}
	body, err = json.Marshal(containerPutInfo)
	require.NoError(t, err)

	reqURL, err = url.Parse(testHost + "/v1/containers")
	require.NoError(t, err)
	query = reqURL.Query()
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	reqURL.RawQuery = query.Encode()

	request, err = http.NewRequest(http.MethodPost, reqURL.String(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	addr := &apiserver.PostContainerOK{}
	responseHeaders, _ := doRequest(t, httpClient, request, http.StatusCreated, addr)

	var CID cid.ID
	err = CID.DecodeString(addr.ContainerId)
	require.NoError(t, err)
	fmt.Println(CID.String())
	require.Equal(t, handlers.LocationHeader(CID), responseHeaders.Get("Location"))

	cnr, err := clientPool.ContainerGet(ctx, CID, client.PrmContainerGet{})
	require.NoError(t, err)

	cnrAttr := maps.Collect(cnr.Attributes())

	for key, val := range userAttributes {
		require.Equal(t, val, cnrAttr[key])
	}
}

func prepareCommonHeaders(header http.Header, bearerToken *handlers.BearerToken) {
	header.Add("Content-Type", "application/json")
	header.Add(XBearerSignature, bearerToken.Signature)
	header.Add("Authorization", "Bearer "+bearerToken.Token)
	header.Add(XBearerSignatureKey, bearerToken.Key)
}

func createContainer(ctx context.Context, t *testing.T, clientPool *pool.Pool, owner user.ID, name string, signer user.Signer) cid.ID {
	var policy netmap.PlacementPolicy
	err := policy.DecodeString("REP 1")
	require.NoError(t, err)

	var cnr container.Container
	cnr.Init()
	cnr.SetOwner(owner)
	cnr.SetPlacementPolicy(policy)
	cnr.SetBasicACL(acl.PublicRWExtended)

	cnr.SetName(name)
	cnr.SetCreationTime(time.Now())

	err = client.SyncContainerWithNetwork(ctx, &cnr, clientPool)
	require.NoError(t, err)

	var prm client.PrmContainerPut

	w := waiter.NewContainerPutWaiter(clientPool, waiter.DefaultPollInterval)
	CID, err := w.ContainerPut(ctx, cnr, signer, prm)
	require.NoError(t, err)

	return CID
}

func createObject(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, headers map[string]string, payload []byte, signer user.Signer) oid.ID {
	attributes := make([]object.Attribute, 0, len(headers))

	for key, val := range headers {
		attr := object.NewAttribute(key, val)
		attributes = append(attributes, attr)
	}

	var obj object.Object
	obj.SetOwner(*ownerID)
	obj.SetContainerID(cnrID)
	obj.SetAttributes(attributes...)
	obj.SetPayload(payload)

	info, err := p.NetworkInfo(ctx, client.PrmNetworkInfo{})
	require.NoError(t, err)

	var opts slicer.Options
	if !info.HomomorphicHashingDisabled() {
		opts.CalculateHomomorphicChecksum()
	}

	objID, err := slicer.Put(ctx, p, obj, signer, bytes.NewReader(payload), opts)
	require.NoError(t, err)

	return objID
}

func restrictByEACL(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID cid.ID, signer user.Signer) *eacl.Table {
	var records []eacl.Record
	for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
		record := eacl.ConstructRecord(eacl.ActionDeny, op, []eacl.Target{eacl.NewTargetByRole(eacl.RoleOthers)})
		records = append(records, record)
	}

	var prm client.PrmContainerSetEACL
	w := waiter.NewContainerSetEACLWaiter(clientPool, waiter.DefaultPollInterval)

	table := eacl.NewTableForContainer(cnrID, records)
	err := w.ContainerSetEACL(ctx, table, signer, prm)
	require.NoError(t, err)

	return &table
}

func allowByEACL(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID cid.ID, signer user.Signer) *eacl.Table {
	table := eacl.NewTableForContainer(cnrID, []eacl.Record{})

	var prm client.PrmContainerSetEACL
	w := waiter.NewContainerSetEACLWaiter(clientPool, waiter.DefaultPollInterval)

	err := w.ContainerSetEACL(ctx, table, signer, prm)

	require.NoError(t, err)

	return &table
}

func restBalance(_ context.Context, t *testing.T) {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	reqURL, err := url.Parse(testHost + "/v1/accounting/balance/NPFCqWHfi9ixCJRu7DABRbVfXRbkSEr9Vo")
	require.NoError(t, err)

	request, err := http.NewRequest(http.MethodGet, reqURL.String(), nil)
	require.NoError(t, err)

	resp := &apiserver.Balance{}
	doRequest(t, httpClient, request, http.StatusOK, resp)
	require.Equal(t, "0", resp.Value)
	require.Equal(t, uint32(12), resp.Precision)
}

func restObjectUpload(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID cid.ID, signer user.Signer) {
	restObjectUploadInt(ctx, t, clientPool, cnrID, signer, false)
}
func restObjectUploadCookie(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID cid.ID, signer user.Signer) {
	restObjectUploadInt(ctx, t, clientPool, cnrID, signer, true)
}
func restObjectUploadInt(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID cid.ID, signer user.Signer, cookie bool) {
	bt := apiserver.Bearer{
		Object: []apiserver.Record{
			formAllowRecord(apiserver.OperationPUT),
		},
	}
	bt.Object = append(bt.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bt}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	// check that object bearer token is valid
	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)
	resp := &apiserver.BinaryBearer{}
	doRequest(t, httpClient, request, http.StatusOK, resp)

	actualTokenRaw, err := base64.StdEncoding.DecodeString(resp.Token)
	require.NoError(t, err)

	content := "content of file"
	attrKey, attrValue := "User-Attribute", "user value"

	attributes := map[string]string{
		object.AttributeFileName:    "newFile.txt",
		object.AttributeContentType: "application/octet-stream",
		attrKey:                     attrValue,
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("payload", "newFile.txt")
	_, err = io.Copy(part, bytes.NewReader([]byte(content)))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	request, err = http.NewRequest(http.MethodPost, testHost+"/v1/upload/"+cnrID.String(), body)
	require.NoError(t, err)

	request.Header.Set("Content-Type", writer.FormDataContentType())
	if cookie {
		request.Header.Add("Cookie", "Bearer="+base64.StdEncoding.EncodeToString(actualTokenRaw)+";")
	} else {
		request.Header.Add("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(actualTokenRaw))
	}
	addr := &apiserver.AddressForUpload{}
	doRequest(t, httpClient, request, http.StatusOK, addr)

	var CID cid.ID
	err = CID.DecodeString(addr.ContainerId)
	require.NoError(t, err)

	var id oid.ID
	err = id.DecodeString(addr.ObjectId)
	require.NoError(t, err)

	var prm client.PrmObjectGet
	res, payloadReader, err := clientPool.ObjectGetInit(ctx, CID, id, signer, prm)
	require.NoError(t, err)

	payload := bytes.NewBuffer(nil)
	_, err = io.Copy(payload, payloadReader)
	require.NoError(t, err)
	require.Equal(t, content, payload.String())

	for _, attribute := range res.Attributes() {
		require.Equal(t, attributes[attribute.Key()], attribute.Value(), attribute.Key())
	}
}

func restNewObjectUpload(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID cid.ID, signer user.Signer) {
	restNewObjectUploadInt(ctx, t, clientPool, cnrID, signer, false, false)
}
func restNewObjectUploadCookie(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID cid.ID, signer user.Signer) {
	restNewObjectUploadInt(ctx, t, clientPool, cnrID, signer, true, false)
}
func restNewObjectUploadWC(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID cid.ID, signer user.Signer) {
	restNewObjectUploadInt(ctx, t, clientPool, cnrID, signer, false, true)
}
func restNewObjectUploadInt(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID cid.ID, signer user.Signer, cookie bool, walletConnect bool) {
	bt := apiserver.Bearer{
		Object: []apiserver.Record{
			formAllowRecord(apiserver.OperationPUT),
		},
	}
	bt.Object = append(bt.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bt}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	resp := &apiserver.BinaryBearer{}
	if !walletConnect {
		request, err := http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)
		doRequest(t, httpClient, request, http.StatusOK, resp)
		_, err = base64.StdEncoding.DecodeString(resp.Token)
		require.NoError(t, err)
	}

	content := "content of file"
	attributes := map[string]string{
		object.AttributeFileName:    "newFile.txt",
		object.AttributeContentType: "application/octet-stream",
		"User-Attribute":            "user value",
		"FREE-case-kEy":             "other value",
	}
	attributesJSON, err := json.Marshal(attributes)
	require.NoError(t, err)

	if !walletConnect {
		// Change the query, we only need the `fullBearer` parameter here.
		query = make(url.Values)
		query.Add(fullBearerQuery, "true")
	}
	body := bytes.NewBufferString(content)
	request, err := http.NewRequest(http.MethodPost, testHost+"/v1/objects/"+cnrID.String()+"?"+query.Encode(), body)
	require.NoError(t, err)

	if !walletConnect {
		request.Header.Set("Content-Type", "text/plain")
		if cookie {
			request.Header.Add("Cookie", "Bearer="+resp.Token+";")
		} else {
			request.Header.Add("Authorization", "Bearer "+resp.Token)
		}
	} else {
		prepareCommonHeaders(request.Header, bearerToken)
	}

	request.Header.Set("X-Attributes", string(attributesJSON))
	addr := &apiserver.AddressForUpload{}
	doRequest(t, httpClient, request, http.StatusOK, addr)

	var CID cid.ID
	err = CID.DecodeString(addr.ContainerId)
	require.NoError(t, err)

	var id oid.ID
	err = id.DecodeString(addr.ObjectId)
	require.NoError(t, err)

	var prm client.PrmObjectGet
	res, payloadReader, err := clientPool.ObjectGetInit(ctx, CID, id, signer, prm)
	require.NoError(t, err)

	payload := bytes.NewBuffer(nil)
	_, err = io.Copy(payload, payloadReader)
	require.NoError(t, err)
	require.Equal(t, content, payload.String())

	for _, attribute := range res.Attributes() {
		require.Equal(t, attributes[attribute.Key()], attribute.Value(), attribute.Key())
	}
}

func restNewObjectHead(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer, walletConnect bool) {
	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			formAllowRecord(apiserver.OperationHEAD),
			formAllowRecord(apiserver.OperationRANGE),
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	resp := &apiserver.BinaryBearer{}
	if !walletConnect {
		request, err := http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)
		doRequest(t, httpClient, request, http.StatusOK, resp)
	}

	var (
		content      = []byte("some content")
		fileNameAttr = "head-obj-name-echo"
		attrKey      = "user-attribute"
		attrValue    = "user value"

		attributes = map[string]string{
			object.AttributeFileName:  fileNameAttr,
			object.AttributeTimestamp: strconv.FormatInt(time.Now().Unix(), 10),
			attrKey:                   attrValue,
		}
	)

	if !walletConnect {
		// Change the query, we only need the `fullBearer` parameter here.
		query = make(url.Values)
		query.Add(fullBearerQuery, "true")
	}

	t.Run("head", func(t *testing.T) {
		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		attrTS := getObjectCreateTimestamp(ctx, t, p, cnrID, objID, signer)
		createTS, err := strconv.ParseInt(attrTS, 10, 64)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodHead, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/by_id/"+objID.EncodeToString()+"?"+query.Encode(), nil)
		require.NoError(t, err)

		if !walletConnect {
			request.Header.Set("Authorization", "Bearer "+resp.Token)
		} else {
			prepareCommonHeaders(request.Header, bearerToken)
		}

		headers, _ := doRequest(t, httpClient, request, http.StatusOK, nil)
		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attributes":
				var customAttr map[string]string
				err := json.Unmarshal([]byte(vals[0]), &customAttr)
				require.NoError(t, err)
				require.Equal(t, fileNameAttr, customAttr[object.AttributeFileName])
				require.Equal(t, attrValue, customAttr[attrKey])
				require.Equal(t, strconv.FormatInt(createTS, 10), customAttr[object.AttributeTimestamp])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				require.Equal(t, strconv.FormatInt(int64(len(content)), 10), vals[0])
			case "Content-Type":
				require.Equal(t, "text/plain; charset=utf-8", vals[0])
			case "Date":
				tm, err := time.ParseInLocation(http.TimeFormat, vals[0], time.UTC)
				require.NoError(t, err)
				require.GreaterOrEqual(t, tm.Unix(), createTS)
			case "Access-Control-Allow-Origin":
				require.Equal(t, "*", vals[0])
			}
		}
	})

	t.Run("custom content-type", func(t *testing.T) {
		customContentType := "some/type"
		attributes[object.AttributeContentType] = customContentType

		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		attrTS := getObjectCreateTimestamp(ctx, t, p, cnrID, objID, signer)
		createTS, err := strconv.ParseInt(attrTS, 10, 64)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodHead, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/by_id/"+objID.EncodeToString()+"?"+query.Encode(), nil)
		require.NoError(t, err)

		if !walletConnect {
			request.Header.Set("Authorization", "Bearer "+resp.Token)
		} else {
			prepareCommonHeaders(request.Header, bearerToken)
		}

		headers, _ := doRequest(t, httpClient, request, http.StatusOK, nil)
		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attributes":
				var customAttr map[string]string
				err := json.Unmarshal([]byte(vals[0]), &customAttr)
				require.NoError(t, err)
				require.Equal(t, fileNameAttr, customAttr[object.AttributeFileName])
				require.Equal(t, attrValue, customAttr[attrKey])
				require.Equal(t, strconv.FormatInt(createTS, 10), customAttr[object.AttributeTimestamp])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				require.Equal(t, strconv.FormatInt(int64(len(content)), 10), vals[0])
			case "Content-Type":
				require.Equal(t, customContentType, vals[0])
			case "Date":
				tm, err := time.ParseInLocation(http.TimeFormat, vals[0], time.UTC)
				require.NoError(t, err)
				require.GreaterOrEqual(t, tm.Unix(), createTS)
			case "Access-Control-Allow-Origin":
				require.Equal(t, "*", vals[0])
			}
		}
	})
}

func restNewObjectHeadByAttribute(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer, walletConnect bool) {
	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			formAllowRecord(apiserver.OperationHEAD),
			formAllowRecord(apiserver.OperationRANGE),
			formAllowRecord(apiserver.OperationSEARCH),
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	resp := &apiserver.BinaryBearer{}
	if !walletConnect {
		request, err := http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)
		doRequest(t, httpClient, request, http.StatusOK, resp)
	}

	var (
		content      = []byte("some content")
		fileNameAttr = "new-head-obj-by-attr-name-" + strconv.FormatBool(walletConnect)
		attrKey      = "soME-attribute"
		attrValue    = "user value"
		attributes   = map[string]string{
			object.AttributeFileName:  fileNameAttr,
			object.AttributeTimestamp: strconv.FormatInt(time.Now().Unix(), 10),
			attrKey:                   attrValue,
		}
	)

	if !walletConnect {
		query = make(url.Values)
		query.Add(fullBearerQuery, "true")
	}

	t.Run("head", func(t *testing.T) {
		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		attrTS := getObjectCreateTimestamp(ctx, t, p, cnrID, objID, signer)
		createTS, err := strconv.ParseInt(attrTS, 10, 64)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodHead, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/by_attribute/"+object.AttributeFileName+"/"+fileNameAttr+"?"+query.Encode(), nil)
		require.NoError(t, err)

		if !walletConnect {
			request.Header.Set("Authorization", "Bearer "+resp.Token)
		} else {
			prepareCommonHeaders(request.Header, bearerToken)
		}

		headers, _ := doRequest(t, httpClient, request, http.StatusOK, nil)
		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attributes":
				var customAttr map[string]string
				err := json.Unmarshal([]byte(vals[0]), &customAttr)
				require.NoError(t, err)
				require.Equal(t, fileNameAttr, customAttr[object.AttributeFileName])
				require.Equal(t, attrValue, customAttr[attrKey])
				require.Equal(t, strconv.FormatInt(createTS, 10), customAttr[object.AttributeTimestamp])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				require.Equal(t, strconv.FormatInt(int64(len(content)), 10), vals[0])
			case "Content-Type":
				require.Equal(t, "text/plain; charset=utf-8", vals[0])
			case "Date":
				tm, err := time.ParseInLocation(http.TimeFormat, vals[0], time.UTC)
				require.NoError(t, err)
				require.GreaterOrEqual(t, tm.Unix(), createTS)
			case "Access-Control-Allow-Origin":
				require.Equal(t, "*", vals[0])
			}
		}
	})

	t.Run("head multi-segment path attribute", func(t *testing.T) {
		multiSegmentName := "path/" + fileNameAttr
		attributes[object.AttributeFileName] = multiSegmentName

		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		attrTS := getObjectCreateTimestamp(ctx, t, p, cnrID, objID, signer)
		createTS, err := strconv.ParseInt(attrTS, 10, 64)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodHead, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/by_attribute/"+object.AttributeFileName+"/"+multiSegmentName+"?"+query.Encode(), nil)
		require.NoError(t, err)

		if !walletConnect {
			request.Header.Set("Authorization", "Bearer "+resp.Token)
		} else {
			prepareCommonHeaders(request.Header, bearerToken)
		}

		headers, _ := doRequest(t, httpClient, request, http.StatusOK, nil)
		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attributes":
				var customAttr map[string]string
				err := json.Unmarshal([]byte(vals[0]), &customAttr)
				require.NoError(t, err)
				require.Equal(t, multiSegmentName, customAttr[object.AttributeFileName])
				require.Equal(t, attrValue, customAttr[attrKey])
				require.Equal(t, strconv.FormatInt(createTS, 10), customAttr[object.AttributeTimestamp])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				require.Equal(t, strconv.FormatInt(int64(len(content)), 10), vals[0])
			case "Content-Type":
				require.Equal(t, "text/plain; charset=utf-8", vals[0])
			case "Date":
				tm, err := time.ParseInLocation(http.TimeFormat, vals[0], time.UTC)
				require.NoError(t, err)
				require.GreaterOrEqual(t, tm.Unix(), createTS)
			case "Access-Control-Allow-Origin":
				require.Equal(t, "*", vals[0])
			}
		}
	})
}

func restNewObjectGetByAttribute(ctx context.Context, t *testing.T, p *pool.Pool, ownerID *user.ID, cnrID cid.ID, signer user.Signer, walletConnect, addRange bool) {
	bearer := apiserver.Bearer{
		Object: []apiserver.Record{
			formAllowRecord(apiserver.OperationGET),
			formAllowRecord(apiserver.OperationSEARCH),
			formAllowRecord(apiserver.OperationHEAD),
			formAllowRecord(apiserver.OperationRANGE),
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []apiserver.Bearer{bearer}, httpClient, false)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	resp := &apiserver.BinaryBearer{}
	if !walletConnect {
		request, err := http.NewRequest(http.MethodGet, testHost+"/v1/auth/bearer?"+query.Encode(), nil)
		require.NoError(t, err)
		prepareCommonHeaders(request.Header, bearerToken)
		doRequest(t, httpClient, request, http.StatusOK, resp)
	}

	var (
		content      = []byte("some content")
		fileNameAttr = "new-get-obj-by-attr-name-" + strconv.FormatBool(walletConnect) + strconv.FormatBool(addRange)
		createTS     = time.Now().Unix()
		attrKey      = "user-attribute"
		attrValue    = "user value"
		attributes   = map[string]string{
			object.AttributeFileName:  fileNameAttr,
			object.AttributeTimestamp: strconv.FormatInt(createTS, 10),
			attrKey:                   attrValue,
		}
	)

	t.Run("get", func(t *testing.T) {
		objID := createObject(ctx, t, p, ownerID, cnrID, attributes, content, signer)

		if !walletConnect {
			// Change the query, we only need the `fullBearer` parameter here.
			query = make(url.Values)
			query.Add(fullBearerQuery, "true")
		}

		request, err := http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.EncodeToString()+"/by_attribute/"+object.AttributeFileName+"/"+fileNameAttr+"?"+query.Encode(), nil)
		require.NoError(t, err)

		if !walletConnect {
			request.Header.Set("Authorization", "Bearer "+resp.Token)
		} else {
			prepareCommonHeaders(request.Header, bearerToken)
		}

		start, end := 5, 10
		status := http.StatusOK
		if addRange {
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
			status = http.StatusPartialContent
		}

		headers, rawPayload := doRequest(t, httpClient, request, status, nil)

		require.NotEmpty(t, headers)

		for key, vals := range headers {
			require.Len(t, vals, 1)

			switch key {
			case "X-Attributes":
				var customAttr map[string]string
				err := json.Unmarshal([]byte(vals[0]), &customAttr)
				require.NoError(t, err)
				require.Equal(t, fileNameAttr, customAttr[object.AttributeFileName])
				require.Equal(t, attrValue, customAttr[attrKey])
				require.Equal(t, strconv.FormatInt(createTS, 10), customAttr[object.AttributeTimestamp])
			case "Content-Disposition":
				require.Equal(t, "inline; filename="+fileNameAttr, vals[0])
			case "X-Object-Id":
				require.Equal(t, objID.String(), vals[0])
			case "Last-Modified":
				require.Equal(t, time.Unix(createTS, 0).UTC().Format(http.TimeFormat), vals[0])
			case "X-Owner-Id":
				require.Equal(t, signer.UserID().String(), vals[0])
			case "X-Container-Id":
				require.Equal(t, cnrID.String(), vals[0])
			case "Content-Length":
				if addRange {
					require.Equal(t, strconv.Itoa(end-start+1), vals[0])
				} else {
					require.Equal(t, strconv.Itoa(len(content)), vals[0])
				}
			case "Content-Type":
				require.Equal(t, "text/plain; charset=utf-8", vals[0])
			case "Date":
				tm, err := time.ParseInLocation(http.TimeFormat, vals[0], time.UTC)
				require.NoError(t, err)
				require.GreaterOrEqual(t, tm.Unix(), createTS)
			case "Access-Control-Allow-Origin":
				require.Equal(t, "*", vals[0])
			case "Content-Range":
				require.Equal(t, fmt.Sprintf("bytes %d-%d/%d", start, end, len(content)), vals[0])
			}
		}

		if addRange {
			require.Equal(t, content[start:end+1], rawPayload)
		} else {
			require.Equal(t, content, rawPayload)
		}
	})
}

func getObjectCreateTimestamp(ctx context.Context, t *testing.T, clientPool *pool.Pool, CID cid.ID, id oid.ID, signer user.Signer) string {
	var prm client.PrmObjectGet
	res, payloadReader, err := clientPool.ObjectGetInit(ctx, CID, id, signer, prm)
	require.NoError(t, err)

	payload := bytes.NewBuffer(nil)
	_, err = io.Copy(payload, payloadReader)
	require.NoError(t, err)

	for _, attribute := range res.Attributes() {
		if attribute.Key() == object.AttributeTimestamp {
			return attribute.Value()
		}
	}
	return ""
}
