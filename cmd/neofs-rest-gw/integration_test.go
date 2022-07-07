package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/go-openapi/loads"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
	"github.com/nspcc-dev/neofs-rest-gw/handlers"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	walletconnect "github.com/nspcc-dev/neofs-rest-gw/internal/wallet-connect"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/policy"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
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
	localVersion      = "local"

	walletConnectQuery = "walletConnect"
	// XBearerSignature header contains base64 encoded signature of the token body.
	XBearerSignature = "X-Bearer-Signature"
	// XBearerSignatureKey header contains hex encoded public key that corresponds the signature of the token body.
	XBearerSignatureKey = "X-Bearer-Signature-Key"
	// XBearerOwnerID header contains owner id (wallet address) that corresponds the signature of the token body.
	XBearerOwnerID = "X-Bearer-Owner-Id"

	// tests configuration.
	useWalletConnect    = false
	useLocalEnvironment = false
)

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
	runTests(ctx, t, key, localVersion)
}

func runTestInContainer(rootCtx context.Context, t *testing.T, key *keys.PrivateKey) {
	aioImage := "nspccdev/neofs-aio-testcontainer:"
	versions := []string{
		//"0.24.0",
		//"0.25.1",
		//"0.26.1",
		//"0.27.5",
		"0.27.7",
		//"latest",
	}

	for _, version := range versions {
		ctx, cancel := context.WithCancel(rootCtx)
		aioContainer := createDockerContainer(ctx, t, aioImage+version)

		runTests(ctx, t, key, version)

		err := aioContainer.Terminate(ctx)
		require.NoError(t, err)
		cancel()
		<-ctx.Done()
	}
}

func runTests(ctx context.Context, t *testing.T, key *keys.PrivateKey, version string) {
	node := testContainerNode
	if version == localVersion {
		node = testLocalNode
	}

	cancel := runServer(ctx, t, node)
	defer cancel()

	clientPool := getPool(ctx, t, key, node)
	cnrID := createContainer(ctx, t, clientPool, containerName)
	restrictByEACL(ctx, t, clientPool, cnrID)

	t.Run("rest auth several tokens "+version, func(t *testing.T) { authTokens(ctx, t) })

	t.Run("rest put object "+version, func(t *testing.T) { restObjectPut(ctx, t, clientPool, cnrID) })
	t.Run("rest get object "+version, func(t *testing.T) { restObjectGet(ctx, t, clientPool, cnrID) })
	t.Run("rest delete object "+version, func(t *testing.T) { restObjectDelete(ctx, t, clientPool, cnrID) })
	t.Run("rest search objects "+version, func(t *testing.T) { restObjectsSearch(ctx, t, clientPool, cnrID) })

	t.Run("rest put container "+version, func(t *testing.T) { restContainerPut(ctx, t, clientPool) })
	t.Run("rest get container "+version, func(t *testing.T) { restContainerGet(ctx, t, clientPool, cnrID) })
	t.Run("rest delete container "+version, func(t *testing.T) { restContainerDelete(ctx, t, clientPool) })
	t.Run("rest put container eacl "+version, func(t *testing.T) { restContainerEACLPut(ctx, t, clientPool) })
	t.Run("rest get container eacl "+version, func(t *testing.T) { restContainerEACLGet(ctx, t, clientPool, cnrID) })
	t.Run("rest list containers	"+version, func(t *testing.T) { restContainerList(ctx, t, clientPool, cnrID) })
}

func createDockerContainer(ctx context.Context, t *testing.T, image string) testcontainers.Container {
	req := testcontainers.ContainerRequest{
		Image:       image,
		WaitingFor:  wait.NewLogStrategy("aio container started").WithStartupTimeout(30 * time.Second),
		Name:        "aio",
		Hostname:    "aio",
		NetworkMode: "host",
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

	swaggerSpec, err := loads.Analyzed(restapi.SwaggerJSON, "")
	require.NoError(t, err)

	api := operations.NewNeofsRestGwAPI(swaggerSpec)
	server := restapi.NewServer(api, serverConfig(v))

	server.ConfigureAPI(neofsAPI.Configure)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	return func() {
		cancel()
		err := server.Shutdown()
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
	v.SetDefault(restapi.FlagListenAddress, testListenAddress)
	v.SetDefault(restapi.FlagWriteTimeout, 60*time.Second)

	return v
}

func getPool(ctx context.Context, t *testing.T, key *keys.PrivateKey, node string) *pool.Pool {
	var prm pool.InitParameters
	prm.AddNode(pool.NewNodeParam(1, node, 1))
	prm.SetKey(&key.PrivateKey)
	prm.SetHealthcheckTimeout(5 * time.Second)
	prm.SetNodeDialTimeout(5 * time.Second)

	clientPool, err := pool.NewPool(prm)
	require.NoError(t, err)
	err = clientPool.Dial(ctx)
	require.NoError(t, err)

	return clientPool
}

func getRestrictBearerRecords() []*models.Record {
	return []*models.Record{
		formRestrictRecord(models.OperationGET),
		formRestrictRecord(models.OperationHEAD),
		formRestrictRecord(models.OperationPUT),
		formRestrictRecord(models.OperationDELETE),
		formRestrictRecord(models.OperationSEARCH),
		formRestrictRecord(models.OperationRANGE),
		formRestrictRecord(models.OperationRANGEHASH),
	}
}

func formRestrictRecord(op models.Operation) *models.Record {
	return &models.Record{
		Operation: models.NewOperation(op),
		Action:    models.NewAction(models.ActionDENY),
		Filters:   []*models.Filter{},
		Targets: []*models.Target{{
			Role: models.NewRole(models.RoleOTHERS),
			Keys: []string{},
		}}}
}

func authTokens(ctx context.Context, t *testing.T) {
	bearers := []*models.Bearer{
		{
			Name: "all-object",
			Object: []*models.Record{{
				Operation: models.NewOperation(models.OperationPUT),
				Action:    models.NewAction(models.ActionALLOW),
				Filters:   []*models.Filter{},
				Targets: []*models.Target{{
					Role: models.NewRole(models.RoleOTHERS),
					Keys: []string{},
				}},
			}},
		},
		{
			Name: "put-container",
			Container: &models.Rule{
				Verb: models.NewVerb(models.VerbPUT),
			},
		},
		{
			Name: "seteacl-container",
			Container: &models.Rule{
				Verb: models.NewVerb(models.VerbSETEACL),
			},
		},
		{
			Name: "delete-container",
			Container: &models.Rule{
				Verb: models.NewVerb(models.VerbDELETE),
			},
		},
	}

	httpClient := defaultHTTPClient()
	makeAuthTokenRequest(ctx, t, bearers, httpClient)
}

func restObjectPut(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID *cid.ID) {
	bearer := &models.Bearer{
		Object: []*models.Record{{
			Operation: models.NewOperation(models.OperationPUT),
			Action:    models.NewAction(models.ActionALLOW),
			Filters:   []*models.Filter{},
			Targets: []*models.Target{{
				Role: models.NewRole(models.RoleOTHERS),
				Keys: []string{},
			}},
		}},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []*models.Bearer{bearer}, httpClient)
	bearerToken := bearerTokens[0]

	content := "content of file"
	attrKey, attrValue := "User-Attribute", "user value"

	attributes := map[string]string{
		object.AttributeFileName: "newFile.txt",
		attrKey:                  attrValue,
	}

	req := &models.ObjectUpload{
		ContainerID: util.NewString(cnrID.String()),
		FileName:    util.NewString("newFile.txt"),
		Payload:     base64.StdEncoding.EncodeToString([]byte(content)),
		Attributes: []*models.Attribute{{
			Key:   &attrKey,
			Value: &attrValue,
		}},
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodPut, testHost+"/v1/objects?"+query.Encode(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	addr := &models.Address{}
	doRequest(t, httpClient, request, http.StatusOK, addr)

	var CID cid.ID
	err = CID.Parse(*addr.ContainerID)
	require.NoError(t, err)
	var id oid.ID
	err = id.Parse(*addr.ObjectID)
	require.NoError(t, err)
	objectAddress := address.NewAddress()
	objectAddress.SetContainerID(&CID)
	objectAddress.SetObjectID(&id)

	var prm pool.PrmObjectGet
	prm.SetAddress(*objectAddress)
	res, err := clientPool.GetObject(ctx, prm)
	require.NoError(t, err)

	payload := bytes.NewBuffer(nil)
	_, err = io.Copy(payload, res.Payload)
	require.NoError(t, err)
	require.Equal(t, content, payload.String())

	for _, attribute := range res.Header.Attributes() {
		require.Equal(t, attributes[attribute.Key()], attribute.Value(), attribute.Key())
	}
}

func restObjectGet(ctx context.Context, t *testing.T, p *pool.Pool, cnrID *cid.ID) {
	content := []byte("some content")
	attributes := map[string]string{
		object.AttributeFileName: "get-obj-name",
		"user-attribute":         "user value",
	}

	objID := createObject(ctx, t, p, cnrID, attributes, content)

	bearer := &models.Bearer{
		Object: []*models.Record{
			{
				Operation: models.NewOperation(models.OperationHEAD),
				Action:    models.NewAction(models.ActionALLOW),
				Filters:   []*models.Filter{},
				Targets: []*models.Target{{
					Role: models.NewRole(models.RoleOTHERS),
					Keys: []string{},
				}},
			},
			{
				Operation: models.NewOperation(models.OperationRANGE),
				Action:    models.NewAction(models.ActionALLOW),
				Filters:   []*models.Filter{},
				Targets: []*models.Target{{
					Role: models.NewRole(models.RoleOTHERS),
					Keys: []string{},
				}},
			},
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []*models.Bearer{bearer}, httpClient)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.String()+"/"+objID.String()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	objInfo := &models.ObjectInfo{}
	doRequest(t, httpClient, request, http.StatusOK, objInfo)

	require.Equal(t, cnrID.String(), *objInfo.ContainerID)
	require.Equal(t, objID.String(), *objInfo.ObjectID)
	require.Equal(t, p.OwnerID().String(), *objInfo.OwnerID)
	require.Equal(t, len(attributes), len(objInfo.Attributes))
	require.Equal(t, int64(len(content)), *objInfo.ObjectSize)

	contentData, err := base64.StdEncoding.DecodeString(objInfo.Payload)
	require.NoError(t, err)
	require.Equal(t, content, contentData)

	for _, attr := range objInfo.Attributes {
		require.Equal(t, attributes[*attr.Key], *attr.Value)
	}

	// check max-payload-size params
	query = make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	query.Add("max-payload-size", "0")

	request, err = http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.String()+"/"+objID.String()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	objInfo = &models.ObjectInfo{}
	doRequest(t, httpClient, request, http.StatusOK, objInfo)
	require.Empty(t, objInfo.Payload)
	require.Equal(t, int64(0), *objInfo.PayloadSize)

	// check range params
	rangeLength := 4
	query = make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	query.Add("range-offset", "0")
	query.Add("range-length", strconv.Itoa(rangeLength))

	request, err = http.NewRequest(http.MethodGet, testHost+"/v1/objects/"+cnrID.String()+"/"+objID.String()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	objInfo = &models.ObjectInfo{}
	doRequest(t, httpClient, request, http.StatusOK, objInfo)
	require.Equal(t, int64(rangeLength), *objInfo.PayloadSize)

	contentData, err = base64.StdEncoding.DecodeString(objInfo.Payload)
	require.NoError(t, err)
	require.Equal(t, content[:rangeLength], contentData)
}

func restObjectDelete(ctx context.Context, t *testing.T, p *pool.Pool, cnrID *cid.ID) {
	objID := createObject(ctx, t, p, cnrID, nil, []byte("some content"))

	bearer := &models.Bearer{
		Object: []*models.Record{{
			Operation: models.NewOperation(models.OperationDELETE),
			Action:    models.NewAction(models.ActionALLOW),
			Filters:   []*models.Filter{},
			Targets: []*models.Target{{
				Role: models.NewRole(models.RoleOTHERS),
				Keys: []string{},
			}},
		}},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []*models.Bearer{bearer}, httpClient)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodDelete, testHost+"/v1/objects/"+cnrID.String()+"/"+objID.String()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	resp := &models.SuccessResponse{}
	doRequest(t, httpClient, request, http.StatusOK, resp)
	require.True(t, *resp.Success)

	var addr address.Address
	addr.SetContainerID(cnrID)
	addr.SetObjectID(objID)

	var prm pool.PrmObjectHead
	prm.SetAddress(addr)

	_, err = p.HeadObject(ctx, prm)
	require.Error(t, err)
}

func restObjectsSearch(ctx context.Context, t *testing.T, p *pool.Pool, cnrID *cid.ID) {
	userKey, userValue := "User-Attribute", "user-attribute-value"
	objectName := "object-name"
	headers := map[string]string{
		object.AttributeFileName: objectName,
		userKey:                  userValue,
	}
	objID := createObject(ctx, t, p, cnrID, headers, []byte("some content"))
	headers[userKey] = "dummy"
	_ = createObject(ctx, t, p, cnrID, headers, []byte("some content"))

	bearer := &models.Bearer{
		Object: []*models.Record{
			{
				Operation: models.NewOperation(models.OperationSEARCH),
				Action:    models.NewAction(models.ActionALLOW),
				Filters:   []*models.Filter{},
				Targets:   []*models.Target{{Role: models.NewRole(models.RoleOTHERS), Keys: []string{}}},
			},
			{
				Operation: models.NewOperation(models.OperationHEAD),
				Action:    models.NewAction(models.ActionALLOW),
				Filters:   []*models.Filter{},
				Targets:   []*models.Target{{Role: models.NewRole(models.RoleOTHERS), Keys: []string{}}},
			},
			{
				Operation: models.NewOperation(models.OperationGET),
				Action:    models.NewAction(models.ActionALLOW),
				Filters:   []*models.Filter{},
				Targets:   []*models.Target{{Role: models.NewRole(models.RoleOTHERS), Keys: []string{}}},
			},
		},
	}
	bearer.Object = append(bearer.Object, getRestrictBearerRecords()...)

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []*models.Bearer{bearer}, httpClient)
	bearerToken := bearerTokens[0]

	search := &models.SearchFilters{
		Filters: []*models.SearchFilter{
			{
				Key:   util.NewString(userKey),
				Match: models.NewSearchMatch(models.SearchMatchMatchStringEqual),
				Value: util.NewString(userValue),
			},
		},
	}

	body, err := json.Marshal(search)
	require.NoError(t, err)

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodPost, testHost+"/v1/objects/"+cnrID.String()+"/search?"+query.Encode(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)

	resp := &models.ObjectList{}
	doRequest(t, httpClient, request, http.StatusOK, resp)

	require.Equal(t, 1, int(*resp.Size))
	require.Len(t, resp.Objects, 1)

	objBaseInfo := resp.Objects[0]
	require.Equal(t, cnrID.String(), *objBaseInfo.Address.ContainerID)
	require.Equal(t, objID.String(), *objBaseInfo.Address.ObjectID)
	require.Equal(t, objectName, objBaseInfo.Name)
}

func doRequest(t *testing.T, httpClient *http.Client, request *http.Request, expectedCode int, model interface{}) {
	resp, err := httpClient.Do(request)
	require.NoError(t, err)
	defer func() {
		err := resp.Body.Close()
		require.NoError(t, err)
	}()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if expectedCode != resp.StatusCode {
		fmt.Println("resp", string(respBody))
	}
	require.Equal(t, expectedCode, resp.StatusCode)

	if model == nil {
		return
	}

	err = json.Unmarshal(respBody, model)
	require.NoError(t, err)
}

func restContainerGet(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID *cid.ID) {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/containers/"+cnrID.String(), nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)

	cnrInfo := &models.ContainerInfo{}
	doRequest(t, httpClient, request, http.StatusOK, cnrInfo)

	require.Equal(t, cnrID.String(), *cnrInfo.ContainerID)
	require.Equal(t, clientPool.OwnerID().String(), *cnrInfo.OwnerID)
}

func restContainerDelete(ctx context.Context, t *testing.T, clientPool *pool.Pool) {
	cnrID := createContainer(ctx, t, clientPool, "for-delete")

	bearer := &models.Bearer{
		Container: &models.Rule{
			Verb: models.NewVerb(models.VerbDELETE),
		},
	}

	httpClient := defaultHTTPClient()
	bearerTokens := makeAuthTokenRequest(ctx, t, []*models.Bearer{bearer}, httpClient)
	bearerToken := bearerTokens[0]

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodDelete, testHost+"/v1/containers/"+cnrID.String()+"?"+query.Encode(), nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)
	prepareCommonHeaders(request.Header, bearerToken)

	resp := &models.SuccessResponse{}
	doRequest(t, httpClient, request, http.StatusOK, resp)
	require.True(t, *resp.Success)

	var prm pool.PrmContainerGet
	prm.SetContainerID(*cnrID)

	_, err = clientPool.GetContainer(ctx, prm)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func restContainerEACLPut(ctx context.Context, t *testing.T, clientPool *pool.Pool) {
	cnrID := createContainer(ctx, t, clientPool, "for-eacl-put")
	httpClient := &http.Client{Timeout: 60 * time.Second}
	bearer := &models.Bearer{
		Container: &models.Rule{
			Verb: models.NewVerb(models.VerbSETEACL),
		},
	}
	bearerTokens := makeAuthTokenRequest(ctx, t, []*models.Bearer{bearer}, httpClient)
	bearerToken := bearerTokens[0]

	req := models.Eacl{
		Records: []*models.Record{{
			Action:    models.NewAction(models.ActionDENY),
			Filters:   []*models.Filter{},
			Operation: models.NewOperation(models.OperationDELETE),
			Targets: []*models.Target{{
				Keys: []string{},
				Role: models.NewRole(models.RoleOTHERS),
			}},
		}},
	}

	body, err := json.Marshal(&req)
	require.NoError(t, err)

	query := make(url.Values)
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))

	request, err := http.NewRequest(http.MethodPut, testHost+"/v1/containers/"+cnrID.String()+"/eacl?"+query.Encode(), bytes.NewReader(body))
	require.NoError(t, err)
	request = request.WithContext(ctx)
	prepareCommonHeaders(request.Header, bearerToken)

	resp := &models.SuccessResponse{}
	doRequest(t, httpClient, request, http.StatusOK, resp)
	require.True(t, *resp.Success)

	var prm pool.PrmContainerEACL
	prm.SetContainerID(*cnrID)

	table, err := clientPool.GetEACL(ctx, prm)
	require.NoError(t, err)

	expectedTable, err := util.ToNativeTable(req.Records)
	require.NoError(t, err)
	expectedTable.SetCID(cnrID)

	require.True(t, eacl.EqualTables(*expectedTable, *table))
}

func restContainerEACLGet(ctx context.Context, t *testing.T, p *pool.Pool, cnrID *cid.ID) {
	var prm pool.PrmContainerEACL
	prm.SetContainerID(*cnrID)
	expectedTable, err := p.GetEACL(ctx, prm)
	require.NoError(t, err)

	httpClient := &http.Client{Timeout: 60 * time.Second}

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/containers/"+cnrID.String()+"/eacl", nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)

	responseTable := &models.Eacl{}
	doRequest(t, httpClient, request, http.StatusOK, responseTable)

	require.Equal(t, cnrID.String(), responseTable.ContainerID)

	actualTable, err := util.ToNativeTable(responseTable.Records)
	require.NoError(t, err)
	actualTable.SetCID(cnrID)

	require.True(t, eacl.EqualTables(*expectedTable, *actualTable))
}

func restContainerList(ctx context.Context, t *testing.T, p *pool.Pool, cnrID *cid.ID) {
	var prm pool.PrmContainerList
	prm.SetOwnerID(*p.OwnerID())

	ids, err := p.ListContainers(ctx, prm)
	require.NoError(t, err)

	httpClient := defaultHTTPClient()

	query := make(url.Values)
	query.Add("ownerId", p.OwnerID().String())

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/containers?"+query.Encode(), nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)

	list := &models.ContainerList{}
	doRequest(t, httpClient, request, http.StatusOK, list)

	require.Equal(t, len(ids), int(*list.Size))

	expected := &models.ContainerBaseInfo{
		ContainerID: util.NewString(cnrID.String()),
		Name:        containerName,
	}

	require.Contains(t, list.Containers, expected)
}

func makeAuthTokenRequest(ctx context.Context, t *testing.T, bearers []*models.Bearer, httpClient *http.Client) []*handlers.BearerToken {
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	ownerID := owner.NewIDFromPublicKey((*ecdsa.PublicKey)(key.PublicKey()))

	data, err := json.Marshal(bearers)
	require.NoError(t, err)

	request, err := http.NewRequest(http.MethodPost, testHost+"/v1/auth", bytes.NewReader(data))
	require.NoError(t, err)
	request = request.WithContext(ctx)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(XBearerOwnerID, ownerID.String())

	resp, err := httpClient.Do(request)
	require.NoError(t, err)
	defer func() {
		err := resp.Body.Close()
		require.NoError(t, err)
	}()

	rr, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("auth response", string(rr))
	}
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var stokenResp []*models.TokenResponse
	err = json.Unmarshal(rr, &stokenResp)
	require.NoError(t, err)

	fmt.Println("resp tokens:")

	respTokens := make([]*handlers.BearerToken, len(stokenResp))
	for i, tok := range stokenResp {
		isObject, err := handlers.IsObjectToken(bearers[i])
		require.NoError(t, err)

		require.Equal(t, bearers[i].Name, tok.Name)

		if isObject {
			require.Equal(t, models.TokenTypeObject, *tok.Type)
		} else {
			require.Equal(t, models.TokenTypeContainer, *tok.Type)
		}

		binaryData, err := base64.StdEncoding.DecodeString(*tok.Token)
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
	h := sha512.Sum512(data)
	x, y, err := ecdsa.Sign(rand.Reader, &key.PrivateKey, h[:])
	require.NoError(t, err)
	sign := elliptic.Marshal(elliptic.P256(), x, y)

	return &handlers.BearerToken{
		Token:     base64.StdEncoding.EncodeToString(data),
		Signature: hex.EncodeToString(sign),
		Key:       hex.EncodeToString(key.PublicKey().Bytes()),
	}
}

func signTokenWalletConnect(t *testing.T, key *keys.PrivateKey, data []byte) *handlers.BearerToken {
	sm, err := walletconnect.SignMessage(&key.PrivateKey, data[:])
	require.NoError(t, err)

	return &handlers.BearerToken{
		Token:     base64.StdEncoding.EncodeToString(data),
		Signature: hex.EncodeToString(append(sm.Data, sm.Salt...)),
		Key:       hex.EncodeToString(key.PublicKey().Bytes()),
	}
}

func restContainerPut(ctx context.Context, t *testing.T, clientPool *pool.Pool) {
	bearer := &models.Bearer{
		Container: &models.Rule{
			Verb: models.NewVerb(models.VerbPUT),
		},
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	bearerTokens := makeAuthTokenRequest(ctx, t, []*models.Bearer{bearer}, httpClient)
	bearerToken := bearerTokens[0]

	attrKey, attrValue := "User-Attribute", "user value"
	userAttributes := map[string]string{
		attrKey: attrValue,
	}

	// try to create container without name but with name-scope-global
	body, err := json.Marshal(&operations.PutContainerBody{})
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

	doRequest(t, httpClient, request, http.StatusBadRequest, nil)

	// create container with name in local scope
	body, err = json.Marshal(&operations.PutContainerBody{})
	require.NoError(t, err)

	reqURL, err = url.Parse(testHost + "/v1/containers")
	require.NoError(t, err)
	query = reqURL.Query()
	query.Add(walletConnectQuery, strconv.FormatBool(useWalletConnect))
	reqURL.RawQuery = query.Encode()

	request, err = http.NewRequest(http.MethodPut, reqURL.String(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)
	request.Header.Add("X-Attribute-"+attrKey, attrValue)

	addr := &operations.PutContainerOKBody{}
	doRequest(t, httpClient, request, http.StatusOK, addr)

	var CID cid.ID
	err = CID.Parse(*addr.ContainerID)
	require.NoError(t, err)
	fmt.Println(CID.String())

	var prm pool.PrmContainerGet
	prm.SetContainerID(CID)

	cnr, err := clientPool.GetContainer(ctx, prm)
	require.NoError(t, err)

	cnrAttr := make(map[string]string, len(cnr.Attributes()))
	for _, attribute := range cnr.Attributes() {
		cnrAttr[attribute.Key()] = attribute.Value()
	}

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

func createContainer(ctx context.Context, t *testing.T, clientPool *pool.Pool, name string) *cid.ID {
	pp, err := policy.Parse("REP 1")
	require.NoError(t, err)

	cnr := container.New(
		container.WithPolicy(pp),
		container.WithCustomBasicACL(0x0FFFFFFF),
		container.WithAttribute(container.AttributeName, name),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10)))
	cnr.SetOwnerID(clientPool.OwnerID())

	var waitPrm pool.WaitParams
	waitPrm.SetPollInterval(3 * time.Second)
	waitPrm.SetTimeout(15 * time.Second)

	var prm pool.PrmContainerPut
	prm.SetContainer(*cnr)
	prm.SetWaitParams(waitPrm)

	CID, err := clientPool.PutContainer(ctx, prm)
	require.NoError(t, err)

	return CID
}

func createObject(ctx context.Context, t *testing.T, p *pool.Pool, cnrID *cid.ID, headers map[string]string, payload []byte) *oid.ID {
	attributes := make([]object.Attribute, 0, len(headers))

	for key, val := range headers {
		attr := object.NewAttribute()
		attr.SetKey(key)
		attr.SetValue(val)
		attributes = append(attributes, *attr)
	}

	obj := object.New()
	obj.SetOwnerID(p.OwnerID())
	obj.SetContainerID(cnrID)
	obj.SetAttributes(attributes...)
	obj.SetPayload(payload)

	var prm pool.PrmObjectPut
	prm.SetHeader(*obj)

	objID, err := p.PutObject(ctx, prm)
	require.NoError(t, err)

	return objID
}

func restrictByEACL(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID *cid.ID) *eacl.Table {
	table := eacl.NewTable()
	table.SetCID(cnrID)

	for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
		record := new(eacl.Record)
		record.SetOperation(op)
		record.SetAction(eacl.ActionDeny)
		target := new(eacl.Target)
		target.SetRole(eacl.RoleOthers)
		record.SetTargets(*target)
		table.AddRecord(record)
	}

	var waitPrm pool.WaitParams
	waitPrm.SetPollInterval(3 * time.Second)
	waitPrm.SetTimeout(15 * time.Second)

	var prm pool.PrmContainerSetEACL
	prm.SetTable(*table)
	prm.SetWaitParams(waitPrm)

	err := clientPool.SetEACL(ctx, prm)
	require.NoError(t, err)

	return table
}
