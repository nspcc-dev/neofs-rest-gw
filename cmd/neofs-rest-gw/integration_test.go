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
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
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
	testNode          = "localhost:8080"

	// XNeofsTokenSignature header contains base64 encoded signature of the token body.
	XNeofsTokenSignature = "X-Neofs-Token-Signature"
	// XNeofsTokenSignatureKey header contains hex encoded public key that corresponds the signature of the token body.
	XNeofsTokenSignatureKey = "X-Neofs-Token-Signature-Key"
	// XNeofsTokenScope header contains operation scope for auth (bearer) token.
	// It corresponds to 'object' or 'container' services in neofs.
	XNeofsTokenScope = "X-Neofs-Token-Scope"
)

func TestIntegration(t *testing.T) {
	rootCtx := context.Background()
	aioImage := "nspccdev/neofs-aio-testcontainer:"
	versions := []string{
		//"0.24.0",
		//"0.25.1",
		//"0.26.1",
		"0.27.5",
		"latest",
	}
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	for _, version := range versions {
		ctx, cancel2 := context.WithCancel(rootCtx)

		aioContainer := createDockerContainer(ctx, t, aioImage+version)
		cancel := runServer(ctx, t)
		clientPool := getPool(ctx, t, key)
		cnrID := createContainer(ctx, t, clientPool, "test-container")

		t.Run("rest put object "+version, func(t *testing.T) { restObjectPut(ctx, t, clientPool, cnrID) })

		t.Run("rest put container"+version, func(t *testing.T) { restContainerPut(ctx, t, clientPool) })
		t.Run("rest get container"+version, func(t *testing.T) { restContainerGet(ctx, t, clientPool, cnrID) })
		t.Run("rest delete container"+version, func(t *testing.T) { restContainerDelete(ctx, t, clientPool) })
		t.Run("rest put container eacl	"+version, func(t *testing.T) { restContainerEACLPut(ctx, t, clientPool) })
		t.Run("rest get container eacl	"+version, func(t *testing.T) { restContainerEACLGet(ctx, t, clientPool) })

		cancel()
		err = aioContainer.Terminate(ctx)
		require.NoError(t, err)
		cancel2()
		<-ctx.Done()
	}
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

func runServer(ctx context.Context, t *testing.T) context.CancelFunc {
	cancelCtx, cancel := context.WithCancel(ctx)

	v := getDefaultConfig()
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

func getDefaultConfig() *viper.Viper {
	v := config()
	v.SetDefault(cfgPeers+".0.address", testNode)
	v.SetDefault(cfgPeers+".0.weight", 1)
	v.SetDefault(cfgPeers+".0.priority", 1)
	v.SetDefault(restapi.FlagListenAddress, testListenAddress)
	v.SetDefault(restapi.FlagWriteTimeout, 60*time.Second)

	return v
}

func getPool(ctx context.Context, t *testing.T, key *keys.PrivateKey) *pool.Pool {
	var prm pool.InitParameters
	prm.AddNode(pool.NewNodeParam(1, testNode, 1))
	prm.SetKey(&key.PrivateKey)
	prm.SetHealthcheckTimeout(5 * time.Second)
	prm.SetNodeDialTimeout(5 * time.Second)

	clientPool, err := pool.NewPool(prm)
	require.NoError(t, err)
	err = clientPool.Dial(ctx)
	require.NoError(t, err)

	return clientPool
}

func restObjectPut(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID *cid.ID) {
	restrictByEACL(ctx, t, clientPool, cnrID)

	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	b := models.Bearer{
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

	data, err := json.Marshal(&b)
	require.NoError(t, err)

	request0, err := http.NewRequest(http.MethodPost, testHost+"/v1/auth", bytes.NewReader(data))
	require.NoError(t, err)
	request0.Header.Add("Content-Type", "application/json")
	request0.Header.Add(XNeofsTokenScope, string(models.TokenTypeObject))
	request0.Header.Add(XNeofsTokenSignatureKey, hex.EncodeToString(key.PublicKey().Bytes()))

	httpClient := http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Do(request0)
	require.NoError(t, err)
	defer resp.Body.Close()

	rr, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	fmt.Println(string(rr))

	require.Equal(t, http.StatusOK, resp.StatusCode)

	stokenResp := &models.TokenResponse{}
	err = json.Unmarshal(rr, stokenResp)
	require.NoError(t, err)

	require.Equal(t, *stokenResp.Type, models.TokenTypeObject)

	bearerBase64 := stokenResp.Token
	fmt.Println(*bearerBase64)
	binaryData, err := base64.StdEncoding.DecodeString(*bearerBase64)
	require.NoError(t, err)

	signatureData := signData(t, key, binaryData)

	content := "content of file"
	attrKey, attrValue := "User-Attribute", "user value"

	attributes := map[string]string{
		object.AttributeFileName: "newFile.txt",
		attrKey:                  attrValue,
	}

	req := operations.PutObjectBody{
		ContainerID: handlers.NewString(cnrID.String()),
		FileName:    handlers.NewString("newFile.txt"),
		Payload:     base64.StdEncoding.EncodeToString([]byte(content)),
	}

	body, err := json.Marshal(&req)
	require.NoError(t, err)

	fmt.Println(base64.StdEncoding.EncodeToString(signatureData))
	fmt.Println(hex.EncodeToString(key.PublicKey().Bytes()))

	request, err := http.NewRequest(http.MethodPut, testHost+"/v1/objects", bytes.NewReader(body))
	require.NoError(t, err)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(XNeofsTokenSignature, base64.StdEncoding.EncodeToString(signatureData))
	request.Header.Add("Authorization", "Bearer "+*bearerBase64)
	request.Header.Add(XNeofsTokenSignatureKey, hex.EncodeToString(key.PublicKey().Bytes()))
	request.Header.Add("X-Attribute-"+attrKey, attrValue)

	resp2, err := httpClient.Do(request)
	require.NoError(t, err)
	defer resp2.Body.Close()

	rr2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)

	fmt.Println(string(rr2))
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	addr := &operations.PutObjectOKBody{}
	err = json.Unmarshal(rr2, addr)
	require.NoError(t, err)

	var CID cid.ID
	err = CID.Parse(*addr.ContainerID)
	require.NoError(t, err)

	id := oid.NewID()
	err = id.Parse(*addr.ObjectID)
	require.NoError(t, err)

	objectAddress := address.NewAddress()
	objectAddress.SetContainerID(&CID)
	objectAddress.SetObjectID(id)

	payload := bytes.NewBuffer(nil)

	var prm pool.PrmObjectGet
	prm.SetAddress(*objectAddress)

	res, err := clientPool.GetObject(ctx, prm)
	require.NoError(t, err)

	_, err = io.Copy(payload, res.Payload)
	require.NoError(t, err)

	require.Equal(t, content, payload.String())

	for _, attribute := range res.Header.Attributes() {
		require.Equal(t, attributes[attribute.Key()], attribute.Value(), attribute.Key())
	}
}

func restContainerGet(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID *cid.ID) {
	httpClient := http.Client{Timeout: 5 * time.Second}
	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/containers/"+cnrID.String(), nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)

	resp, err := httpClient.Do(request)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	cnrInfo := &models.ContainerInfo{}
	err = json.NewDecoder(resp.Body).Decode(cnrInfo)
	require.NoError(t, err)

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

	httpClient := &http.Client{Timeout: 60 * time.Second}

	bearerToken := makeAuthContainerTokenRequest(ctx, t, bearer, httpClient)

	request, err := http.NewRequest(http.MethodDelete, testHost+"/v1/containers/"+cnrID.String(), nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)
	prepareCommonHeaders(request.Header, bearerToken)

	resp, err := httpClient.Do(request)
	require.NoError(t, err)
	defer func() {
		err := resp.Body.Close()
		require.NoError(t, err)
	}()
	if resp.StatusCode != http.StatusNoContent {
		fmt.Println("resp", resp.Status)
		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		fmt.Println(string(respBody))
	}
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

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
	bearerToken := makeAuthContainerTokenRequest(ctx, t, bearer, httpClient)

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

	request, err := http.NewRequest(http.MethodPut, testHost+"/v1/containers/"+cnrID.String()+"/eacl", bytes.NewReader(body))
	require.NoError(t, err)
	request = request.WithContext(ctx)
	prepareCommonHeaders(request.Header, bearerToken)

	resp, err := httpClient.Do(request)
	require.NoError(t, err)
	defer func() {
		err := resp.Body.Close()
		require.NoError(t, err)
	}()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("resp", resp.Status)
		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		fmt.Println(string(respBody))

	}
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var prm pool.PrmContainerEACL
	prm.SetContainerID(*cnrID)

	table, err := clientPool.GetEACL(ctx, prm)
	require.NoError(t, err)

	expectedTable, err := handlers.ToNativeTable(req.Records)
	require.NoError(t, err)
	expectedTable.SetCID(cnrID)

	require.True(t, eacl.EqualTables(*expectedTable, *table))
}

func restContainerEACLGet(ctx context.Context, t *testing.T, clientPool *pool.Pool) {
	cnrID := createContainer(ctx, t, clientPool, "for-eacl-get")
	expectedTable := restrictByEACL(ctx, t, clientPool, cnrID)

	httpClient := &http.Client{Timeout: 60 * time.Second}

	request, err := http.NewRequest(http.MethodGet, testHost+"/v1/containers/"+cnrID.String()+"/eacl", nil)
	require.NoError(t, err)
	request = request.WithContext(ctx)

	resp, err := httpClient.Do(request)
	require.NoError(t, err)
	defer func() {
		err := resp.Body.Close()
		require.NoError(t, err)
	}()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("resp", resp.Status)
		fmt.Println(string(respBody))

	}
	require.Equal(t, http.StatusOK, resp.StatusCode)

	responseTable := &models.Eacl{}
	err = json.Unmarshal(respBody, responseTable)
	require.NoError(t, err)

	require.Equal(t, cnrID.String(), responseTable.ContainerID)

	actualTable, err := handlers.ToNativeTable(responseTable.Records)
	require.NoError(t, err)
	actualTable.SetCID(cnrID)

	require.True(t, eacl.EqualTables(*expectedTable, *actualTable))
}

func makeAuthContainerTokenRequest(ctx context.Context, t *testing.T, bearer *models.Bearer, httpClient *http.Client) *handlers.BearerToken {
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	hexPubKey := hex.EncodeToString(key.PublicKey().Bytes())

	data, err := json.Marshal(bearer)
	require.NoError(t, err)

	request, err := http.NewRequest(http.MethodPost, testHost+"/v1/auth", bytes.NewReader(data))
	require.NoError(t, err)
	request = request.WithContext(ctx)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(XNeofsTokenScope, string(models.TokenTypeContainer))
	request.Header.Add(XNeofsTokenSignatureKey, hexPubKey)

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

	stokenResp := &models.TokenResponse{}
	err = json.Unmarshal(rr, stokenResp)
	require.NoError(t, err)

	require.Equal(t, *stokenResp.Type, models.TokenTypeContainer)

	binaryData, err := base64.StdEncoding.DecodeString(*stokenResp.Token)
	require.NoError(t, err)

	signatureData := signData(t, key, binaryData)
	signature := base64.StdEncoding.EncodeToString(signatureData)

	bt := handlers.BearerToken{
		Token:     *stokenResp.Token,
		Signature: signature,
		Key:       hexPubKey,
	}

	fmt.Printf("container token:\n%+v\n", bt)
	return &bt
}

func signData(t *testing.T, key *keys.PrivateKey, data []byte) []byte {
	h := sha512.Sum512(data)
	x, y, err := ecdsa.Sign(rand.Reader, &key.PrivateKey, h[:])
	require.NoError(t, err)
	return elliptic.Marshal(elliptic.P256(), x, y)
}

func restContainerPut(ctx context.Context, t *testing.T, clientPool *pool.Pool) {
	bearer := &models.Bearer{
		Container: &models.Rule{
			Verb: models.NewVerb(models.VerbPUT),
		},
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}

	bearerToken := makeAuthContainerTokenRequest(ctx, t, bearer, httpClient)

	attrKey, attrValue := "User-Attribute", "user value"

	userAttributes := map[string]string{
		attrKey: attrValue,
	}

	req := operations.PutContainerBody{
		ContainerName: handlers.NewString("cnr"),
	}

	body, err := json.Marshal(&req)
	require.NoError(t, err)

	reqURL, err := url.Parse(testHost + "/v1/containers")
	require.NoError(t, err)

	query := reqURL.Query()
	query.Add("skip-native-name", "true")

	reqURL.RawQuery = query.Encode()

	request, err := http.NewRequest(http.MethodPut, reqURL.String(), bytes.NewReader(body))
	require.NoError(t, err)
	prepareCommonHeaders(request.Header, bearerToken)
	request.Header.Add("X-Attribute-"+attrKey, attrValue)

	resp2, err := httpClient.Do(request)
	require.NoError(t, err)
	defer resp2.Body.Close()

	body, err = io.ReadAll(resp2.Body)
	require.NoError(t, err)
	fmt.Println(string(body))

	require.Equal(t, http.StatusOK, resp2.StatusCode)

	addr := &operations.PutContainerOKBody{}
	err = json.Unmarshal(body, addr)
	require.NoError(t, err)

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
	header.Add(XNeofsTokenSignature, bearerToken.Signature)
	header.Add("Authorization", "Bearer "+bearerToken.Token)
	header.Add(XNeofsTokenSignatureKey, bearerToken.Key)
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
