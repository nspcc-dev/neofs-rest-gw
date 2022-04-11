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
	versions := []string{"0.24.0", "0.25.1", "0.27.5", "latest"}
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	for _, version := range versions {
		ctx, cancel2 := context.WithCancel(rootCtx)

		aioContainer := createDockerContainer(ctx, t, aioImage+version)
		cancel := runServer(ctx, t)
		clientPool := getPool(ctx, t, key)
		CID, err := createContainer(ctx, t, clientPool)
		require.NoError(t, err, version)

		t.Run("rest put object "+version, func(t *testing.T) { restObjectPut(ctx, t, clientPool, CID) })
		t.Run("rest put container"+version, func(t *testing.T) { restContainerPut(ctx, t, clientPool) })
		t.Run("rest get container"+version, func(t *testing.T) { restContainerGet(ctx, t, clientPool, CID) })

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

	require.Equal(t, cnrID.String(), cnrInfo.ContainerID)
	require.Equal(t, clientPool.OwnerID().String(), cnrInfo.OwnerID)
}

func signData(t *testing.T, key *keys.PrivateKey, data []byte) []byte {
	h := sha512.Sum512(data)
	x, y, err := ecdsa.Sign(rand.Reader, &key.PrivateKey, h[:])
	require.NoError(t, err)
	return elliptic.Marshal(elliptic.P256(), x, y)
}

func restContainerPut(ctx context.Context, t *testing.T, clientPool *pool.Pool) {
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	b := models.Bearer{
		Container: &models.Rule{
			Verb: models.NewVerb(models.VerbPUT),
		},
	}

	data, err := json.Marshal(&b)
	require.NoError(t, err)

	request0, err := http.NewRequest(http.MethodPost, testHost+"/v1/auth", bytes.NewReader(data))
	require.NoError(t, err)
	request0.Header.Add("Content-Type", "application/json")
	request0.Header.Add(XNeofsTokenScope, "container")
	request0.Header.Add(XNeofsTokenSignatureKey, hex.EncodeToString(key.PublicKey().Bytes()))

	httpClient := http.Client{
		Timeout: 30 * time.Second,
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

	require.Equal(t, *stokenResp.Type, models.TokenTypeContainer)

	bearerBase64 := stokenResp.Token
	binaryData, err := base64.StdEncoding.DecodeString(*bearerBase64)
	require.NoError(t, err)

	signatureData := signData(t, key, binaryData)

	attrKey, attrValue := "User-Attribute", "user value"

	userAttributes := map[string]string{
		attrKey: attrValue,
	}

	req := operations.PutContainerBody{
		ContainerName: handlers.NewString("cnr"),
	}

	body, err := json.Marshal(&req)
	require.NoError(t, err)

	fmt.Println(base64.StdEncoding.EncodeToString(signatureData))
	fmt.Println(hex.EncodeToString(key.PublicKey().Bytes()))

	request, err := http.NewRequest(http.MethodPut, testHost+"/v1/containers", bytes.NewReader(body))
	require.NoError(t, err)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(XNeofsTokenSignature, base64.StdEncoding.EncodeToString(signatureData))
	request.Header.Add("Authorization", "Bearer "+*bearerBase64)
	request.Header.Add(XNeofsTokenSignatureKey, hex.EncodeToString(key.PublicKey().Bytes()))
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

func createContainer(ctx context.Context, t *testing.T, clientPool *pool.Pool) (*cid.ID, error) {
	pp, err := policy.Parse("REP 1")
	require.NoError(t, err)

	cnr := container.New(
		container.WithPolicy(pp),
		container.WithCustomBasicACL(0x0FFFFFFF),
		container.WithAttribute(container.AttributeName, "friendlyName"),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10)))
	cnr.SetOwnerID(clientPool.OwnerID())

	var waitPrm pool.WaitParams
	waitPrm.SetPollInterval(3 * time.Second)
	waitPrm.SetTimeout(15 * time.Second)

	var prm pool.PrmContainerPut
	prm.SetContainer(*cnr)
	prm.SetWaitParams(waitPrm)

	CID, err := clientPool.PutContainer(ctx, prm)
	if err != nil {
		return nil, err
	}
	fmt.Println(CID.String())

	return CID, err
}

func restrictByEACL(ctx context.Context, t *testing.T, clientPool *pool.Pool, cnrID *cid.ID) {
	table := new(eacl.Table)
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
}
