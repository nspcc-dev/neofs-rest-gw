package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
)

const devenvPrivateKey = "1dd37fba80fec4e6a6f13fd708d8dcb3b29def768017052f6c930fa1c5d90bbb"

func TestSign(t *testing.T) {
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	pubKeyHex := hex.EncodeToString(key.PublicKey().Bytes())

	records := []*models.Record{{
		Operation: models.NewOperation(models.OperationPUT),
		Action:    models.NewAction(models.ActionALLOW),
		Filters:   []*models.Filter{},
		Targets: []*models.Target{{
			Role: models.NewRole(models.RoleOTHERS),
			Keys: []string{},
		}},
	}}

	btoken, err := util.ToNativeObjectToken(records)
	require.NoError(t, err)

	btoken.SetExp(math.MaxInt64)

	ownerKey, err := keys.NewPublicKeyFromString(pubKeyHex)
	require.NoError(t, err)

	var owner user.ID
	user.IDFromKey(&owner, *(*ecdsa.PublicKey)(ownerKey))
	btoken.ForUser(owner)

	var v2token acl.BearerToken
	btoken.WriteToV2(&v2token)

	binaryBearer := v2token.GetBody().StableMarshal(nil)
	bearerBase64 := base64.StdEncoding.EncodeToString(binaryBearer)

	h := sha512.Sum512(binaryBearer)
	x, y, err := ecdsa.Sign(rand.Reader, &key.PrivateKey, h[:])
	if err != nil {
		panic(err)
	}
	signatureData := elliptic.Marshal(elliptic.P256(), x, y)

	bt := &BearerToken{
		Token:     bearerBase64,
		Signature: hex.EncodeToString(signatureData),
		Key:       pubKeyHex,
	}

	_, err = prepareBearerToken(bt, false)
	require.NoError(t, err)
}

func TestName(t *testing.T) {
	//bt := "Cq4BCokBCgASIgog1WV5EUB4P+vBDntpIRfpfqU9vFbfqYCLVQxeGiN4We4aVwgDEAEaTQgCEAEaBUVtYWlsIkA2NGJhM2FkNDdjYmVlNWY1Mjg4ZTZjOTZiNWUwNjg1NjZmMzM2MGMyOGIyODNiN2M2NmM0MmFiZTczNTFjNDQ5IgIIAxoICAMQAiICCAMSGwoZNaq5pfYuroaGE7h9o5iQsPR/1aRe5gmWrhoDCLcGEmYKIQMabG+73wLKNRdF+oa5ulqUUteFrE9/wrdUjKKkbE/PShJBBEGKRnVy4jfvBuNMspDwI6/fynIkqql4p+wKe/BgOKgDFkX83h6Q13J8eakV4RzZR+31JLgyM37GVp57ndZk9w4="
	//
	//btRaw, err := base64.StdEncoding.DecodeString(bt)
	//require.NoError(t, err)

	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	var btoken bearer.Token

	var table eacl.Table
	var r eacl.Record
	r.SetAction(eacl.ActionAllow)
	r.SetOperation(eacl.OperationGet)
	eacl.AddFormedTarget(&r, eacl.RoleOthers)

	table.AddRecord(&r)

	btoken.SetExp(100)
	btoken.SetEACLTable(table)
	err = btoken.Sign(key.PrivateKey)
	require.NoError(t, err)

	bytes := btoken.Marshal()
	fmt.Println(base64.StdEncoding.EncodeToString(bytes))
}
