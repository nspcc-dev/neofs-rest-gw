package handlers

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/v2/acl"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
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

	signatureData, err := crypto.Sign(&key.PrivateKey, binaryBearer)
	require.NoError(t, err)

	bt := &BearerToken{
		Token:     bearerBase64,
		Signature: hex.EncodeToString(signatureData),
		Key:       pubKeyHex,
	}

	_, err = prepareBearerToken(bt, false, false)
	require.NoError(t, err)
}

func TestWalletConnect20Signature(t *testing.T) {
	stV10 := &SessionToken{
		BearerToken: BearerToken{
			Token:     "ChAMDRXN+epG44eLachkJJQKEhsKGTV0c7bhRT/GDdQsm7gPCNG63g4isq97/E8aBgixAhjNASIhAzFSJMOEdkH6YbJYhHN0w1wrgiz/QFPZvQ2D/8oqNrQjMgQIARAB",
			Signature: "87f54d849fc887dfda7546b4edde6f83397cea798a0c5edf979149659007fbe868e7d8a3b6813c56a81c266a5d28956b28b59ba87cd6aff09d518bcfe11474276e5c3d4d714eb13d43601cae70aef11e",
			Key:       "027e9b7e3b9f07b6bcb59b050f11616c78f433806d4314f7c72e5ac1d9f4d1fb02",
		},
		Verb: 1,
	}

	stV20 := &SessionToken{
		BearerToken: BearerToken{
			Token:     "ChBLgy6hRhBIpJVysyjM84OUEhsKGTV0c7bhRT/GDdQsm7gPCNG63g4isq97/E8aBgi0AhjQASIhAkwGSfK6lIf6HkuzG1YSSeFn5D/qIesknvBFTGN8qod5MgQIARAB",
			Signature: "e286951bfd1cc172b70fcd6a832d2121a5a635493a5b15c385b8001e676576df308898615cc25efc7fd649a7b3052453338b96671776d498c15cf032fdb072ec30f30aba0bb9375c6575fac8a4d4a19d",
			Key:       "027e9b7e3b9f07b6bcb59b050f11616c78f433806d4314f7c72e5ac1d9f4d1fb02",
		},
		Verb: 1,
	}

	_, err1 := prepareSessionToken(stV10, true)
	require.NoError(t, err1)

	err2 := prepareSessionToken2(stV20)
	require.NoError(t, err2)

}

func prepareSessionToken2(st *SessionToken) error {
	data := []byte(st.Token)

	signature, err := hex.DecodeString(st.Signature)
	if err != nil {
		return fmt.Errorf("couldn't decode signature: %w", err)
	}

	ownerKey, err := keys.NewPublicKeyFromString(st.Key)
	if err != nil {
		return fmt.Errorf("couldn't fetch session token owner key: %w", err)
	}

	if !Verify((*ecdsa.PublicKey)(ownerKey), data, signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
