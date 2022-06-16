package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/stretchr/testify/require"
)

const devenvPrivateKey = "1dd37fba80fec4e6a6f13fd708d8dcb3b29def768017052f6c930fa1c5d90bbb"

func TestSign(t *testing.T) {
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	pubKeyHex := hex.EncodeToString(key.PublicKey().Bytes())

	b := &models.Bearer{
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

	btoken, err := util.ToNativeObjectToken(b)
	require.NoError(t, err)

	ownerKey, err := keys.NewPublicKeyFromString(pubKeyHex)
	require.NoError(t, err)

	btoken.SetOwner(owner.NewIDFromPublicKey((*ecdsa.PublicKey)(ownerKey)))

	binaryBearer, err := btoken.ToV2().GetBody().StableMarshal(nil)
	require.NoError(t, err)

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
