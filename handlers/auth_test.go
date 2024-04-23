package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
)

const devenvPrivateKey = "1dd37fba80fec4e6a6f13fd708d8dcb3b29def768017052f6c930fa1c5d90bbb"

func TestSign(t *testing.T) {
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	pubKeyHex := hex.EncodeToString(key.PublicKey().Bytes())

	records := []apiserver.Record{{
		Operation: apiserver.OperationPUT,
		Action:    apiserver.ALLOW,
		Filters:   []apiserver.Filter{},
		Targets: []apiserver.Target{{
			Role: apiserver.OTHERS,
			Keys: []string{},
		}},
	}}

	btoken, err := util.ToNativeObjectToken(records)
	require.NoError(t, err)

	btoken.SetExp(math.MaxInt64)

	signer := user.NewAutoIDSigner(key.PrivateKey)
	owner := signer.UserID()
	btoken.ForUser(owner)
	btoken.SetIssuer(signer.UserID())

	binaryBearer := btoken.SignedData()
	bearerBase64 := base64.StdEncoding.EncodeToString(binaryBearer)

	signatureData, err := signer.Sign(binaryBearer)
	require.NoError(t, err)

	bt := &BearerToken{
		Token:     bearerBase64,
		Signature: hex.EncodeToString(signatureData),
		Key:       pubKeyHex,
	}

	_, err = prepareBearerToken(bt, false, false)
	require.NoError(t, err)
}
