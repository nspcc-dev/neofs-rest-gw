package walletconnect

import (
	"crypto/ecdsa"
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

	sm, err := SignMessage(&key.PrivateKey, binaryBearer)
	require.NoError(t, err)

	verified := Verify((*ecdsa.PublicKey)(key.PublicKey()), binaryBearer, append(sm.Data, sm.Salt...))
	require.True(t, verified)
}

func TestVerifyMessage(t *testing.T) {
	testCases := [...]struct {
		publicKey       string
		data            string
		salt            string
		messageHex      string
		messageOriginal string
	}{
		{ // Test values from this GIF https://github.com/CityOfZion/neon-wallet/pull/2390 .
			publicKey:       "02ce6228ba2cb2fc235be93aff9cd5fc0851702eb9791552f60db062f01e3d83f6",
			data:            "90ab1886ca0bece59b982d9ade8f5598065d651362fb9ce45ad66d0474b89c0b80913c8f0118a282acbdf200a429ba2d81bc52534a53ab41a2c6dfe2f0b4fb1b",
			salt:            "d41e348afccc2f3ee45cd9f5128b16dc",
			messageHex:      "010001f05c6434316533343861666363633266336565343563643966353132386231366463436172616c686f2c206d756c65712c206f2062616775697520656820697373756d65726d6f2074616978206c696761646f206e61206d697373e36f3f0000",
			messageOriginal: "436172616c686f2c206d756c65712c206f2062616775697520656820697373756d65726d6f2074616978206c696761646f206e61206d697373e36f3f",
		},
		{ // Test value from wallet connect integration test
			publicKey:       "03bd9108c0b49f657e9eee50d1399022bd1e436118e5b7529a1b7cd606652f578f",
			data:            "510caa8cb6db5dedf04d215a064208d64be7496916d890df59aee132db8f2b07532e06f7ea664c4a99e3bcb74b43a35eb9653891b5f8701d2aef9e7526703eaa",
			salt:            "2c5b189569e92cce12e1c640f23e83ba",
			messageHex:      "010001f02632633562313839353639653932636365313265316336343066323365383362613132333435360000",
			messageOriginal: "313233343536", // ascii string "123456"
		},
		{ // Test value from wallet connect integration test
			publicKey:       "03bd9108c0b49f657e9eee50d1399022bd1e436118e5b7529a1b7cd606652f578f",
			data:            "1e13f248962d8b3b60708b55ddf448d6d6a28c6b43887212a38b00bf6bab695e61261e54451c6e3d5f1f000e5534d166c7ca30f662a296d3a9aafa6d8c173c01",
			salt:            "58c86b2e74215b4f36b47d731236be3b",
			messageHex:      "010001f02035386338366232653734323135623466333662343764373331323336626533620000",
			messageOriginal: "", // empty string
		},
	}

	for _, testCase := range testCases {
		pub, err := keys.NewPublicKeyFromString(testCase.publicKey)
		require.NoError(t, err)
		data, err := hex.DecodeString(testCase.data)
		require.NoError(t, err)
		salt, err := hex.DecodeString(testCase.salt)
		require.NoError(t, err)
		msg, err := hex.DecodeString(testCase.messageHex)
		require.NoError(t, err)
		orig, err := hex.DecodeString(testCase.messageOriginal)
		require.NoError(t, err)

		require.Equal(t, msg, createMessageWithSalt(orig, salt))

		sm := SignedMessage{
			Data:      data,
			Message:   msg,
			PublicKey: pub.Bytes(),
			Salt:      salt,
		}
		require.True(t, VerifyMessage(nil, sm))

		require.True(t, Verify((*ecdsa.PublicKey)(pub), orig, append(data, salt...)))
	}
}
