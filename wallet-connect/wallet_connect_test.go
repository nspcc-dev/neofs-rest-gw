package walletconnect

import (
	"crypto/ecdsa"
	"encoding/hex"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/handlers"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/stretchr/testify/require"
	"testing"
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

	btoken, err := handlers.ToNativeObjectToken(b)
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
