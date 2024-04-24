package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	bearertest "github.com/nspcc-dev/neofs-sdk-go/bearer/test"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/crypto/test"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
)

func TestPrepareOffset(t *testing.T) {
	for _, tc := range []struct {
		err            bool
		expectedOffset uint64
		expectedLength uint64
		params         apiserver.GetObjectInfoParams
		objSize        uint64
	}{
		{
			params: apiserver.GetObjectInfoParams{
				RangeLength: util.NewInteger(1),
				RangeOffset: util.NewInteger(0),
			},
			objSize:        1,
			expectedOffset: 0,
			expectedLength: 1,
		},
		{
			params: apiserver.GetObjectInfoParams{
				RangeLength: util.NewInteger(3),
				RangeOffset: util.NewInteger(1),
			},
			objSize:        5,
			expectedOffset: 1,
			expectedLength: 3,
		},
		{
			objSize:        1,
			expectedOffset: 0,
			expectedLength: 1,
		},
		{
			err: true,
			params: apiserver.GetObjectInfoParams{
				RangeLength: util.NewInteger(1),
				RangeOffset: nil,
			},
		},
		{
			err: true,
			params: apiserver.GetObjectInfoParams{
				RangeLength: nil,
				RangeOffset: util.NewInteger(1),
			},
		},
		{
			err: true,
			params: apiserver.GetObjectInfoParams{
				RangeLength: util.NewInteger(1),
				RangeOffset: util.NewInteger(0),
			},
			objSize: 0,
		},
	} {
		t.Run("", func(t *testing.T) {
			offset, length, err := prepareOffsetLength(tc.params, tc.objSize)
			if tc.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedOffset, offset)
			require.Equal(t, tc.expectedLength, length)
		})
	}
}

func TestPrepareBearerToken(t *testing.T) {
	signer := test.RandomSigner(t)
	token := bearertest.Token(t)

	keyHex := hex.EncodeToString(neofscrypto.PublicKeyBytes(signer.Public()))
	pKey, err := keys.NewPublicKeyFromString(keyHex)
	require.NoError(t, err)
	usrID := user.ResolveFromECDSAPublicKey(ecdsa.PublicKey(*pKey))

	token.SetIssuer(usrID)

	sig, err := signer.Sign(token.SignedData())
	require.NoError(t, err)

	err = token.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), usrID))
	require.NoError(t, err)
	require.True(t, token.VerifySignature())

	tokenB64 := base64.StdEncoding.EncodeToString(token.Marshal())
	unsignedTokenB64 := base64.StdEncoding.EncodeToString(token.SignedData())
	sigHex := hex.EncodeToString(sig)

	t.Run("invalid base64", func(t *testing.T) {
		_, err := prepareBearerToken(&BearerToken{
			Token: "not a base64 string",
		}, false, false)
		require.ErrorContains(t, err, "can't base64-decode bearer token")
	})

	res, err := prepareBearerToken(&BearerToken{
		Token:     unsignedTokenB64,
		Signature: sigHex,
		Key:       keyHex,
	}, false, false)
	require.NoError(t, err)
	require.Equal(t, token.Marshal(), res.Marshal())

	t.Run("full", func(t *testing.T) {
		res, err := prepareBearerToken(&BearerToken{
			Token:     tokenB64,
			Signature: sigHex,
			Key:       keyHex,
		}, false, true)
		require.NoError(t, err)
		require.Equal(t, token.Marshal(), res.Marshal())

		t.Run("invalid binary", func(t *testing.T) {
			_, err := prepareBearerToken(&BearerToken{
				Token: base64.StdEncoding.EncodeToString([]byte("not a bearer token")),
			}, false, true)
			require.ErrorContains(t, err, "couldn't unmarshall bearer token")
		})

		t.Run("invalid signature", func(t *testing.T) {
			tokenCp := token

			// corrupt signature
			sig := bytes.Clone(sig)
			sig[0]++

			err = tokenCp.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), usrID))
			require.NoError(t, err)

			_, err = prepareBearerToken(&BearerToken{
				Token: base64.StdEncoding.EncodeToString(tokenCp.Marshal()),
			}, false, true)
			require.ErrorContains(t, err, "invalid signature")
		})
	})

	t.Run("invalid signature hex", func(t *testing.T) {
		_, err := prepareBearerToken(&BearerToken{
			Token:     tokenB64,
			Signature: "not a hex string",
		}, false, false)
		require.ErrorContains(t, err, "couldn't decode bearer signature")
	})

	t.Run("invalid signature hex", func(t *testing.T) {
		_, err := prepareBearerToken(&BearerToken{
			Token:     tokenB64,
			Signature: "not a hex string",
		}, false, false)
		require.ErrorContains(t, err, "couldn't decode bearer signature")
	})

	t.Run("invalid public key", func(t *testing.T) {
		_, err := prepareBearerToken(&BearerToken{
			Token:     tokenB64,
			Signature: sigHex,
			Key:       "not a public key",
		}, false, false)
		require.ErrorContains(t, err, "couldn't fetch bearer token owner key")
	})

	t.Run("invalid body binary", func(t *testing.T) {
		_, err := prepareBearerToken(&BearerToken{
			Token:     base64.StdEncoding.EncodeToString([]byte("not a bearer token")),
			Signature: sigHex,
			Key:       keyHex,
		}, false, false)
		require.ErrorContains(t, err, "can't unmarshal bearer token body")
	})

	t.Run("invalid signature", func(t *testing.T) {
		tokenCp := token

		err = tokenCp.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), usrID))
		require.NoError(t, err)
		require.True(t, tokenCp.VerifySignature())

		// corrupt signature
		sig := bytes.Clone(sig)
		sig[0]++

		err = tokenCp.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), usrID))
		require.NoError(t, err)

		_, err = prepareBearerToken(&BearerToken{
			Token:     unsignedTokenB64,
			Signature: hex.EncodeToString(sig),
			Key:       keyHex,
		}, false, false)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("WalletConnect", func(t *testing.T) {
		key, err := keys.NewPrivateKey()
		require.NoError(t, err)
		signer := neofsecdsa.SignerWalletConnect(key.PrivateKey)
		keyHex := hex.EncodeToString(key.PublicKey().Bytes())
		tokenCp := token
		unsignedTokenB64 := base64.StdEncoding.EncodeToString(tokenCp.SignedData())
		usrID := user.ResolveFromECDSAPublicKey(ecdsa.PublicKey(*key.PublicKey()))
		tokenCp.SetIssuer(usrID)

		sig, err := signer.Sign(tokenCp.SignedData())
		require.NoError(t, err)

		err = tokenCp.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), usrID))
		require.NoError(t, err)
		require.True(t, tokenCp.VerifySignature())

		res, err := prepareBearerToken(&BearerToken{
			Token:     unsignedTokenB64,
			Signature: hex.EncodeToString(sig),
			Key:       keyHex,
		}, true, false)
		require.NoError(t, err)
		require.Equal(t, tokenCp.Marshal(), res.Marshal())

		// corrupt signature
		sig[0]++

		err = tokenCp.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), usrID))
		require.NoError(t, err)

		_, err = prepareBearerToken(&BearerToken{
			Token:     unsignedTokenB64,
			Signature: hex.EncodeToString(sig),
			Key:       keyHex,
		}, true, false)
		require.ErrorContains(t, err, "invalid signature")
	})
}
