package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	bearertest "github.com/nspcc-dev/neofs-sdk-go/bearer/test"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPrepareBearerToken(t *testing.T) {
	signer := usertest.User()
	token := bearertest.Token()

	keyHex := hex.EncodeToString(signer.PublicKeyBytes)
	usrID := signer.ID

	token.SetIssuer(usrID)

	sig, err := signer.Sign(token.SignedData())
	require.NoError(t, err)

	token.AttachSignature(neofscrypto.NewSignature(signer.Scheme(), signer.Public(), sig))
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

			tokenCp.AttachSignature(neofscrypto.NewSignature(signer.Scheme(), signer.Public(), sig))

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

		tokenCp.AttachSignature(neofscrypto.NewSignature(signer.Scheme(), signer.Public(), sig))
		require.True(t, tokenCp.VerifySignature())

		// corrupt signature
		sig := bytes.Clone(sig)
		sig[0]++

		tokenCp.AttachSignature(neofscrypto.NewSignature(signer.Scheme(), signer.Public(), sig))

		_, err = prepareBearerToken(&BearerToken{
			Token:     unsignedTokenB64,
			Signature: hex.EncodeToString(sig),
			Key:       keyHex,
		}, false, false)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("WalletConnect", func(t *testing.T) {
		usr := usertest.User()
		signer := usr.WalletConnect
		keyHex := hex.EncodeToString(usr.PublicKeyBytes)
		tokenCp := token
		tokenCp.SetIssuer(usr.ID)
		unsignedTokenB64 := base64.StdEncoding.EncodeToString(tokenCp.SignedData())

		sig, err := signer.Sign(tokenCp.SignedData())
		require.NoError(t, err)

		tokenCp.AttachSignature(neofscrypto.NewSignature(signer.Scheme(), signer.Public(), sig))
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

		tokenCp.AttachSignature(neofscrypto.NewSignature(signer.Scheme(), signer.Public(), sig))

		_, err = prepareBearerToken(&BearerToken{
			Token:     unsignedTokenB64,
			Signature: hex.EncodeToString(sig),
			Key:       keyHex,
		}, true, false)
		require.ErrorContains(t, err, "invalid signature")
	})
}

func TestSetAttributes_ObjectTypeHeader(t *testing.T) {
	e := echo.New()
	log := zap.NewNop()
	api := &RestAPI{log: log}

	for _, tc := range []struct {
		name     string
		objType  object.Type
		expected string
	}{
		{name: "regular", objType: object.TypeRegular, expected: "REGULAR"},
		{name: "tombstone", objType: object.TypeTombstone, expected: "TOMBSTONE"},
		{name: "lock", objType: object.TypeLock, expected: "LOCK"},
		{name: "link", objType: object.TypeLink, expected: "LINK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			var hdr object.Object
			hdr.SetType(tc.objType)

			params := setAttributeParams{
				cid:    "testCID",
				oid:    "testOID",
				header: hdr,
			}
			api.setAttributes(ctx, params, log)

			require.Equal(t, tc.expected, rec.Header().Get(objectTypeHeader))
		})
	}
}
