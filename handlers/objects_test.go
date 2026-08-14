package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func TestContentDisposition(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dis      string
		fileName string
		expected string
	}{
		{
			name:     "token name",
			dis:      "inline",
			fileName: "photo.jpg",
			expected: "inline; filename=photo.jpg",
		},
		{
			name:     "attachment",
			dis:      "attachment",
			fileName: "photo.jpg",
			expected: "attachment; filename=photo.jpg",
		},
		{
			name:     "space in name",
			dis:      "inline",
			fileName: "my photo.jpg",
			expected: `inline; filename="my photo.jpg"`,
		},
		{
			name:     "non-ascii",
			dis:      "inline",
			fileName: "Лев.txt",
			expected: "inline; filename*=utf-8''%D0%9B%D0%B5%D0%B2.txt",
		},
		{
			name:     "non-ascii attachment",
			dis:      "attachment",
			fileName: "Лев.txt",
			expected: "attachment; filename*=utf-8''%D0%9B%D0%B5%D0%B2.txt",
		},
		{
			name:     "multi-segment path",
			dis:      "inline",
			fileName: "dir/Лев.txt",
			expected: "inline; filename*=utf-8''%D0%9B%D0%B5%D0%B2.txt",
		},
		{
			name:     "quote in name",
			dis:      "inline",
			fileName: `a"b.txt`,
			expected: `inline; filename="a\"b.txt"`,
		},
		{
			name:     "backslash in name",
			dis:      "inline",
			fileName: `a\b.txt`,
			expected: `inline; filename="a\\b.txt"`,
		},
		{
			name:     "control character",
			dis:      "inline",
			fileName: "a\x01b.txt",
			expected: "inline; filename*=utf-8''a%01b.txt",
		},
		{
			name:     "empty name",
			dis:      "inline",
			fileName: "",
			expected: "inline",
		},
		{
			name:     "root path",
			dis:      "inline",
			fileName: "/",
			expected: "inline",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := contentDisposition(tc.dis, tc.fileName)
			require.Equal(t, tc.expected, got)
		})
	}

	t.Run("no header injection", func(t *testing.T) {
		got := contentDisposition("inline", "a\r\nX-Evil: 1.txt")
		require.NotContains(t, got, "\r")
		require.NotContains(t, got, "\n")
		require.Equal(t, "inline; filename*=utf-8''a%0D%0AX-Evil%3A%201.txt", got)
	})
}

func TestSetAttributes_ContentDisposition(t *testing.T) {
	e := echo.New()
	log := zap.NewNop()
	api := &RestAPI{log: log}

	const (
		asciiName    = "photo.jpg"
		nonASCIIName = "Лев.txt"

		nonASCIIDisposition = "filename*=utf-8''%D0%9B%D0%B5%D0%B2.txt"
	)

	download := "1"

	for _, tc := range []struct {
		name     string
		fileName string
		useJSON  bool
		download *string
		expected string
	}{
		{
			name:     "ascii",
			fileName: asciiName,
			expected: "inline; filename=" + asciiName,
		},
		{
			name:     "ascii download",
			fileName: asciiName,
			download: &download,
			expected: "attachment; filename=" + asciiName,
		},
		{
			name:     "non-ascii",
			fileName: nonASCIIName,
			expected: "inline; " + nonASCIIDisposition,
		},
		{
			name:     "non-ascii JSON",
			fileName: nonASCIIName,
			useJSON:  true,
			expected: "inline; " + nonASCIIDisposition,
		},
		{
			name:     "non-ascii download",
			fileName: nonASCIIName,
			download: &download,
			expected: "attachment; " + nonASCIIDisposition,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			var hdr object.Object
			hdr.SetAttributes(object.NewAttribute(object.AttributeFileName, tc.fileName))

			params := setAttributeParams{
				cid:      "testCID",
				oid:      "testOID",
				header:   hdr,
				useJSON:  tc.useJSON,
				download: tc.download,
			}
			api.setAttributes(ctx, params, log)

			require.Equal(t, tc.expected, rec.Header().Get("Content-Disposition"))

			// Non-ASCII values are still not exposed as a raw header, they are
			// only available via X-Attributes-Base64.
			plain := rec.Header().Get(userAttributeHeaderPrefix + object.AttributeFileName)
			if tc.fileName == asciiName {
				require.Equal(t, asciiName, plain)
			} else {
				require.Empty(t, plain)
			}
		})
	}
}

func TestSetAttributes_XAttributesASCIIGating(t *testing.T) {
	e := echo.New()
	log := zap.NewNop()
	api := &RestAPI{log: log}

	for _, tc := range []struct {
		name      string
		attrs     [][2]string
		wantPlain bool // whether the plain X-Attributes header must be present
	}{
		{
			name:      "ascii only",
			attrs:     [][2]string{{"writer", "Leo Tolstoy"}, {"chapter", "War and Peace"}},
			wantPlain: true,
		},
		{
			name:      "non-ascii value",
			attrs:     [][2]string{{"writer", "Лев Толстой"}},
			wantPlain: false,
		},
		{
			name:      "non-ascii key",
			attrs:     [][2]string{{"автор", "Tolstoy"}},
			wantPlain: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			var hdr object.Object
			attrs := make([]object.Attribute, 0, len(tc.attrs))
			for _, kv := range tc.attrs {
				attrs = append(attrs, object.NewAttribute(kv[0], kv[1]))
			}
			hdr.SetAttributes(attrs...)

			params := setAttributeParams{
				cid:     "testCID",
				oid:     "testOID",
				header:  hdr,
				useJSON: true,
			}
			api.setAttributes(ctx, params, log)

			// X-Attributes-Base64 must always be present and decode to the full map.
			encoded := rec.Header().Get(userAttributesEncodedHeader)
			require.NotEmpty(t, encoded)
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			require.NoError(t, err)
			var got map[string]string
			require.NoError(t, json.Unmarshal(decoded, &got))
			for _, kv := range tc.attrs {
				require.Equal(t, kv[1], got[kv[0]])
			}

			plain := rec.Header().Get(userAttributesHeader)
			if tc.wantPlain {
				require.Equal(t, string(decoded), plain)
			} else {
				require.Empty(t, plain)
			}
		})
	}
}
