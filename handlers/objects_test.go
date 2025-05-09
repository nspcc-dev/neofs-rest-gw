package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	bearertest "github.com/nspcc-dev/neofs-sdk-go/bearer/test"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
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

func Test_getReturningAttributes(t *testing.T) {
	commonAttributes := []string{
		object.AttributeFileName,
		object.AttributeFilePath,
		object.AttributeTimestamp,
	}

	type args struct {
		commonAttributes []string
		attribute        string
	}
	tests := []struct {
		name                string
		args                args
		returningAttributes []string
		actualIndexes       attributeIndexes
	}{
		{
			name:                "by FileName",
			args:                args{commonAttributes: commonAttributes, attribute: object.AttributeFileName},
			returningAttributes: commonAttributes,
			actualIndexes: attributeIndexes{
				FileName:  0,
				FilePath:  1,
				Timestamp: 2,
			},
		},
		{
			name: "by FilePath",
			args: args{commonAttributes: commonAttributes, attribute: object.AttributeFilePath},
			returningAttributes: []string{
				object.AttributeFilePath,
				object.AttributeFileName,
				object.AttributeTimestamp,
			},
			actualIndexes: attributeIndexes{
				FileName:  1,
				FilePath:  0,
				Timestamp: 2,
			},
		},
		{
			name: "by Timestamp",
			args: args{commonAttributes: commonAttributes, attribute: object.AttributeTimestamp},
			returningAttributes: []string{
				object.AttributeTimestamp,
				object.AttributeFileName,
				object.AttributeFilePath,
			},
			actualIndexes: attributeIndexes{
				FileName:  1,
				FilePath:  2,
				Timestamp: 0,
			},
		},
		{
			name: "not well known attribute",
			args: args{commonAttributes: commonAttributes, attribute: "attr1"},
			returningAttributes: []string{
				"attr1",
				object.AttributeFileName,
				object.AttributeFilePath,
				object.AttributeTimestamp,
			},
			actualIndexes: attributeIndexes{
				FileName:  1,
				FilePath:  2,
				Timestamp: 3,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := getReturningAttributes(tt.args.commonAttributes, tt.args.attribute)
			if !reflect.DeepEqual(got, tt.returningAttributes) {
				t.Errorf("getReturningAttributes() got = %v, returningAttributes %v", got, tt.returningAttributes)
			}
			if got1 != tt.actualIndexes {
				t.Errorf("getReturningAttributes() got1 = %v, returningAttributes %v", got1, tt.actualIndexes)
			}
		})
	}
}
