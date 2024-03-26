package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/crypto/test"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	sessiontest "github.com/nspcc-dev/neofs-sdk-go/session/test"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
	"github.com/stretchr/testify/require"
)

func TestCheckContainerName(t *testing.T) {
	name64 := "container-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	name256 := "container-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{name: "container", valid: true},
		{name: "container-name", valid: true},
		{name: "container.name", valid: true},
		{name: "container2", valid: true},
		{name: "2container.name", valid: true},
		{name: "containerName", valid: false},
		{name: "-container", valid: false},
		{name: "container-", valid: false},
		{name: "container name", valid: false},
		{name: "c", valid: false},
		{name: name64 + ".name", valid: false},
		{name: name256, valid: false},
	} {
		err := checkNNSContainerName(tc.name)
		if tc.valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}

func TestPrepareSessionToken(t *testing.T) {
	st := &SessionToken{
		BearerToken: BearerToken{
			Token:     "ChASxCTiXwREjLAG7nkxjDHVEhsKGTVxfQ56a0uQeFmOO63mqykBS1HNpw1rxSgaBgjIAhjkASIhAnLj82Qmdlcg7JtoyhDjJ1OsRFjtmxdXbzrwVkwxWAdWMgQIAxAB",
			Signature: "2ebdc1f2fea2bba397d1be6f982a6fe1b2bc9f46a348b700108fe2eba4e6531a1bb585febf9a40a3fa2e085fca5e2a75ca57f61166117c6d3e04a95ef9a2d2196f52648546784853e17c0b7ba762eae1",
			Key:       "03bd9108c0b49f657e9eee50d1399022bd1e436118e5b7529a1b7cd606652f578f",
		},
		Verb: session.VerbContainerSetEACL,
	}

	_, err := prepareSessionToken(st, true)
	require.NoError(t, err)

	issuer := usertest.ID(t)
	signer := user.NewSigner(test.RandomSigner(t), issuer)
	token := sessiontest.Container()
	token.SetIssuer(issuer)
	const verb = session.VerbContainerPut
	token.ForVerb(verb)

	sig, err := signer.Sign(token.SignedData())
	require.NoError(t, err)

	err = token.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), issuer))
	require.NoError(t, err)
	require.True(t, token.VerifySignature())

	unsignedTokenB64 := base64.StdEncoding.EncodeToString(token.SignedData())
	sigHex := hex.EncodeToString(sig)
	keyHex := hex.EncodeToString(neofscrypto.PublicKeyBytes(signer.Public()))

	t.Run("invalid base64", func(t *testing.T) {
		_, err := prepareSessionToken(&SessionToken{
			BearerToken: BearerToken{
				Token: "not a base64 string",
			},
		}, false)
		require.ErrorContains(t, err, "can't base64-decode session token")
	})

	res, err := prepareSessionToken(&SessionToken{
		BearerToken: BearerToken{
			Token:     unsignedTokenB64,
			Signature: sigHex,
			Key:       keyHex,
		},
		Verb: verb,
	}, false)
	require.NoError(t, err)
	require.Equal(t, token, res)

	t.Run("invalid signature hex", func(t *testing.T) {
		_, err := prepareSessionToken(&SessionToken{
			BearerToken: BearerToken{
				Token:     unsignedTokenB64,
				Signature: "not a hex string",
			},
			Verb: 0,
		}, false)
		require.ErrorContains(t, err, "couldn't decode signature")
	})

	t.Run("invalid public key", func(t *testing.T) {
		_, err := prepareSessionToken(&SessionToken{
			BearerToken: BearerToken{
				Token:     unsignedTokenB64,
				Signature: sigHex,
				Key:       "not a public key",
			},
			Verb: 0,
		}, false)
		require.ErrorContains(t, err, "couldn't fetch session token owner key")
	})

	t.Run("invalid body binary", func(t *testing.T) {
		_, err := prepareSessionToken(&SessionToken{
			BearerToken: BearerToken{
				Token:     base64.StdEncoding.EncodeToString([]byte("not a bearer token")),
				Signature: sigHex,
				Key:       keyHex,
			},
			Verb: 0,
		}, false)
		require.ErrorContains(t, err, "can't unmarshal session token")
	})

	t.Run("invalid signature", func(t *testing.T) {
		tokenCp := token

		err = tokenCp.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), issuer))
		require.NoError(t, err)
		require.True(t, tokenCp.VerifySignature())

		// corrupt signature
		sig := bytes.Clone(sig)
		sig[0]++

		err = tokenCp.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), issuer))
		require.NoError(t, err)

		_, err = prepareSessionToken(&SessionToken{
			BearerToken: BearerToken{
				Token:     unsignedTokenB64,
				Signature: hex.EncodeToString(sig),
				Key:       keyHex,
			},
			Verb: verb,
		}, false)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("WalletConnect", func(t *testing.T) {
		key, err := keys.NewPrivateKey()
		require.NoError(t, err)
		signer := neofsecdsa.SignerWalletConnect(key.PrivateKey)
		keyHex := hex.EncodeToString(key.PublicKey().Bytes())
		var tokenCp session.Container
		token.CopyTo(&tokenCp)
		unsignedTokenB64 := base64.StdEncoding.EncodeToString(tokenCp.SignedData())

		sig, err := signer.Sign(tokenCp.SignedData())
		require.NoError(t, err)

		sigHex := hex.EncodeToString(sig)

		err = tokenCp.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), issuer))
		require.NoError(t, err)
		require.True(t, tokenCp.VerifySignature())

		res, err := prepareSessionToken(&SessionToken{
			BearerToken: BearerToken{
				Token:     unsignedTokenB64,
				Signature: sigHex,
				Key:       keyHex,
			},
			Verb: verb,
		}, true)
		require.NoError(t, err)
		require.Equal(t, tokenCp, res)

		// corrupt signature
		sig[0]++

		err = tokenCp.Sign(user.NewSigner(neofscrypto.NewStaticSigner(signer.Scheme(), sig, signer.Public()), issuer))
		require.NoError(t, err)

		_, err = prepareSessionToken(&SessionToken{
			BearerToken: BearerToken{
				Token:     unsignedTokenB64,
				Signature: hex.EncodeToString(sig),
				Key:       keyHex,
			},
			Verb: verb,
		}, true)
		require.ErrorContains(t, err, "invalid signature")
	})
}
