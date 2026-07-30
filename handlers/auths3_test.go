package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/accessbox"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	sessionv2 "github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestS3API(t *testing.T) *RestAPI {
	gwKey, err := keys.NewPrivateKey()
	require.NoError(t, err)

	return &RestAPI{
		log:            zap.NewNop(),
		gatePrivateKey: gwKey,
		signer:         user.NewAutoIDSignerRFC6979(gwKey.PrivateKey),
	}
}

func prepareS3CredentialsCall(t *testing.T, a *RestAPI, body apiserver.S3CredentialsRequest) (*httptest.ResponseRecorder, apiserver.S3CredentialsResponse) {
	bodyBts, err := json.Marshal(body)
	require.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/v2/auth/s3", bytes.NewReader(bodyBts))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	require.NoError(t, a.PrepareS3Credentials(e.NewContext(req, rec)))

	var resp apiserver.S3CredentialsResponse
	if rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	}

	return rec, resp
}

func signS3Token(t *testing.T, tokenBase64 string, key *keys.PrivateKey) apiserver.S3SignedToken {
	tokenBts, err := base64.StdEncoding.DecodeString(tokenBase64)
	require.NoError(t, err)

	signature, err := user.NewAutoIDSignerRFC6979(key.PrivateKey).Sign(tokenBts)
	require.NoError(t, err)

	return apiserver.S3SignedToken{
		Token:     tokenBase64,
		Signature: hex.EncodeToString(signature),
		Key:       hex.EncodeToString(key.PublicKey().Bytes()),
		Scheme:    apiserver.DETERMINISTICSHA256,
	}
}

func s3PrepareBody(issuer user.ID, authCnrID cid.ID, gateKeys ...*keys.PrivateKey) apiserver.S3CredentialsRequest {
	gates := make([]string, 0, len(gateKeys))
	for _, k := range gateKeys {
		gates = append(gates, hex.EncodeToString(k.PublicKey().Bytes()))
	}

	return apiserver.S3CredentialsRequest{
		Issuer:      issuer.EncodeToString(),
		ContainerId: authCnrID.EncodeToString(),
		Gates:       gates,
	}
}

func TestS3CredentialsFlow(t *testing.T) {
	userKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	gateKey1, err := keys.NewPrivateKey()
	require.NoError(t, err)
	gateKey2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	a := newTestS3API(t)

	authCnrID := cid.ID{1, 2, 3}
	issuer := user.NewAutoIDSignerRFC6979(userKey.PrivateKey).UserID()
	rec, resp := prepareS3CredentialsCall(t, a, s3PrepareBody(issuer, authCnrID, gateKey1, gateKey2))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, resp.Tokens, 1)
	require.NotEmpty(t, resp.State)

	secret, ephemeralKey, stateCnrID, err := a.unpackS3State(resp.State)
	require.NoError(t, err)
	require.Len(t, secret, s3SecretLength)
	require.Equal(t, authCnrID, stateCnrID)

	// Unsigned token content is inspectable by the client before signing.
	tokenBts, err := base64.StdEncoding.DecodeString(resp.Tokens[0])
	require.NoError(t, err)

	var unsigned sessionv2.Token
	require.NoError(t, unsigned.UnmarshalSignedData(tokenBts))
	require.Equal(t, issuer, unsigned.Issuer())
	require.Len(t, unsigned.Subjects(), 3) // two gates + the REST gateway
	require.Len(t, unsigned.AppData(), 3*accessbox.EncryptedSecretLength)
	require.WithinDuration(t, time.Now().Add(defaultSessionTokenExpiration), unsigned.Exp(), time.Minute)

	// The default wildcard context plus the extended auth container one.
	require.Len(t, unsigned.Contexts(), 2)
	require.True(t, unsigned.AssertVerb(sessionv2.VerbObjectGet, authCnrID))
	require.True(t, unsigned.AssertVerb(sessionv2.VerbObjectPut, authCnrID))

	signed := signS3Token(t, resp.Tokens[0], userKey)

	completed, err := a.completeS3SessionToken(signed, ephemeralKey.PublicKey(), secret, a.signer.UserID())
	require.NoError(t, err)
	require.Equal(t, issuer, completed.Issuer())
	require.True(t, completed.VerifySignature())

	// The S3 gateway side: unpack the produced box with a gate key.
	box, err := accessbox.PackTokens([]sessionv2.Token{completed}, ephemeralKey.PublicKey().Bytes())
	require.NoError(t, err)

	payload, err := box.Marshal()
	require.NoError(t, err)

	var parsedBox accessbox.AccessBox
	require.NoError(t, parsedBox.Unmarshal(payload))

	for _, gateKey := range []*keys.PrivateKey{gateKey1, gateKey2} {
		gateData, err := parsedBox.GetTokens(gateKey, &noopNNSResolver{})
		require.NoError(t, err)
		require.Equal(t, hex.EncodeToString(secret), gateData.AccessKey)
		require.Equal(t, issuer, gateData.SessionTokenV2.Issuer())
		require.True(t, gateData.SessionTokenV2.VerifySignature())
	}

	// A key that is not a subject of the token gets nothing.
	strangerKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	_, err = parsedBox.GetTokens(strangerKey, &noopNNSResolver{})
	require.Error(t, err)
}

func TestPrepareS3CredentialsValidation(t *testing.T) {
	gateKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	userKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	issuer := user.NewAutoIDSignerRFC6979(userKey.PrivateKey).UserID()

	a := newTestS3API(t)
	authCnrID := cid.ID{1, 2, 3}
	gateHex := hex.EncodeToString(gateKey.PublicKey().Bytes())

	t.Run("no gates", func(t *testing.T) {
		rec, _ := prepareS3CredentialsCall(t, a, apiserver.S3CredentialsRequest{
			Issuer:      issuer.EncodeToString(),
			ContainerId: authCnrID.EncodeToString(),
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid issuer", func(t *testing.T) {
		rec, _ := prepareS3CredentialsCall(t, a, apiserver.S3CredentialsRequest{
			Issuer:      "invalid",
			ContainerId: authCnrID.EncodeToString(),
			Gates:       []string{gateHex},
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("no container", func(t *testing.T) {
		rec, _ := prepareS3CredentialsCall(t, a, apiserver.S3CredentialsRequest{
			Issuer: issuer.EncodeToString(),
			Gates:  []string{gateHex},
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("zero container", func(t *testing.T) {
		rec, _ := prepareS3CredentialsCall(t, a, apiserver.S3CredentialsRequest{
			Issuer:      issuer.EncodeToString(),
			ContainerId: cid.ID{}.EncodeToString(),
			Gates:       []string{gateHex},
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("malformed gate key", func(t *testing.T) {
		rec, _ := prepareS3CredentialsCall(t, a, apiserver.S3CredentialsRequest{
			Issuer:      issuer.EncodeToString(),
			ContainerId: authCnrID.EncodeToString(),
			Gates:       []string{"zz"},
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("expired expiration", func(t *testing.T) {
		expiredAt := "2000-01-01T00:00:00Z"
		rec, _ := prepareS3CredentialsCall(t, a, apiserver.S3CredentialsRequest{
			Issuer:            issuer.EncodeToString(),
			ContainerId:       authCnrID.EncodeToString(),
			Gates:             []string{gateHex},
			ExpirationRfc3339: &expiredAt,
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestCompleteS3SessionTokenValidation(t *testing.T) {
	userKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	gateKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	issuer := user.NewAutoIDSignerRFC6979(userKey.PrivateKey).UserID()

	a := newTestS3API(t)
	authCnrID := cid.ID{1, 2, 3}

	rec, resp := prepareS3CredentialsCall(t, a, s3PrepareBody(issuer, authCnrID, gateKey))
	require.Equal(t, http.StatusOK, rec.Code)

	secret, ephemeralKey, _, err := a.unpackS3State(resp.State)
	require.NoError(t, err)

	t.Run("wrong signature", func(t *testing.T) {
		signed := signS3Token(t, resp.Tokens[0], userKey)
		signed.Signature = strings.Repeat("00", 64)

		_, err := a.completeS3SessionToken(signed, ephemeralKey.PublicKey(), secret, a.signer.UserID())
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("foreign state", func(t *testing.T) {
		// Token from one prepare call combined with the state of another.
		rec2, resp2 := prepareS3CredentialsCall(t, a, s3PrepareBody(issuer, authCnrID, gateKey))
		require.Equal(t, http.StatusOK, rec2.Code)

		secret2, ephemeralKey2, _, err := a.unpackS3State(resp2.State)
		require.NoError(t, err)

		signed := signS3Token(t, resp.Tokens[0], userKey)
		_, err = a.completeS3SessionToken(signed, ephemeralKey2.PublicKey(), secret2, a.signer.UserID())
		require.ErrorContains(t, err, "doesn't match the state")
	})

	t.Run("gateway is not a subject", func(t *testing.T) {
		signed := signS3Token(t, resp.Tokens[0], userKey)

		otherGw, err := keys.NewPrivateKey()
		require.NoError(t, err)

		_, err = a.completeS3SessionToken(signed, ephemeralKey.PublicKey(), secret, user.NewFromScriptHash(otherGw.PublicKey().GetScriptHash()))
		require.ErrorContains(t, err, "not a subject")
	})
}

func TestS3StateRoundTrip(t *testing.T) {
	a := newTestS3API(t)

	ephemeralKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	secret := []byte(strings.Repeat("s", s3SecretLength))
	cnrID := cid.ID{4, 5, 6}

	state, err := a.packS3State(secret, ephemeralKey, cnrID)
	require.NoError(t, err)

	gotSecret, gotKey, gotCnrID, err := a.unpackS3State(state)
	require.NoError(t, err)
	require.Equal(t, secret, gotSecret)
	require.Equal(t, ephemeralKey.Bytes(), gotKey.Bytes())
	require.Equal(t, cnrID, gotCnrID)

	t.Run("tampered", func(t *testing.T) {
		raw, err := base64.StdEncoding.DecodeString(state)
		require.NoError(t, err)
		raw[len(raw)-1] ^= 0xff

		_, _, _, err = a.unpackS3State(base64.StdEncoding.EncodeToString(raw))
		require.Error(t, err)
	})

	t.Run("foreign gateway key", func(t *testing.T) {
		other := newTestS3API(t)
		_, _, _, err := other.unpackS3State(state)
		require.Error(t, err)
	})
}

func TestBuildS3SessionTokensChunking(t *testing.T) {
	userKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	issuer := user.NewAutoIDSignerRFC6979(userKey.PrivateKey).UserID()

	gwKey, err := keys.NewPrivateKey()
	require.NoError(t, err)

	var gateKeys keys.PublicKeys
	for range 10 {
		k, err := keys.NewPrivateKey()
		require.NoError(t, err)
		gateKeys = append(gateKeys, k.PublicKey())
	}

	ephemeralKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	secret := []byte(strings.Repeat("s", s3SecretLength))

	contexts, err := prepareS3TokenContexts(nil, cid.ID{1})
	require.NoError(t, err)

	now := time.Now()
	tokens, err := buildS3SessionTokens(gateKeys, gwKey.PublicKey(), issuer, contexts, now, now.Add(time.Hour), ephemeralKey, secret)
	require.NoError(t, err)
	require.Len(t, tokens, 2)

	gwID := user.NewFromScriptHash(gwKey.PublicKey().GetScriptHash())
	for i, expectedSubjects := range []int{maxS3GatesPerToken + 1, 10 - maxS3GatesPerToken + 1} {
		subjects := tokens[i].Subjects()
		require.Len(t, subjects, expectedSubjects)
		require.Equal(t, gwID, subjects[len(subjects)-1].UserID())
		require.Len(t, tokens[i].AppData(), expectedSubjects*accessbox.EncryptedSecretLength)
	}

	t.Run("gateway key is also a gate key", func(t *testing.T) {
		tokens, err := buildS3SessionTokens(keys.PublicKeys{gwKey.PublicKey()}, gwKey.PublicKey(), issuer, contexts, now, now.Add(time.Hour), ephemeralKey, secret)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		require.Len(t, tokens[0].Subjects(), 1)
	})
}

func TestPrepareS3TokenContexts(t *testing.T) {
	authCnrID := cid.ID{1, 2, 3}

	t.Run("default", func(t *testing.T) {
		contexts, err := prepareS3TokenContexts(nil, authCnrID)
		require.NoError(t, err)
		require.Len(t, contexts, 2)
		require.True(t, contexts[0].Container().IsZero())
		require.ElementsMatch(t, defaultS3SessionVerbs, contexts[0].Verbs())
		require.Equal(t, authCnrID, contexts[1].Container())
		require.ElementsMatch(t, []sessionv2.Verb{sessionv2.VerbObjectGet, sessionv2.VerbObjectPut}, contexts[1].Verbs())
	})

	t.Run("auth container context merged", func(t *testing.T) {
		contexts, err := prepareS3TokenContexts([]apiserver.TokenContext{
			{ContainerID: authCnrID.EncodeToString(), Verbs: []apiserver.TokenVerb{"OBJECT_DELETE"}},
		}, authCnrID)
		require.NoError(t, err)
		require.Len(t, contexts, 1)
		require.Equal(t, authCnrID, contexts[0].Container())
		require.ElementsMatch(t,
			[]sessionv2.Verb{sessionv2.VerbObjectGet, sessionv2.VerbObjectPut, sessionv2.VerbObjectDelete},
			contexts[0].Verbs())
	})

	t.Run("auth container context appended", func(t *testing.T) {
		otherCnrID := cid.ID{9}
		contexts, err := prepareS3TokenContexts([]apiserver.TokenContext{
			{ContainerID: otherCnrID.EncodeToString(), Verbs: []apiserver.TokenVerb{"OBJECT_GET"}},
		}, authCnrID)
		require.NoError(t, err)
		require.Len(t, contexts, 2)

		for _, c := range contexts {
			if c.Container() == authCnrID {
				require.ElementsMatch(t, []sessionv2.Verb{sessionv2.VerbObjectGet, sessionv2.VerbObjectPut}, c.Verbs())
			} else {
				require.Equal(t, otherCnrID, c.Container())
				require.ElementsMatch(t, []sessionv2.Verb{sessionv2.VerbObjectGet}, c.Verbs())
			}
		}
	})

	t.Run("duplicated container", func(t *testing.T) {
		_, err := prepareS3TokenContexts([]apiserver.TokenContext{
			{Verbs: []apiserver.TokenVerb{"OBJECT_GET"}},
			{Verbs: []apiserver.TokenVerb{"OBJECT_PUT"}},
		}, authCnrID)
		require.ErrorContains(t, err, "same container")
	})

	t.Run("no verbs", func(t *testing.T) {
		_, err := prepareS3TokenContexts([]apiserver.TokenContext{{ContainerID: cid.ID{1}.EncodeToString()}}, authCnrID)
		require.ErrorContains(t, err, "at least one verb")
	})

	t.Run("sorted by container", func(t *testing.T) {
		id1, id2 := cid.ID{}, cid.ID{}
		id1[0], id2[0] = 2, 1

		contexts, err := prepareS3TokenContexts([]apiserver.TokenContext{
			{ContainerID: id1.EncodeToString(), Verbs: []apiserver.TokenVerb{"OBJECT_GET"}},
			{ContainerID: id2.EncodeToString(), Verbs: []apiserver.TokenVerb{"OBJECT_PUT"}},
		}, id2)
		require.NoError(t, err)
		require.Len(t, contexts, 2)
		require.Equal(t, id2, contexts[0].Container())
		require.Equal(t, id1, contexts[1].Container())
	})
}

func TestParseS3GateKeys(t *testing.T) {
	gateKey1, err := keys.NewPrivateKey()
	require.NoError(t, err)
	gateKey2, err := keys.NewPrivateKey()
	require.NoError(t, err)

	t.Run("empty", func(t *testing.T) {
		_, err := parseS3GateKeys(nil)
		require.ErrorContains(t, err, "at least one")
	})

	t.Run("deduplicated", func(t *testing.T) {
		hexKey1 := hex.EncodeToString(gateKey1.PublicKey().Bytes())
		hexKey2 := hex.EncodeToString(gateKey2.PublicKey().Bytes())

		parsed, err := parseS3GateKeys([]string{hexKey1, hexKey2, hexKey1})
		require.NoError(t, err)
		require.Len(t, parsed, 2)
		require.True(t, parsed[0].Equal(gateKey1.PublicKey()))
		require.True(t, parsed[1].Equal(gateKey2.PublicKey()))
	})

	t.Run("malformed key", func(t *testing.T) {
		_, err := parseS3GateKeys([]string{"zz"})
		require.ErrorContains(t, err, "invalid gate key")
	})
}
