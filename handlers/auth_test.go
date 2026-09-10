package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/util"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const devenvPrivateKey = "1dd37fba80fec4e6a6f13fd708d8dcb3b29def768017052f6c930fa1c5d90bbb"

func TestSign(t *testing.T) {
	key, err := keys.NewPrivateKeyFromHex(devenvPrivateKey)
	require.NoError(t, err)

	pubKeyHex := hex.EncodeToString(key.PublicKey().Bytes())
	oth := apiserver.OTHERS

	records := []apiserver.Record{{
		Operation: apiserver.PUT,
		Action:    apiserver.ALLOW,
		Filters:   []apiserver.Filter{},
		Targets: []apiserver.Target{{
			Role: &oth,
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

func makeV2SessionToken(t *testing.T, api *RestAPI, req apiserver.SessionTokenV2Request) session.Token {
	t.Helper()

	body, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/v2/auth/session", bytes.NewReader(body))
	httpReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	require.NoError(t, api.V2AuthSessionToken(echo.New().NewContext(httpReq, rec)))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp apiserver.SessionTokenv2Response
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	signedData, err := base64.StdEncoding.DecodeString(resp.Token)
	require.NoError(t, err)

	var token session.Token
	require.NoError(t, token.UnmarshalSignedData(signedData))

	return token
}

func TestV2AuthSessionTokenIssueTime(t *testing.T) {
	key, err := keys.NewPrivateKey()
	require.NoError(t, err)

	signer := user.NewAutoIDSigner(key.PrivateKey)
	issuer := signer.UserID()

	cnrID, err := cid.DecodeString("9JCbLjeipa75ymzkcyDpocWyFjmsTuYjGw8aSdJKxUn7")
	require.NoError(t, err)

	api := &RestAPI{log: zap.NewNop()}
	request := apiserver.SessionTokenV2Request{
		Contexts: []apiserver.TokenContext{{ContainerID: cnrID.String(), Verbs: []apiserver.TokenVerb{"CONTAINER_PUT"}}},
		Issuer:   issuer.String(),
		Targets:  []string{issuer.String()},
	}

	t.Run("shifted back in time", func(t *testing.T) {
		now := time.Now()
		token := makeV2SessionToken(t, api, request)

		require.WithinRange(t, token.Iat(), now.Add(-tokenIssueTimeShift-time.Minute), now.Add(-tokenIssueTimeShift+time.Second))
		require.Equal(t, token.Iat(), token.Nbf())
	})

	t.Run("short lifetime is not reduced by the issue time shift", func(t *testing.T) {
		shortExpiration := "30s"

		req := request
		req.ExpirationDuration = &shortExpiration

		now := time.Now()
		token := makeV2SessionToken(t, api, req)

		require.True(t, token.Exp().After(now), "token must not be born expired")
		require.WithinRange(t, token.Exp(), now.Add(30*time.Second-time.Second), now.Add(30*time.Second+time.Minute))
	})

	t.Run("not earlier than origin", func(t *testing.T) {
		originKey, err := keys.NewPrivateKey()
		require.NoError(t, err)

		var (
			originSigner = user.NewAutoIDSigner(originKey.PrivateKey)
			originToken  session.Token
			now          = time.Now()
		)

		originToken.SetIat(now)
		originToken.SetNbf(now)
		originToken.SetExp(now.Add(48 * time.Hour))
		originToken.SetIssuer(originSigner.UserID())
		originToken.SetVersion(session.TokenCurrentVersion)

		originCtx, err := session.NewContext(cnrID, []session.Verb{session.VerbContainerPut})
		require.NoError(t, err)
		require.NoError(t, originToken.SetContexts([]session.Context{originCtx}))
		require.NoError(t, originToken.SetSubjects([]session.Target{session.NewTargetUser(issuer)}))
		require.NoError(t, originToken.Sign(originSigner))

		req := request
		req.Origin = base64.StdEncoding.EncodeToString(originToken.Marshal())

		token := makeV2SessionToken(t, api, req)

		require.Equal(t, originToken.Nbf(), token.Nbf())
		require.True(t, token.Iat().Before(token.Nbf()))
	})
}
