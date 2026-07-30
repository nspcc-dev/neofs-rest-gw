package handlers

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-rest-gw/internal/accessbox"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	sessionv2 "github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

const (
	s3SecretLength = 32
	s3StateVersion = 1

	// The gateway itself occupies one subject slot in every issued token:
	// it uses the token to store the credential box on behalf of the user.
	maxS3GatesPerToken = sessionv2.MaxSubjectsPerToken - 1
)

var defaultS3SessionVerbs = []sessionv2.Verb{
	sessionv2.VerbObjectPut,
	sessionv2.VerbObjectGet,
	sessionv2.VerbObjectHead,
	sessionv2.VerbObjectSearch,
	sessionv2.VerbObjectDelete,
	sessionv2.VerbObjectRange,
	sessionv2.VerbContainerPut,
	sessionv2.VerbContainerDelete,
	sessionv2.VerbContainerSetEACL,
	sessionv2.VerbContainerSetAttribute,
	sessionv2.VerbContainerRemoveAttribute,
}

// PrepareS3Credentials handler forms unsigned session v2 tokens
// carrying encrypted S3 credentials for configured S3 gateways.
func (a *RestAPI) PrepareS3Credentials(ctx echo.Context) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.PrepareS3CredentialsDuration)()
	}

	var (
		// https://github.com/nspcc-dev/neofs-node/pull/3671#discussion_r2709969518
		tokenIssueTime = time.Now().Add(-10 * time.Second)
		apiParams      apiserver.S3CredentialsRequest
		log            = a.log.With(zap.String(handlerFieldName, "PrepareS3Credentials"))
	)

	if err := ctx.Bind(&apiParams); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	var owner user.ID
	if err := owner.DecodeString(apiParams.Issuer); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid issuer", err, log))
	}

	var authCnrID cid.ID
	if err := authCnrID.DecodeString(apiParams.ContainerId); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid container id", err, log))
	}
	if authCnrID.IsZero() {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid container id", errors.New("zero container id"), log))
	}

	gateKeys, err := parseS3GateKeys(apiParams.Gates)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("gate keys", err, log))
	}

	contexts, err := prepareS3TokenContexts(apiParams.Contexts, authCnrID)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid contexts", err, log))
	}

	expiration, err := prepareSessionTokenV2Expiration(tokenIssueTime, apiserver.SessionTokenV2Request{
		ExpirationRfc3339:   apiParams.ExpirationRfc3339,
		ExpirationTimestamp: apiParams.ExpirationTimestamp,
		ExpirationDuration:  apiParams.ExpirationDuration,
	})
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid expiration", err, log))
	}

	secret := make([]byte, s3SecretLength)
	_, _ = rand.Read(secret)

	ephemeralKey, err := keys.NewPrivateKey()
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, a.logAndGetErrorResponse("ephemeral key", err, log))
	}

	tokens, err := buildS3SessionTokens(gateKeys, a.gatePrivateKey.PublicKey(), owner, contexts, tokenIssueTime, expiration, ephemeralKey, secret)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("build session tokens", err, log))
	}

	// For validation purposes only.
	for i := range tokens {
		validated := tokens[i]
		validated.AttachSignature(fakeSignature)
		if err = validated.Validate(&noopNNSResolver{}); err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("session token v2 validation", err, log))
		}
	}

	state, err := a.packS3State(secret, ephemeralKey, authCnrID)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, a.logAndGetErrorResponse("seal state", err, log))
	}

	resp := apiserver.S3CredentialsResponse{
		Tokens: make([]string, 0, len(tokens)),
		State:  state,
	}
	for i := range tokens {
		resp.Tokens = append(resp.Tokens, base64.StdEncoding.EncodeToString(tokens[i].SignedData()))
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

// CompleteS3Credentials handler that checks token signatures, stores the
// credential box in NeoFS and returns ready to use S3 credentials.
func (a *RestAPI) CompleteS3Credentials(ctx echo.Context) error {
	if a.apiMetric != nil {
		defer metrics.Elapsed(a.apiMetric.CompleteS3CredentialsDuration)()
	}

	var (
		apiParams apiserver.CompleteS3CredentialsRequest
		log       = a.log.With(zap.String(handlerFieldName, "CompleteS3Credentials"))
	)

	if err := ctx.Bind(&apiParams); err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("bind", err, log))
	}

	secret, ephemeralKey, cnrID, err := a.unpackS3State(apiParams.State)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid state", err, log))
	}

	if len(apiParams.Tokens) == 0 {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("no tokens", errors.New("at least one token required"), log))
	}

	var (
		gwID          = a.signer.UserID()
		issuer        user.ID
		sessionTokens = make([]sessionv2.Token, 0, len(apiParams.Tokens))
	)

	for i, signed := range apiParams.Tokens {
		token, err := a.completeS3SessionToken(signed, ephemeralKey.PublicKey(), secret, gwID)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid token", err, log))
		}

		if i == 0 {
			issuer = token.Issuer()
		} else if token.Issuer() != issuer {
			return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid token", errors.New("all tokens must have the same issuer"), log))
		}

		sessionTokens = append(sessionTokens, token)
	}

	var (
		reqCtx = ctx.Request().Context()
		// Any of the tokens authorizes the gateway, take the first one.
		gwToken = &sessionTokens[0]
	)

	cnr, err := getContainer(reqCtx, a.pool, cnrID)
	if err != nil {
		return ctx.JSON(getResponseCodeFromStatus(err), a.logAndGetErrorResponse("get container", err, log))
	}

	if cnr.Owner() != issuer {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid container", errors.New("auth container is not owned by the issuer"), log))
	}

	if !gwToken.AssertVerb(sessionv2.VerbObjectPut, cnrID) {
		return ctx.JSON(http.StatusBadRequest, a.logAndGetErrorResponse("invalid token", errors.New("token doesn't allow OBJECT_PUT required to store the credential box"), log))
	}

	box, err := accessbox.PackTokens(sessionTokens, ephemeralKey.PublicKey().Bytes())
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, a.logAndGetErrorResponse("pack tokens", err, log))
	}

	payload, err := box.Marshal()
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, a.logAndGetErrorResponse("marshal access box", err, log))
	}

	durations, err := getEpochDurations(reqCtx, a.networkInfoGetter)
	if err != nil {
		return ctx.JSON(getResponseCodeFromStatus(err), a.logAndGetErrorResponse("get epoch durations", err, log))
	}

	var (
		now             = time.Now()
		expirationAttrs = map[string]string{}
	)
	updateExpirationHeader(expirationAttrs, durations, gwToken.Exp().Sub(now))

	var hdr object.Object
	hdr.SetContainerID(cnrID)
	hdr.SetOwner(issuer)
	hdr.SetPayloadSize(uint64(len(payload)))
	hdr.SetAttributes(
		object.NewAttribute(object.AttributeFilePath, strconv.FormatInt(now.UnixNano(), 10)+"_access.box"),
		object.NewAttribute(object.AttributeTimestamp, strconv.FormatInt(now.Unix(), 10)),
		object.NewAttribute(object.AttributeExpirationEpoch, expirationAttrs[object.AttributeExpirationEpoch]),
	)

	var wp = func(w io.Writer) error {
		_, err := w.Write(payload)
		return err
	}

	objID, err := a.putObject(ctx, hdr, nil, gwToken, wp)
	if err != nil {
		return ctx.JSON(getResponseCodeFromStatus(err), a.logAndGetErrorResponse("put access box", err, log))
	}

	resp := apiserver.CompleteS3CredentialsResponse{
		AccessKeyId:     cnrID.EncodeToString() + "0" + objID.EncodeToString(),
		SecretAccessKey: hex.EncodeToString(secret),
		ContainerId:     cnrID.EncodeToString(),
	}

	ctx.Response().Header().Set(accessControlAllowOriginHeader, "*")
	return ctx.JSON(http.StatusOK, resp)
}

func parseS3GateKeys(requested []string) (keys.PublicKeys, error) {
	if len(requested) == 0 {
		return nil, errors.New("at least one S3 gateway key required")
	}

	var result keys.PublicKeys

	for _, s := range requested {
		gateKey, err := keys.NewPublicKeyFromString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid gate key %q: %w", s, err)
		}

		if !result.Contains(gateKey) {
			result = append(result, gateKey)
		}
	}

	return result, nil
}

func prepareS3TokenContexts(apiContexts []apiserver.TokenContext, authCnrID cid.ID) ([]sessionv2.Context, error) {
	verbsByCnr := make(map[cid.ID]map[sessionv2.Verb]struct{}, len(apiContexts)+1)

	if len(apiContexts) == 0 {
		wildcardVerbs := make(map[sessionv2.Verb]struct{}, len(defaultS3SessionVerbs))
		for _, v := range defaultS3SessionVerbs {
			wildcardVerbs[v] = struct{}{}
		}

		verbsByCnr[cid.ID{}] = wildcardVerbs
	}

	for _, apiTokenContext := range apiContexts {
		var cnrID cid.ID
		if apiTokenContext.ContainerID != "" {
			if err := cnrID.DecodeString(apiTokenContext.ContainerID); err != nil {
				return nil, fmt.Errorf("invalid container id: %w", err)
			}
		}

		if _, ok := verbsByCnr[cnrID]; ok {
			return nil, fmt.Errorf("two different contexts have the same container: %s", cnrID)
		}

		if len(apiTokenContext.Verbs) == 0 {
			return nil, errors.New("context must have at least one verb")
		}

		uniqueVerbs := make(map[sessionv2.Verb]struct{}, len(apiTokenContext.Verbs))
		for _, verb := range apiTokenContext.Verbs {
			v, err := sessionVerbV2(verb)
			if err != nil {
				return nil, fmt.Errorf("invalid verb: %w", err)
			}

			uniqueVerbs[v] = struct{}{}
		}

		verbsByCnr[cnrID] = uniqueVerbs
	}

	if _, ok := verbsByCnr[authCnrID]; !ok {
		verbsByCnr[authCnrID] = make(map[sessionv2.Verb]struct{}, 2)
	}
	verbsByCnr[authCnrID][sessionv2.VerbObjectGet] = struct{}{}
	verbsByCnr[authCnrID][sessionv2.VerbObjectPut] = struct{}{}

	contexts := make([]sessionv2.Context, 0, len(verbsByCnr))
	for cnrID, verbs := range verbsByCnr {
		newContext, err := sessionv2.NewContext(cnrID, slices.Sorted(maps.Keys(verbs)))
		if err != nil {
			return nil, fmt.Errorf("session context: %w", err)
		}

		contexts = append(contexts, newContext)
	}

	slices.SortFunc(contexts, func(a, b sessionv2.Context) int {
		return a.Container().Compare(b.Container())
	})

	return contexts, nil
}

func buildS3SessionTokens(gateKeys keys.PublicKeys, gwKey *keys.PublicKey, issuer user.ID, contexts []sessionv2.Context, issueTime, expiration time.Time, ephemeralKey *keys.PrivateKey, secret []byte) ([]sessionv2.Token, error) {
	var tokens []sessionv2.Token

	for chunk := range slices.Chunk(gateKeys, maxS3GatesPerToken) {
		subjectKeys := slices.Clone(chunk)
		if !subjectKeys.Contains(gwKey) {
			subjectKeys = append(subjectKeys, gwKey)
		}

		var (
			token   sessionv2.Token
			targets = make([]sessionv2.Target, 0, len(subjectKeys))
			appData = bytes.NewBuffer(make([]byte, 0, len(subjectKeys)*accessbox.EncryptedSecretLength))
		)

		// The app data holds one encrypted secret per subject, in the
		// subjects order: that is how S3 gateways locate their entry.
		for _, subjectKey := range subjectKeys {
			targets = append(targets, sessionv2.NewTargetUser(user.NewFromScriptHash(subjectKey.GetScriptHash())))

			enc, err := accessbox.Encrypt(ephemeralKey, subjectKey, secret)
			if err != nil {
				return nil, fmt.Errorf("encrypt secret: %w", err)
			}

			appData.Write(enc)
		}

		if err := token.SetSubjects(targets); err != nil {
			return nil, fmt.Errorf("set subjects: %w", err)
		}

		if err := token.SetContexts(contexts); err != nil {
			return nil, fmt.Errorf("set contexts: %w", err)
		}

		if err := token.SetAppData(appData.Bytes()); err != nil {
			return nil, fmt.Errorf("set app data: %w", err)
		}

		token.SetNbf(issueTime)
		token.SetIat(issueTime)
		token.SetExp(expiration)
		token.SetIssuer(issuer)
		token.SetVersion(sessionv2.TokenCurrentVersion)

		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (a *RestAPI) completeS3SessionToken(signed apiserver.S3SignedToken, ephemeralPub *keys.PublicKey, secret []byte, gwID user.ID) (sessionv2.Token, error) {
	var (
		token  sessionv2.Token
		scheme neofscrypto.Scheme
	)

	switch signed.Scheme {
	case apiserver.WALLETCONNECT:
		scheme = neofscrypto.ECDSA_WALLETCONNECT
	case apiserver.SHA512:
		scheme = neofscrypto.ECDSA_SHA512
	case apiserver.DETERMINISTICSHA256:
		scheme = neofscrypto.ECDSA_DETERMINISTIC_SHA256
	case apiserver.N3:
		scheme = neofscrypto.N3
	default:
		return token, fmt.Errorf("unknown scheme: %s", signed.Scheme)
	}

	tokenBts, err := base64.StdEncoding.DecodeString(signed.Token)
	if err != nil {
		return token, fmt.Errorf("malformed base64 encoding: %w", err)
	}

	if err = token.UnmarshalSignedData(tokenBts); err != nil {
		return token, fmt.Errorf("malformed session token: %w", err)
	}

	signatureValue, err := decodeHexOrBase64(signed.Signature)
	if err != nil {
		return token, fmt.Errorf("couldn't decode session token signature: %w", err)
	}

	signatureKey, err := decodeHexOrBase64(signed.Key)
	if err != nil {
		return token, fmt.Errorf("couldn't fetch token owner key: %w", err)
	}

	if scheme == neofscrypto.N3 {
		token.AttachSignature(neofscrypto.NewN3Signature(signatureValue, signatureKey))
	} else {
		if _, err = keys.NewPublicKeyFromBytes(signatureKey, elliptic.P256()); err != nil {
			return token, fmt.Errorf("couldn't extract token owner key: %w", err)
		}

		token.AttachSignature(neofscrypto.NewSignatureFromRawKey(scheme, signatureKey, signatureValue))
		if !token.VerifySignature() {
			return token, errors.New("invalid signature")
		}
	}

	if err = token.Validate(&noopNNSResolver{}); err != nil {
		return token, fmt.Errorf("session token v2 validation: %w", err)
	}

	subjects := token.Subjects()
	if len(token.AppData()) != len(subjects)*accessbox.EncryptedSecretLength {
		return token, errors.New("unexpected app data size")
	}

	gwIndex := slices.IndexFunc(subjects, func(t sessionv2.Target) bool {
		return t.UserID() == gwID
	})
	if gwIndex == -1 {
		return token, errors.New("gateway is not a subject of the token")
	}

	// Decrypting our own entry proves the token comes from the prepare call that produced the state.
	slot := token.AppData()[gwIndex*accessbox.EncryptedSecretLength : (gwIndex+1)*accessbox.EncryptedSecretLength]
	decrypted, err := accessbox.Decrypt(a.gatePrivateKey, ephemeralPub, slot)
	if err != nil || !bytes.Equal(decrypted, secret) {
		return token, errors.New("token doesn't match the state")
	}

	return token, nil
}

// packS3State packs the issuance secrets and the auth container into a state string
// encrypted to the gateway gatePrivateKey, so the flow needs no server-side state
// between the prepare and complete calls.
func (a *RestAPI) packS3State(secret []byte, ephemeralKey *keys.PrivateKey, cnrID cid.ID) (string, error) {
	plain := make([]byte, 0, 1+s3SecretLength+len(ephemeralKey.Bytes())+len(cnrID))
	plain = append(plain, s3StateVersion)
	plain = append(plain, secret...)
	plain = append(plain, ephemeralKey.Bytes()...)
	plain = append(plain, cnrID[:]...)

	sealed, err := accessbox.Encrypt(a.gatePrivateKey, a.gatePrivateKey.PublicKey(), plain)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sealed), nil
}

func (a *RestAPI) unpackS3State(state string) ([]byte, *keys.PrivateKey, cid.ID, error) {
	var cnrID cid.ID

	sealed, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return nil, nil, cnrID, fmt.Errorf("malformed base64 encoding: %w", err)
	}

	plain, err := accessbox.Decrypt(a.gatePrivateKey, a.gatePrivateKey.PublicKey(), sealed)
	if err != nil {
		return nil, nil, cnrID, fmt.Errorf("decrypt: %w", err)
	}

	if len(plain) != 1+s3SecretLength+32+len(cnrID) || plain[0] != s3StateVersion {
		return nil, nil, cnrID, errors.New("unexpected state format")
	}

	ephemeralKey, err := keys.NewPrivateKeyFromBytes(plain[1+s3SecretLength : 1+s3SecretLength+32])
	if err != nil {
		return nil, nil, cnrID, fmt.Errorf("ephemeral key: %w", err)
	}

	cnrID = cid.ID(plain[1+s3SecretLength+32:])

	return plain[1 : 1+s3SecretLength], ephemeralKey, cnrID, nil
}
