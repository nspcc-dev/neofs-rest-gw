package accessbox

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"google.golang.org/protobuf/proto"
)

const (
	accessBoxVersionSessionV2 = 1

	// EncryptedSecretLength is the length of a single encrypted secret
	// entry in the session token app data: 16 bytes of HKDF salt, 12
	// bytes of AES-GCM nonce, 32 bytes of ciphertext and 16 bytes of tag.
	EncryptedSecretLength = 76
)

// GateData represents gate tokens in AccessBox.
type GateData struct {
	AccessKey      string
	SessionTokenV2 *session.Token
}

var errDecodeFailed = errors.New("failed to decode accessbox")

// Marshal returns the wire-format of AccessBox.
func (x *AccessBox) Marshal() ([]byte, error) {
	return proto.Marshal(x)
}

// Unmarshal parses the wire-format message and put data to x.
func (x *AccessBox) Unmarshal(data []byte) error {
	return proto.Unmarshal(data, x)
}

// PackTokens forms an AccessBox from signed session tokens. Each token
// carries encrypted secrets for its subjects in the app data, the
// ephemeral public key is the ECDH sender key those secrets were
// encrypted with.
func PackTokens(tokens []session.Token, ephemeralPublicKey []byte) (*AccessBox, error) {
	box := &AccessBox{
		OwnerPublicKey: ephemeralPublicKey,
		Version:        accessBoxVersionSessionV2,
	}

	for i := range tokens {
		msg := &TokensV2{
			SessionTokenV2: tokens[i].Marshal(),
		}

		data, err := proto.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("encode tokens: %w", err)
		}

		box.Gates = append(box.Gates, &AccessBox_Gate{Tokens: data})
	}

	return box, nil
}

// GetTokens returns the gate data for the given gate key from AccessBox.
// It mirrors the read path of neofs-s3-gw and is used to verify produced
// boxes.
func (x *AccessBox) GetTokens(owner *keys.PrivateKey, resolver session.NNSResolver) (*GateData, error) {
	if x.Version != accessBoxVersionSessionV2 {
		return nil, fmt.Errorf("unsupported access box version %d (current: %d)", x.Version, accessBoxVersionSessionV2)
	}

	sender, err := keys.NewPublicKeyFromBytes(x.OwnerPublicKey, elliptic.P256())
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal OwnerPublicKey: %w", err)
	}
	ownerID := user.NewFromScriptHash(owner.PublicKey().GetScriptHash())

	for _, gate := range x.Gates {
		gateData, err := decodeGateV2(gate, owner, sender)
		if err != nil {
			if errors.Is(err, errDecodeFailed) {
				continue
			}

			return nil, fmt.Errorf("failed to decode gate: %w", err)
		}

		ok, err := gateData.SessionTokenV2.AssertAuthority(ownerID, resolver)
		if err != nil {
			return nil, fmt.Errorf("failed to check authority: %w", err)
		}

		// this token doesn't belong to this gate.
		if !ok {
			continue
		}

		return gateData, nil
	}

	return nil, fmt.Errorf("no gate data for key %x was found", owner.PublicKey().Bytes())
}

func decodeGateV2(gate *AccessBox_Gate, owner *keys.PrivateKey, sender *keys.PublicKey) (*GateData, error) {
	var tokens TokensV2
	if err := proto.Unmarshal(gate.Tokens, &tokens); err != nil {
		return nil, fmt.Errorf("unmarshal tokens: %w", err)
	}

	var (
		stv2       session.Token
		gateUserID = user.NewFromScriptHash(owner.GetScriptHash())
		index      = -1
	)

	if err := stv2.Unmarshal(tokens.SessionTokenV2); err != nil {
		return nil, fmt.Errorf("unmarshal session token v2: %w", err)
	}

	var appData = stv2.AppData()
	if len(appData) == 0 {
		return nil, errors.New("empty app data")
	}

	for i, target := range stv2.Subjects() {
		if target.UserID() == gateUserID {
			index = i
			break
		}
	}

	if index == -1 {
		return nil, errDecodeFailed
	}

	startIndex := EncryptedSecretLength * index
	if startIndex+EncryptedSecretLength > len(appData) {
		return nil, errors.New("gate component not found in token app data")
	}

	enc := appData[startIndex : startIndex+EncryptedSecretLength]

	accessKey, err := Decrypt(owner, sender, enc)
	if err != nil {
		return nil, err
	}

	return &GateData{
		AccessKey:      hex.EncodeToString(accessKey),
		SessionTokenV2: &stv2,
	}, nil
}
