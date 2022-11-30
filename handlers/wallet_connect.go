package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"

	crypto "github.com/nspcc-dev/neofs-crypto"
)

const (
	// saltSize is the salt size added to signed message.
	saltSize = 16
	// signatureLen is the length of RFC6979 signature.
	signatureLen = 64
)

// SignedMessage contains mirrors `SignedMessage` struct from the WalletConnect API.
// https://neon.coz.io/wksdk/core/modules.html#SignedMessage
type SignedMessage struct {
	Data      []byte
	Message   []byte
	PublicKey []byte
	Salt      []byte
}

// Verify verifies message using WalletConnect API.
func Verify(p *ecdsa.PublicKey, data, sign []byte) bool {
	if len(sign) != signatureLen+saltSize {
		return false
	}

	//salt := sign[signatureLen:]
	return VerifyMessage(p, SignedMessage{
		Data:    sign[:signatureLen],
		Message: data,
		//Salt:    salt,
	})
}

// SignMessage signs message with a private key and returns structure similar to
// `signMessage` of the WalletConnect API.
// https://github.com/CityOfZion/wallet-connect-sdk/blob/eca3e5a4d9707c7a9c4d2828a7bf64222ce563ef/packages/wallet-connect-sdk-core/src/index.ts#L318
// https://github.com/CityOfZion/neon-wallet/blob/a5a3ded5d2db80649a528a195a5914709df2d587/app/context/WalletConnect/helpers.js#L185
func SignMessage(p *ecdsa.PrivateKey, msg []byte) (SignedMessage, error) {
	// It seems we have to fix sing in neofs-crypto
	// https://github.com/CityOfZion/neon-js/blob/f316675898117cddf03ea089e3177ef05877845f/packages/neon-core/src/wallet/signing.ts#L23
	// https://github.com/CityOfZion/neon-js/blob/f316675898117cddf03ea089e3177ef05877845f/packages/neon-core/src/u/basic/curve.ts#L32
	panic("not implemented")
}

// VerifyMessage verifies message with a private key and returns structure similar to
// `verifyMessage` of WalletConnect API.
// https://github.com/CityOfZion/wallet-connect-sdk/blob/eca3e5a4d9707c7a9c4d2828a7bf64222ce563ef/packages/wallet-connect-sdk-core/src/index.ts#L345
// https://github.com/CityOfZion/neon-wallet/blob/a5a3ded5d2db80649a528a195a5914709df2d587/app/context/WalletConnect/helpers.js#L197
func VerifyMessage(p *ecdsa.PublicKey, m SignedMessage) bool {
	if p == nil {
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), m.PublicKey)
		if x == nil || y == nil {
			return false
		}
		p = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
	}
	return crypto.VerifyRFC6979(p, m.Message, m.Data) == nil
}
