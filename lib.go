package sigser

import (
	"crypto/ed25519"
	"encoding/base64"
)

// serializer for client
type SigSer struct {
	privateKey ed25519.PrivateKey
}

// from base64 encoded private key
func NewSigSer(privEnc string) (SigSer, error) {
	sigser := SigSer{nil}
	b, err := base64.StdEncoding.DecodeString(privEnc)
	if err != nil {
		return sigser, err
	}

	sigser.privateKey = b
	return sigser, nil
}

// deserializer for server
type SigDe struct {
	publicKey ed25519.PublicKey
}

// from base64 encoded public key
func NewSigDe(pubEnc string) (SigDe, error) {
	sigde := SigDe{nil}
	b, err := base64.StdEncoding.DecodeString(pubEnc)
	if err != nil {
		return sigde, err
	}

	sigde.publicKey = b
	return sigde, nil
}
