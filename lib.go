package sigser

import (
	"crypto/ed25519"
)

// serializer for client
type SigSer struct {
	privateKey ed25519.PrivateKey
}

func NewSigSer()

// deserializer for server
type SigDe struct {
	publicKey ed25519.PublicKey
}
