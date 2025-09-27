package sigser

import "crypto"

// serializer for client
type SigSer struct {
	privateKey crypto.PrivateKey
}

// deserializer for server
type SigDe struct {
	publicKey crypto.PublicKey
}
