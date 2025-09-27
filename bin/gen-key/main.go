package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"log"
)

func main() {
	// private key is 64bytes priv/pub
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	pubEnc := base64.StdEncoding.EncodeToString(pub)
	privEnc := base64.StdEncoding.EncodeToString(priv)

	log.Printf("[PUBLIC KEY] %s", pubEnc)
	log.Printf("[PRIVATE KEY] %s", privEnc)
}
