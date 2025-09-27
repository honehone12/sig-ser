package sigser

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
)

const SIGSER_CTX = "sigser-Version-0.0.1"

type SignedJson struct {
	Json      string `json:"json"`
	Signature string `json:"signature"`
	// add timestamp
}

// serializer for client
type SigSer struct {
	privateKey ed25519.PrivateKey
}

func NewSigSerFromEnv(envKey string) (*SigSer, error) {
	privEnc := os.Getenv(envKey)
	if len(privEnc) == 0 {
		return nil, errors.New("could not find env var for private key")
	}

	return NewSigSerFromString(privEnc)
}

// from base64 encoded private key
func NewSigSerFromString(privEnc string) (*SigSer, error) {
	b, err := base64.StdEncoding.DecodeString(privEnc)
	if err != nil {
		return nil, err
	}

	return NewSigSer(b)
}

func NewSigSer(privatekey ed25519.PrivateKey) (*SigSer, error) {
	if len(privatekey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}

	return &SigSer{privatekey}, nil
}

func (ser *SigSer) Marshal(v any) ([]byte, error) {
	inner, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	op := ed25519.Options{
		Context: SIGSER_CTX,
	}
	sig, err := ser.privateKey.Sign(nil, inner, &op)
	if err != nil {
		return nil, err
	}

	sigJ := SignedJson{
		Json:      base64.StdEncoding.EncodeToString(inner),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	return json.Marshal(sigJ)
}

// deserializer for server
type SigDe struct {
	publicKey ed25519.PublicKey
}

func NewSigDeFromEnv(envKey string) (*SigDe, error) {
	pubEnc := os.Getenv(envKey)
	if len(pubEnc) == 0 {
		return nil, errors.New("could not find env var for public key")
	}

	return NewSigDeFromString(pubEnc)
}

// from base64 encoded public key
func NewSigDeFromString(pubEnc string) (*SigDe, error) {
	b, err := base64.StdEncoding.DecodeString(pubEnc)
	if err != nil {
		return nil, err
	}

	return NewSigDe(b)
}

func NewSigDe(publicKey ed25519.PublicKey) (*SigDe, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key size")
	}

	return &SigDe{publicKey}, nil
}

func (de *SigDe) Unmarshal(data []byte, v any) error {
	sigJ := SignedJson{}
	err := json.Unmarshal(data, &sigJ)
	if err != nil {
		return err
	}

	inner, err := base64.StdEncoding.DecodeString(sigJ.Json)
	if err != nil {
		return err
	}

	sig, err := base64.StdEncoding.DecodeString(sigJ.Signature)
	if err != nil {
		return err
	}

	op := ed25519.Options{
		Context: SIGSER_CTX,
	}
	err = ed25519.VerifyWithOptions(de.publicKey, inner, sig, &op)
	if err != nil {
		return err
	}

	return json.Unmarshal(inner, v)
}
