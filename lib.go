package sigser

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"time"
)

const _SIGSER_CTX = "sigser-Version-0.0.1"
const _MAX_TIMESTAMP_GAP_SEC = 60

type SignedPayload struct {
	Payload   string `json:"payload" msgpack:"payload"`
	Signature string `json:"signature" msgpack:"signature"`
	Timestamp uint64 `json:"timestamp" msgpack:"timestamp"`
}

// serializer interface for client
type SigSerialize interface {
	SignMarshal(v any) ([]byte, error)
}

// deserilzer interface for server
type SigDeserialize interface {
	SignUnmarshal(data []byte, v any) error
}

// key holder for client
type SigSer struct {
	privateKey ed25519.PrivateKey
}

// read private key from env
//
// consider other construction first
func NewSigSerFromEnv(envKey string) (SigSer, error) {
	privEnc := os.Getenv(envKey)
	if len(privEnc) == 0 {
		return SigSer{nil}, errors.New("could not find env var for private key")
	}

	return NewSigSerFromString(privEnc)
}

// from base64 encoded private key
func NewSigSerFromString(privEnc string) (SigSer, error) {
	b, err := base64.StdEncoding.DecodeString(privEnc)
	if err != nil {
		return SigSer{nil}, err
	}

	return NewSigSer(b)
}

func NewSigSer(privatekey ed25519.PrivateKey) (SigSer, error) {
	if len(privatekey) != ed25519.PrivateKeySize {
		return SigSer{nil}, errors.New("invalid private key size")
	}

	return SigSer{privatekey}, nil
}

func (ser *SigSer) Sign(message []byte) ([]byte, error) {
	op := ed25519.Options{
		Context: _SIGSER_CTX,
	}
	return ser.privateKey.Sign(nil, message, &op)
}

// key holder for server
type SigDe struct {
	publicKey ed25519.PublicKey
}

// read public key from env
//
// consider other construction first
func NewSigDeFromEnv(envKey string) (SigDe, error) {
	pubEnc := os.Getenv(envKey)
	if len(pubEnc) == 0 {
		return SigDe{nil}, errors.New("could not find env var for public key")
	}

	return NewSigDeFromString(pubEnc)
}

// from base64 encoded public key
func NewSigDeFromString(pubEnc string) (SigDe, error) {
	b, err := base64.StdEncoding.DecodeString(pubEnc)
	if err != nil {
		return SigDe{nil}, err
	}

	return NewSigDe(b)
}

func NewSigDe(publicKey ed25519.PublicKey) (SigDe, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return SigDe{nil}, errors.New("invalid public key size")
	}

	return SigDe{publicKey}, nil
}

func CheckTimestamp(origin uint64) error {
	now := uint64(time.Now().Unix())
	gap := now - origin
	if gap > _MAX_TIMESTAMP_GAP_SEC {
		return errors.New("timestamp is too old")
	}
	return nil
}

func (de *SigDe) Verify(message []byte, sig []byte) error {
	op := ed25519.Options{
		Context: _SIGSER_CTX,
	}
	return ed25519.VerifyWithOptions(de.publicKey, message, sig, &op)
}
