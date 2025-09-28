package sigser

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"time"
)

const SIGSER_CTX = "sigser-Version-0.0.1"
const MAX_TIMESTAMP_GAP_SEC = 60

type SignedJson struct {
	Json      string `json:"json"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

// serializer for client
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

func (ser *SigSer) Marshal(v any) ([]byte, error) {
	inner, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	b := make([]byte, len(inner)+8)
	binary.BigEndian.PutUint64(b, uint64(now))
	copy(b[8:], inner)

	op := ed25519.Options{
		Context: SIGSER_CTX,
	}
	sig, err := ser.privateKey.Sign(nil, b, &op)
	if err != nil {
		return nil, err
	}

	sigJ := SignedJson{
		Json:      string(inner),
		Signature: base64.StdEncoding.EncodeToString(sig),
		Timestamp: now,
	}

	return json.Marshal(sigJ)
}

// deserializer for server
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

func (de SigDe) Unmarshal(data []byte, v any) error {
	sigJ := SignedJson{}
	err := json.Unmarshal(data, &sigJ)
	if err != nil {
		return err
	}

	// check timestamp
	now := time.Now().Unix()
	gap := now - sigJ.Timestamp
	if gap > MAX_TIMESTAMP_GAP_SEC {
		return errors.New("timestamp is too old")
	}

	inner := []byte(sigJ.Json)
	b := make([]byte, len(inner)+8)
	binary.BigEndian.PutUint64(b, uint64(sigJ.Timestamp))
	copy(b[8:], inner)

	sig, err := base64.StdEncoding.DecodeString(sigJ.Signature)
	if err != nil {
		return err
	}

	op := ed25519.Options{
		Context: SIGSER_CTX,
	}
	err = ed25519.VerifyWithOptions(de.publicKey, b, sig, &op)
	if err != nil {
		return err
	}

	return json.Unmarshal(inner, v)
}
