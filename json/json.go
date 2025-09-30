package json

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sigser"
	"time"
)

func Marshal(v any, ser sigser.SigSer) ([]byte, error) {
	inner, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	b := make([]byte, len(inner)+8)
	binary.BigEndian.PutUint64(b, uint64(now))
	copy(b[8:], inner)

	sig, err := ser.Sign(b)
	if err != nil {
		return nil, err
	}

	sigP := sigser.SignedPayload{
		Payload:   string(inner),
		Signature: base64.StdEncoding.EncodeToString(sig),
		Timestamp: uint64(now),
	}

	return json.Marshal(sigP)
}

func Unmarshal(data []byte, v any, de sigser.SigDe) error {
	sigP := sigser.SignedPayload{}
	err := json.Unmarshal(data, &sigP)
	if err != nil {
		return err
	}

	err = sigser.CheckTimestamp(sigP.Timestamp)
	if err != nil {
		return err
	}

	inner := []byte(sigP.Payload)
	b := make([]byte, len(inner)+8)
	binary.BigEndian.PutUint64(b, sigP.Timestamp)
	copy(b[8:], inner)

	sig, err := base64.StdEncoding.DecodeString(sigP.Signature)
	if err != nil {
		return err
	}

	err = de.Verify(inner, sig)
	if err != nil {
		return err
	}

	return json.Unmarshal(inner, v)
}
