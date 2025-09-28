package sigser

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/joho/godotenv"
)

type testData struct {
	Str string
	Num int64
}

const (
	_PRIVATE_KEY_ENV = "SIGSER_PRIVATE_KEY"
	_PUBLIC_KEY_ENV  = "SIGSER_PUBLIC_KEY"
)

var (
	ser SigSer
	de  SigDe
)

func TestNew(t *testing.T) {
	err := godotenv.Load()
	if err != nil {
		t.Fatal(err)
	}

	ser, err = NewSigSerFromEnv(_PRIVATE_KEY_ENV)
	if err != nil {
		t.Fatal(err)
	}

	de, err = NewSigDeFromEnv(_PUBLIC_KEY_ENV)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewFail(t *testing.T) {
	_, err := NewSigSerFromString("badprivatekey")
	if err == nil {
		t.Fail()
	}

	_, err = NewSigSer([]byte{0})
	if err == nil {
		t.Fail()
	}

	_, err = NewSigDeFromString("badpublickey")
	if err == nil {
		t.Fail()
	}

	_, err = NewSigDe([]byte{0})
	if err == nil {
		t.Fail()
	}
}

func TestCheckTimestamp(t *testing.T) {
	now := time.Now().Unix()
	if err := checkTimestamp(now); err != nil {
		t.Fatal(err)
	}
}

func TestCheckTimestampFail(t *testing.T) {
	now := time.Now().Unix()
	now -= 100
	if err := checkTimestamp(now); err == nil {
		t.Fail()
	}
}

func TestGoodPath(t *testing.T) {
	encD := testData{
		Str: "hogehoge",
		Num: 99,
	}

	b, err := ser.Marshal(encD)
	if err != nil {
		t.Fatal(err)
	}

	var decD *testData
	if err = de.Unmarshal(b, &decD); err != nil {
		t.Fatal(err)
	}

	if decD.Str != encD.Str {
		t.Fail()
	}
	if decD.Num != encD.Num {
		t.Fail()
	}
}

func TestBadPath(t *testing.T) {
	_, badPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	badSer, err := NewSigSer(badPriv)
	if err != nil {
		t.Fatal(err)
	}

	encD := testData{
		Str: "piyopiyo",
		Num: -99,
	}

	b, err := badSer.Marshal(encD)
	if err != nil {
		t.Fatal(err)
	}

	var decD *testData
	if err = de.Unmarshal(b, &decD); err == nil {
		t.Fail()
	}
}
