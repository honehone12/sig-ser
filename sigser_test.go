package sigser_test

import (
	"crypto/ed25519"
	"sigser"
	"sigser/json"

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

func TestStart(t *testing.T) {
	err := godotenv.Load()
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewFail(t *testing.T) {
	_, err := sigser.NewSigSerFromString("badprivatekey")
	if err == nil {
		t.Fail()
	}

	_, err = sigser.NewSigSer([]byte{0})
	if err == nil {
		t.Fail()
	}

	_, err = sigser.NewSigDeFromString("badpublickey")
	if err == nil {
		t.Fail()
	}

	_, err = sigser.NewSigDe([]byte{0})
	if err == nil {
		t.Fail()
	}
}

func TestCheckTimestamp(t *testing.T) {
	now := uint64(time.Now().Unix())
	if err := sigser.CheckTimestamp(now); err != nil {
		t.Fatal(err)
	}
}

func TestCheckTimestampFail(t *testing.T) {
	now := uint64(time.Now().Unix())
	now -= 100
	if err := sigser.CheckTimestamp(now); err == nil {
		t.Fail()
	}
}

func TestGoodPath(t *testing.T) {
	encD := testData{
		Str: "hogehoge",
		Num: 99,
	}

	ser, err := sigser.NewSigSerFromEnv(_PRIVATE_KEY_ENV)
	if err != nil {
		t.Fatal(err)
	}

	b, err := json.Marshal(encD, ser)
	if err != nil {
		t.Fatal(err)
	}

	de, err := sigser.NewSigDeFromEnv(_PUBLIC_KEY_ENV)
	if err != nil {
		t.Fatal(err)
	}

	var decD *testData
	if err = json.Unmarshal(b, &decD, de); err != nil {
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

	badSer, err := sigser.NewSigSer(badPriv)
	if err != nil {
		t.Fatal(err)
	}

	encD := testData{
		Str: "piyopiyo",
		Num: -99,
	}

	b, err := json.Marshal(encD, badSer)
	if err != nil {
		t.Fatal(err)
	}

	de, err := sigser.NewSigDeFromEnv(_PUBLIC_KEY_ENV)
	if err != nil {
		t.Fatal(err)
	}

	var decD *testData
	if err = json.Unmarshal(b, &decD, de); err == nil {
		t.Fail()
	}
}
