package sigser

import (
	"testing"

	"github.com/joho/godotenv"
)

const (
	PRIVATE_KEY_ENV = "SIGSER_PRIVATE_KEY"
	PUBLIC_KEY_ENV  = "SIGSER_PUBLIC_KEY"
)

var (
	ser *SigSer
	de  *SigDe
)

func TestNew(t *testing.T) {
	err := godotenv.Load()
	if err != nil {
		t.Fatal(err)
	}

	ser, err = NewSigSerFromEnv(PRIVATE_KEY_ENV)
	if err != nil {
		t.Fatal(err)
	}

	de, err = NewSigDeFromEnv(PUBLIC_KEY_ENV)
	if err != nil {
		t.Fatal(err)
	}
}
