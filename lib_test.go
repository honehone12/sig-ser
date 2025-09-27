package sigser

import (
	"testing"

	"github.com/joho/godotenv"
)

func TesNew(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		panic(err)
	}

}
