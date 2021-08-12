package vchacha20

import (
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20"
)

func CHACHA20(key, nonce []byte) (cipher.Stream, error) {
	if len(nonce) != 12 {
		return nil, errors.New("nonce length error")
	}
	return chacha20.NewUnauthenticatedCipher(key, nonce)
}

func XCHACHA20(key, nonce []byte) (cipher.Stream, error) {
	if len(nonce) != 24 {
		return nil, errors.New("nonce length error")
	}
	return chacha20.NewUnauthenticatedCipher(key, nonce)
}
