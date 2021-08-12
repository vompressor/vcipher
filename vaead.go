package vcipher

import (
	"crypto/cipher"
	"errors"
)

type VAEAD struct {
	cipher.AEAD
}

func (v *VAEAD) EncryptData(plaintext, nonce, additional []byte) ([]byte, error) {
	if len(nonce) != v.NonceSize() {
		return nil, errors.New("nonce length error")
	}
	return v.Seal(nil, nonce, plaintext, additional), nil
}

func (v *VAEAD) DecryptData(ciphertext, nonce, additional []byte) ([]byte, error) {
	if len(nonce) != v.NonceSize() {
		return nil, errors.New("nonce length error")
	}
	return v.Open(nil, nonce, ciphertext, additional)
}
