package vAES

import (
	"crypto/aes"

	"github.com/vompressor/vcipher"
)

func AES_128(key []byte) (*vcipher.VBlock, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return vcipher.Upgrade(b), nil
}

func AES_192(key []byte) (*vcipher.VBlock, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return vcipher.Upgrade(b), nil
}

func AES_256(key []byte) (*vcipher.VBlock, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return vcipher.Upgrade(b), nil
}
