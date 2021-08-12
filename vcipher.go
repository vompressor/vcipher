package vcipher

import (
	"crypto/cipher"
	"fmt"
)

const (
	// block
	AES_128 = "AES-128"
	AES_192 = "AES-192"
	AES_256 = "AES-256"
	DES     = "DES"
	TDES    = "3DES"

	// stream
	CHACHA20  = "CHACHA20"
	XCHACHA20 = "XCHACHA20"

	// aead
	CHACHA20_POLY1305  = "CHACHA20-POLY1305"
	XCHACHA20_POLY1305 = "CHACHA20-POLY1305"

	// mode
	CTR = "CTR"
)

type VCipher interface {
	EncryptData([]byte) ([]byte, error)
	DecryptData([]byte) ([]byte, error)
}

type BlockCipherGetter func(key []byte) (cip cipher.Block, err error)
type StreamCipherGetter func(key, nonce []byte) (cip cipher.Stream, err error)
type AEADCipherGetter func(key []byte) (cip cipher.AEAD, err error)
type ModeGetter func(cip cipher.Block, iv []byte) (interface{}, error)

var mapBlock map[string]BlockCipherGetter
var mapStream map[string]StreamCipherGetter
var mapAEAD map[string]AEADCipherGetter

func RegistBlock(cip string, getter BlockCipherGetter) {
	mapBlock[cip] = getter
}

func RegistStream(cip string, getter StreamCipherGetter) {
	mapStream[cip] = getter
}

func RegistAEAD(cip string, getter AEADCipherGetter) {
	mapAEAD[cip] = getter
}

// func GetModeFromCipherString(cip string, x interface{}) {

// }

// func GetCipherFromCipherString(cip string) (interface{}, error) {

// }

func GetBlockCipherFromCipherString(cip string, key []byte) (cipher.Block, error) {
	ret, ok := mapBlock[cip]

	if !ok {
		return nil, fmt.Errorf("%s not found", cip)
	}

	return ret(key)
}

func GetStreamCipherFromCipherString(cip string, key, nonce []byte) (cipher.Stream, error) {
	ret, ok := mapStream[cip]

	if !ok {
		return nil, fmt.Errorf("%s not found", cip)
	}

	return ret(key, nonce)
}

func GetAEADCipherFromString(cip string, key []byte) (cipher.AEAD, error) {
	ret, ok := mapAEAD[cip]

	if !ok {
		return nil, fmt.Errorf("%s not found", cip)
	}

	return ret(key)
}
