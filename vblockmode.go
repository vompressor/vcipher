package vcipher

import (
	"crypto/cipher"
	"errors"
)

type VBlockModePair struct {
	E cipher.BlockMode
	D cipher.BlockMode

	p  Padder
	un UnPadder
}

func NewVBlockMode(e, d cipher.BlockMode, p Padder, un UnPadder) *VBlockModePair {
	return &VBlockModePair{E: e, D: d, un: un, p: p}
}

func (v *VBlockModePair) EncryptData(plaintext []byte) ([]byte, error) {
	data := v.p(plaintext, v.E.BlockSize())
	v.E.CryptBlocks(data, data)
	return data, nil
}

func (v *VBlockModePair) DecryptData(ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%v.D.BlockSize() != 0 {
		return nil, errors.New("")
	}
	data := make([]byte, len(ciphertext))
	v.D.CryptBlocks(data, ciphertext)
	return v.un(data, v.D.BlockSize())
}
