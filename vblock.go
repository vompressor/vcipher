package vcipher

import (
	"crypto/cipher"
	"errors"
)

type VBlock struct {
	cipher.Block
}

func Upgrade(b cipher.Block) *VBlock {
	return &VBlock{Block: b}
}

func (v *VBlock) EncryptData(plaintext []byte) ([]byte, error) {
	if len(plaintext) != v.BlockSize() {
		return nil, errors.New("plaintext size must same block length")
	}

	ret := make([]byte, len(plaintext))

	v.Encrypt(ret, plaintext)

	return ret, nil
}

func (v *VBlock) DecryptData(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != v.BlockSize() {
		return nil, errors.New("plaintext size must same block length")
	}

	ret := make([]byte, len(ciphertext))

	v.Decrypt(ret, ciphertext)

	return ret, nil
}

func (v *VBlock) CBC(iv []byte, pair PadderPair) *VBlockModePair {
	return NewVBlockMode(cipher.NewCBCEncrypter(v, iv), cipher.NewCBCDecrypter(v, iv), pair.P, pair.Un)
}

func (v *VBlock) GCM() (cipher.AEAD, error) {
	return cipher.NewGCM(v)
}

func (v *VBlock) CTR(iv []byte) cipher.Stream {
	return cipher.NewCTR(v, iv)
}

func (v *VBlock) OFB(iv []byte) cipher.Stream {
	return cipher.NewOFB(v, iv)
}

func (v *VBlock) CFB(iv []byte) *VStream {
	return &VStream{E: cipher.NewCFBEncrypter(v, iv), D: cipher.NewCFBDecrypter(v, iv)}
}
