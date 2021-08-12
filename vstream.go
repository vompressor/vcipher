package vcipher

import "crypto/cipher"

type VStream struct {
	E cipher.Stream
	D cipher.Stream
}

func NewVStream(e, d cipher.Stream) *VStream {
	return &VStream{E: e, D: d}
}

func (v *VStream) EncryptData(plaintext []byte) ([]byte, error) {
	ret := make([]byte, len(plaintext))
	v.E.XORKeyStream(ret, plaintext)
	return ret, nil
}

func (v *VStream) DecryptData(ciphertext []byte) ([]byte, error) {
	ret := make([]byte, len(ciphertext))
	v.D.XORKeyStream(ret, ciphertext)
	return ret, nil
}
