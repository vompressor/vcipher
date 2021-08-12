package vDES

import (
	"crypto/des"

	"github.com/vompressor/vcipher"
)

func DES(key []byte) (*vcipher.VBlock, error) {
	b, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return vcipher.Upgrade(b), nil
}
func TDES(key []byte) (*vcipher.VBlock, error) {
	b, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return vcipher.Upgrade(b), nil
}
