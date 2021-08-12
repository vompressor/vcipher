package vcipher_test

import (
	"testing"

	"github.com/vompressor/vcipher"
	"github.com/vompressor/vcipher/key"
	"github.com/vompressor/vcipher/vblock/vAES"
)

func TestNewAES_256_CBC(t *testing.T) {
	a, _ := vAES.AES_256(key.NewKeyFromString("hello", 32))
	iv, _ := key.NewRandKey(a.BlockSize())
	c := a.CBC(iv, vcipher.PKCS7Padding())

	r, _ := c.EncryptData([]byte("hello how are you"))
	r, _ = c.DecryptData(r)

	t.Logf("%s", r)
}

func TestNewAES_CFB(t *testing.T) {
	a, _ := vAES.AES_256(key.NewKeyFromString("hello", 32))
	iv, _ := key.NewRandKey(a.BlockSize())
	c := a.CFB(iv)

	r, _ := c.EncryptData([]byte("hello how are you"))
	q, _ := c.DecryptData(r)

	t.Logf("%s", q)
}
