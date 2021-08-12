package key

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

func NewRandKey(len int) ([]byte, error) {
	ret := make([]byte, len)

	n, err := rand.Read(ret)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, errors.New("rand read err")
	}

	return ret, nil
}

func NewKeyFromString(str string, len int) []byte {
	var hasher hash.Hash
	if len <= sha256.Size {
		hasher = sha256.New()
	} else {
		hasher = sha512.New()
	}

	return hasher.Sum([]byte(str))[:len]
}
