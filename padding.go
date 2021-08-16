package vcipher

import (
	"bytes"
	"errors"
)

type PadderPair struct {
	P  Padder
	Un UnPadder
}

func PKCS7Padding() PadderPair {
	return PadderPair{
		P:  PaddingPKCS7,
		Un: UnPaddingPKCS7,
	}
}

func PKCS5Padding() PadderPair {
	return PadderPair{
		P:  PaddingPKCS5,
		Un: UnPaddingPKCS5,
	}
}

type Padder func(src []byte, size int) []byte
type UnPadder func(src []byte, size int) ([]byte, error)

func PaddingPKCS5(src []byte, size int) []byte {
	padding := size - len(src)%size
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func UnPaddingPKCS5(src []byte, size int) ([]byte, error) {
	len := len(src)
	unp := int(src[len-1])
	return src[:len-unp], nil
}

func PaddingPKCS7(src []byte, size int) []byte {
	if src == nil {
		return bytes.Repeat([]byte{byte(size)}, size)
	}

	padlen := 1
	for ((len(src) + padlen) % size) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(src, pad...)
}

func UnPaddingPKCS7(src []byte, size int) ([]byte, error) {
	if len(src) == 0 {
		return nil, errors.New("invalid padding")
	}

	padlen := int(src[len(src)-1])

	if padlen <= 0 || padlen > size {
		return nil, errors.New("invalid padding")
	}

	pad := src[len(src)-padlen:]

	for _, n := range pad {
		if int(n) != padlen {
			return nil, errors.New("invalid padding")
		}
	}

	return src[:len(src)-padlen], nil
}
