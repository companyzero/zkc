// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blobshare

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

var (
	n = 16384
	r = 8
	p = 1
)

func SetNrp(nn, rr, pp int) {
	n = nn
	r = rr
	p = pp
}

func zero(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0
	}
}

func NewKey(password string) (*[32]byte, *[32]byte, error) {
	var (
		salt [32]byte
	)

	// random salt
	_, err := io.ReadFull(rand.Reader, salt[:])
	if err != nil {
		return nil, nil, err
	}

	key, err := DeriveKey(password, &salt)
	if err != nil {
		return nil, nil, err
	}

	return key, &salt, nil
}

func DeriveKey(password string, salt *[32]byte) (*[32]byte, error) {
	var key [32]byte
	dk, err := scrypt.Key([]byte(password), salt[:], n, r, p, len(key))
	if err != nil {
		return nil, err
	}
	copy(key[:], dk[:])
	zero(dk[:])

	return &key, nil
}

func PackSaltNonce(salt *[32]byte, nonce *[24]byte, data []byte) []byte {
	// pack all the things
	packed := make([]byte, len(salt)+len(nonce)+len(data))
	copy(packed[0:], salt[:])
	copy(packed[32:], nonce[:])
	copy(packed[32+24:], data)

	return packed
}

func UnpackSaltNonce(packed []byte) (salt *[32]byte, nonce *[24]byte,
	data []byte, err error) {
	var (
		saltR  [32]byte
		nonceR [24]byte
	)
	copy(saltR[:], packed[0:32])
	copy(nonceR[:], packed[32:32+24])
	salt = &saltR
	nonce = &nonceR

	data = packed[32+24:]

	return
}

func PackNonce(nonce *[24]byte, data []byte) []byte {
	// pack all the things
	packed := make([]byte, len(nonce)+len(data))
	copy(packed[0:], nonce[:])
	copy(packed[24:], data)

	return packed
}

func UnpackNonce(packed []byte) (nonce *[24]byte, data []byte, err error) {
	var nonceR [24]byte
	copy(nonceR[:], packed[0:24])
	nonce = &nonceR

	data = packed[24:]

	return
}

func Encrypt(data []byte, key *[32]byte) ([]byte, *[24]byte, error) {
	var (
		nonce [24]byte
	)

	// random nonce
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, nil, err
	}

	// encrypt data
	return secretbox.Seal(nil, data, &nonce, key), &nonce, nil
}

func Decrypt(key *[32]byte, nonce *[24]byte, data []byte) ([]byte, error) {
	decrypted, ok := secretbox.Open(nil, data, nonce, key)
	if !ok {
		return nil, fmt.Errorf("could not decrypt")
	}
	return decrypted, nil
}
