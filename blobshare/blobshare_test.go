// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blobshare

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

var (
	password = []byte("mysekritpassword")
)

func TestPackSaltNonce(t *testing.T) {
	var (
		salt  [32]byte
		nonce [24]byte
		data  [1024]byte
	)

	_, err := io.ReadFull(rand.Reader, data[:])
	if err != nil {
		t.Fatal(err)
	}

	packed := PackSaltNonce(&salt, &nonce, data[:])

	saltR, nonceR, dataR, err := UnpackSaltNonce(packed)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(salt[:], saltR[:]) {
		t.Fatalf("corrupted salt")
	}
	if !bytes.Equal(nonce[:], nonceR[:]) {
		t.Fatalf("corrupted nonce")
	}
	if !bytes.Equal(data[:], dataR) {
		t.Fatalf("corrupted data")
	}
}

func TestPackNonce(t *testing.T) {
	var (
		nonce [24]byte
		data  [1024]byte
	)

	_, err := io.ReadFull(rand.Reader, data[:])
	if err != nil {
		t.Fatal(err)
	}

	packed := PackNonce(&nonce, data[:])

	nonceR, dataR, err := UnpackNonce(packed)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(nonce[:], nonceR[:]) {
		t.Fatalf("corrupted nonce")
	}
	if !bytes.Equal(data[:], dataR) {
		t.Fatalf("corrupted data")
	}
}

func TestNewAndDerive(t *testing.T) {
	key, salt, err := NewKey(password)
	if err != nil {
		t.Fatal(err)
	}

	dk, err := DeriveKey(password, salt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key[:], dk[:]) {
		t.Fatalf("corrupted data")
	}
	t.Logf("key: %x", *key)
}

func TestEncryptDecrypt(t *testing.T) {
	var payload [1024]byte
	_, err := io.ReadFull(rand.Reader, payload[:])
	if err != nil {
		t.Fatal(err)
	}

	key, salt, err := NewKey(password)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, nonce, err := Encrypt(payload[:], key)
	if err != nil {
		t.Fatal(err)
	}

	packed := PackSaltNonce(salt, nonce, encrypted)

	// reverse process
	saltR, nonceR, dataR, err := UnpackSaltNonce(packed)
	if err != nil {
		t.Fatal(err)
	}

	dk, err := DeriveKey(password, saltR)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Decrypt(dk, nonceR, dataR)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, payload[:]) {
		t.Fatalf("corrupted data")
	}
}

func TestThreeWayHandshake(t *testing.T) {
	var payload [1024]byte
	_, err := io.ReadFull(rand.Reader, payload[:])
	if err != nil {
		t.Fatal(err)
	}

	key, salt, err := NewKey(password)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, nonce, err := Encrypt(payload[:], key)
	if err != nil {
		t.Fatal(err)
	}

	packed := PackSaltNonce(salt, nonce, encrypted)

	// reverse process
	saltR, nonceR, dataR, err := UnpackSaltNonce(packed)
	if err != nil {
		t.Fatal(err)
	}

	dk, err := DeriveKey(password, saltR)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Decrypt(dk, nonceR, dataR)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, payload[:]) {
		t.Fatalf("corrupted data")
	}

	// return something to sender with same key, different nonce
	var payloadX [1024]byte
	_, err = io.ReadFull(rand.Reader, payloadX[:])
	if err != nil {
		t.Fatal(err)
	}
	encryptedX, nonceX, err := Encrypt(payloadX[:], dk)
	if err != nil {
		t.Fatal(err)
	}

	packedX := PackNonce(nonceX, encryptedX)

	// reverse again
	nonceY, dataY, err := UnpackNonce(packedX)
	if err != nil {
		t.Fatal(err)
	}

	decryptedY, err := Decrypt(key, nonceY, dataY)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(payloadX[:], decryptedY) {
		t.Fatalf("corrupted data")
	}
}

func TestEncryptDecryptLargeNrp(t *testing.T) {
	SetNrp(65536, 32, 4)
	var payload [1024]byte
	_, err := io.ReadFull(rand.Reader, payload[:])
	if err != nil {
		t.Fatal(err)
	}

	key, salt, err := NewKey(password)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, nonce, err := Encrypt(payload[:], key)
	if err != nil {
		t.Fatal(err)
	}

	packed := PackSaltNonce(salt, nonce, encrypted)

	// reverse process
	saltR, nonceR, dataR, err := UnpackSaltNonce(packed)
	if err != nil {
		t.Fatal(err)
	}

	dk, err := DeriveKey(password, saltR)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Decrypt(dk, nonceR, dataR)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, payload[:]) {
		t.Fatalf("corrupted data")
	}
	SetNrp(16384, 8, 1)
}
