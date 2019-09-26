// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tools

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/companyzero/zkc/zkidentity"
)

const (
	ZKSIdentityFilename = "zkserver.id"
	ZKSCertFilename     = "zkserver.crt"
	ZKSKeyFilename      = "zkserver.key"
	ZKSHome             = "home"
	ZKCServerFilename   = "myserver/myserver.ini"
)

type ServerRecord struct {
	PublicIdentity zkidentity.PublicIdentity
	Certificate    []byte
	IPandPort      []byte
	Directory      bool
}

type ClientRecord struct {
	PublicIdentity zkidentity.PublicIdentity
}

// randomUint64 returns a cryptographically random uint64 value.  This
// unexported version takes a reader primarily to ensure the error paths
// can be properly tested by passing a fake reader in the tests.
func randomUint64(r io.Reader) (uint64, error) {
	var b [8]byte
	_, err := io.ReadFull(r, b[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// RandomUint64 returns a cryptographically random uint64 value.
func RandomUint64() (uint64, error) {
	return randomUint64(rand.Reader)
}

// ValidateIdentity verfies that a string contains a valid identity and returns
// its []byte representation.
func ValidateIdentity(id string) ([]byte, error) {
	b, err := hex.DecodeString(id)
	if err != nil {
		return nil, err
	}

	if len(b) != zkidentity.IdentitySize {
		return nil, fmt.Errorf("invalid size")
	}

	return b, err
}

func Fingerprint(blob []byte) string {
	d := sha256.New()
	d.Write(blob)
	digest := d.Sum(nil)
	return hex.EncodeToString(digest[:])
}

func FingerprintDER(c tls.Certificate) string {
	if len(c.Certificate) != 1 {
		return "unexpected chained certificate"
	}

	return Fingerprint(c.Certificate[0])
}

func InFours(x string) (string, error) {
	if len(x) != 16 {
		return "", fmt.Errorf("too small")
	}

	return fmt.Sprintf("%4v %4v %4v %4v",
		x[0:4],
		x[4:8],
		x[8:12],
		x[12:16]), nil

}
