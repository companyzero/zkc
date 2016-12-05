// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// zkidentity package manages public and private identities.
package zkidentity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/curve25519"
)

var (
	prng = rand.Reader

	ErrNotEqual = errors.New("not equal")
	ErrVerify   = errors.New("verify error")
)

const (
	privKeySize   = ed25519.PrivateKeySize
	SignatureSize = ed25519.SignatureSize
	pubKeySize    = ed25519.PublicKeySize
	IdentitySize  = 32
)

type FullIdentity struct {
	Public          PublicIdentity     // public key and identity
	PrivateKey      [privKeySize]byte  // private key, exported for marshaling
	PrivateIdentity [IdentitySize]byte // private key, exported for marshaling
}

func (fi *FullIdentity) Marshal() ([]byte, error) {
	b := &bytes.Buffer{}
	_, err := xdr.Marshal(b, fi)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func UnmarshalFullIdentity(data []byte) (*FullIdentity, error) {
	br := bytes.NewReader(data)
	fi := FullIdentity{}
	_, err := xdr.Unmarshal(br, &fi)
	if err != nil {
		return nil, err
	}

	return &fi, nil
}

type PublicIdentity struct {
	Name     string             // long name, e.g. John Doe
	Nick     string             // short name, e.g. jd
	Key      [pubKeySize]byte   // public key
	Identity [IdentitySize]byte // public identity

	Digest    [sha256.Size]byte   // digest of Name, Key and Identity
	Signature [SignatureSize]byte // signature of Digest
}

func New(name, nick string) (*FullIdentity, error) {
	fi := FullIdentity{}
	pub, priv, err := ed25519.GenerateKey(prng)
	if err != nil {
		return nil, err
	}

	// move keys in place
	copy(fi.Public.Key[:], pub[:])
	copy(fi.PrivateKey[:], priv[:])
	zero(pub[:])
	zero(priv[:])

	// obtain identities
	extra25519.PrivateKeyToCurve25519(&fi.PrivateIdentity, &fi.PrivateKey)
	curve25519.ScalarBaseMult(&fi.Public.Identity, &fi.PrivateIdentity)

	fi.Public.Name = name
	fi.Public.Nick = nick

	err = fi.RecalculateDigest()
	if err != nil {
		return nil, err
	}

	return &fi, nil
}

func Fingerprint(id [IdentitySize]byte) string {
	digest := sha256.Sum256(id[:])
	f := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		digest[0],
		digest[1],
		digest[2],
		digest[3],
		digest[4],
		digest[5],
		digest[6],
		digest[7],
		digest[8],
		digest[9],
	)
	return f
}

func (fi *FullIdentity) RecalculateDigest() error {
	// calculate digest
	d := sha256.New()
	d.Write([]byte(fi.Public.Name))
	d.Write([]byte(fi.Public.Nick))
	d.Write(fi.Public.Key[:])
	d.Write(fi.Public.Identity[:])
	copy(fi.Public.Digest[:], d.Sum(nil))

	// sign and verify
	signature := ed25519.Sign(&fi.PrivateKey, fi.Public.Digest[:])
	copy(fi.Public.Signature[:], signature[:])
	if !fi.Public.Verify() {
		return fmt.Errorf("could not verify public signature")
	}

	return nil
}

func (fi *FullIdentity) SignMessage(message []byte) [SignatureSize]byte {
	signature := ed25519.Sign(&fi.PrivateKey, message)
	return *signature
}

func (p PublicIdentity) VerifyMessage(msg []byte, sig [SignatureSize]byte) bool {
	return ed25519.Verify(&p.Key, msg, &sig)
}

func (p PublicIdentity) String() string {
	return hex.EncodeToString(p.Identity[:])
}

func (p PublicIdentity) Fingerprint() string {
	return Fingerprint(p.Identity)
}

func (p *PublicIdentity) Verify() bool {
	d := sha256.New()
	d.Write([]byte(p.Name))
	d.Write([]byte(p.Nick))
	d.Write(p.Key[:])
	d.Write(p.Identity[:])
	if !bytes.Equal(p.Digest[:], d.Sum(nil)) {
		return false
	}
	return ed25519.Verify(&p.Key, p.Digest[:], &p.Signature)
}

func (p *PublicIdentity) Marshal() ([]byte, error) {
	b := &bytes.Buffer{}
	_, err := xdr.Marshal(b, p)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func UnmarshalPublicIdentity(data []byte) (*PublicIdentity, error) {
	br := bytes.NewReader(data)
	pi := PublicIdentity{}
	_, err := xdr.Unmarshal(br, &pi)
	if err != nil {
		return nil, err
	}

	if !pi.Verify() {
		return nil, ErrVerify
	}

	return &pi, nil
}

// Zero out a byte slice.
func zero(in []byte) {
	if in == nil {
		return
	}
	for i := 0; i < len(in); i++ {
		in[i] ^= in[i]
	}
}

func String2ID(to string) (*[32]byte, error) {
	id, err := hex.DecodeString(to)
	if err != nil {
		return nil, err
	}
	if len(id) != 32 {
		return nil, fmt.Errorf("invalid length")
	}

	var id32 [32]byte
	copy(id32[:], id)

	return &id32, nil
}
