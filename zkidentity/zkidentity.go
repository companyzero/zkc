// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// zkidentity package manages public and private identities.
package zkidentity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/agl/ed25519"
	"github.com/companyzero/ntruprime"
	"github.com/davecgh/go-xdr/xdr2"
)

var (
	prng = rand.Reader

	ErrNotEqual = errors.New("not equal")
	ErrVerify   = errors.New("verify error")
)

const (
	IdentitySize  = sha256.Size
)

// A zkc public identity consists of a name and nick (e.g "John Doe" and "jd"
// respectively), a ed25519 public signature key, and a NTRU Prime public key
// (used to derive symmetric encryption keys). An extra Identity field, taken
// as the SHA256 of the NTRU public key, is used as a short handle to uniquely
// identify a user in various zkc structures.
type PublicIdentity struct {
	Name		string
	Nick		string
	SigKey		[ed25519.PublicKeySize]byte
	Key		[ntruprime.PublicKeySize]byte
	Identity	[sha256.Size]byte
	Digest		[sha256.Size]byte // digest of name, keys and identity
	Signature	[ed25519.SignatureSize]byte // signature of Digest
}

type FullIdentity struct {
	Public		PublicIdentity
	PrivateSigKey	[ed25519.PrivateKeySize]byte
	PrivateKey	[ntruprime.PrivateKeySize]byte
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

func New(name, nick string) (*FullIdentity, error) {
	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(prng)
	if err != nil {
		return nil, err
	}
	ntruprimePub, ntruprimePriv, err := ntruprime.GenerateKey(prng)
	if err != nil {
		return nil, err
	}
	identity := sha256.Sum256(ntruprimePub[:])

	fi := new(FullIdentity)
	fi.Public.Name = name
	fi.Public.Nick = nick
	copy(fi.Public.SigKey[:], ed25519Pub[:])
	copy(fi.Public.Key[:], ntruprimePub[:])
	copy(fi.Public.Identity[:], identity[:])
	copy(fi.PrivateSigKey[:], ed25519Priv[:])
	copy(fi.PrivateKey[:], ntruprimePriv[:])
	err = fi.RecalculateDigest()
	if err != nil {
		return nil, err
	}

	zero(ed25519Pub[:])
	zero(ed25519Priv[:])
	zero(ntruprimePub[:])
	zero(ntruprimePriv[:])

	return fi, nil
}

func Fingerprint(id [IdentitySize]byte) string {
	return base64.StdEncoding.EncodeToString(id[:])
}

func (fi *FullIdentity) RecalculateDigest() error {
	// calculate digest
	d := sha256.New()
	d.Write([]byte(fi.Public.Name))
	d.Write([]byte(fi.Public.Nick))
	d.Write(fi.Public.SigKey[:])
	d.Write(fi.Public.Key[:])
	d.Write(fi.Public.Identity[:])
	copy(fi.Public.Digest[:], d.Sum(nil))

	// sign and verify
	signature := ed25519.Sign(&fi.PrivateSigKey, fi.Public.Digest[:])
	copy(fi.Public.Signature[:], signature[:])
	if !fi.Public.Verify() {
		return fmt.Errorf("could not verify public signature")
	}

	return nil
}

func (fi *FullIdentity) SignMessage(message []byte) [ed25519.SignatureSize]byte {
	signature := ed25519.Sign(&fi.PrivateSigKey, message)
	return *signature
}

func (p PublicIdentity) VerifyMessage(msg []byte, sig [ed25519.SignatureSize]byte) bool {
	return ed25519.Verify(&p.SigKey, msg, &sig)
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
	d.Write(p.SigKey[:])
	d.Write(p.Key[:])
	d.Write(p.Identity[:])
	if !bytes.Equal(p.Digest[:], d.Sum(nil)) {
		return false
	}
	return ed25519.Verify(&p.SigKey, p.Digest[:], &p.Signature)
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
