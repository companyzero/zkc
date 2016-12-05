// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sigma

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"time"

	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	ErrDecrypt  = errors.New("decrypt failure")
	ErrOverflow = errors.New("message too large")
)

// SigmaKX implements the KeyExchanger interface.  SigmaKX process is as
// follows:
//	1. Initiator sends ephemeral identity
//	2. Target replies ephemeral identity
//	3. Target calculates shared ephemeral key and sends HMAC server proof
//	4. Initiator calculates shared ephemeral key and verifies HMAC server proof
//	5. Initiator sends HMAC client proof
//	6. Target verifies client proof
//
// Note that this glosses over a lot of detail.
type SigmaKX struct {
	isServer                    bool     // true is target
	ourPrivateIdentity          [32]byte // local long lived private identity
	ourPublicIdentity           [32]byte // local long lived public identity
	theirIdentity               [32]byte // remote long lived identity
	writeKey, readKey           [32]byte // keys used during kx
	writeSequence, readSequence [24]byte // NaCl nonce during kx
	maxMessageSize              uint     // largest message size allow

	conn net.Conn // underlying reader/writer
}

var (
	serverKeysMagic  = []byte("server keys\x00")
	clientKeysMagic  = []byte("client keys\x00")
	serverProofMagic = []byte("server proof\x00")
	clientProofMagic = []byte("client proof\x00")
)

// NewClient returns a SigmaKX context for an initiator.
func NewClient(ourPublicIdentity, ourPrivateIdentity, theirIdentity *[32]byte, maxMessageSize uint) *SigmaKX {

	skx := &SigmaKX{
		maxMessageSize: maxMessageSize,
	}
	copy(skx.ourPublicIdentity[:], ourPublicIdentity[:])
	copy(skx.ourPrivateIdentity[:], ourPrivateIdentity[:])
	copy(skx.theirIdentity[:], theirIdentity[:])

	return skx
}

// NewClient returns a SigmaKX context for a target.
func NewServer(ourPublicIdentity, ourPrivateIdentity *[32]byte, maxMessageSize uint) *SigmaKX {

	skx := &SigmaKX{
		isServer:       true,
		maxMessageSize: maxMessageSize,
	}
	copy(skx.ourPublicIdentity[:], ourPublicIdentity[:])
	copy(skx.ourPrivateIdentity[:], ourPrivateIdentity[:])

	return skx
}

// Initiator initiates the key exchange and progresses through all steps.  Note
// that Initiator shall close conn if it encounters an error.  Calling
// applications must therefore ensure that error is consulted before using conn
// again.
func (k *SigmaKX) Initiator(conn net.Conn) error {
	k.conn = conn

	// obtain ephemeral keys
	var ephemeralPrivate, ephemeralPublic, ephemeralShared [32]byte
	if _, err := io.ReadFull(rand.Reader, ephemeralPrivate[:]); err != nil {
		return err
	}
	curve25519.ScalarBaseMult(&ephemeralPublic, &ephemeralPrivate)

	// step 1
	// write XDR encoded ephemeral public key
	_, err := xdr.Marshal(k.conn, ephemeralPublic)
	if err != nil {
		k.conn.Close()
		return fmt.Errorf("Initiator: could not Marshal")
	}

	// step 2
	// read XDR encoded ephemeral public key
	var theirEphemeralPublic [32]byte
	_, err = xdr.Unmarshal(k.conn, &theirEphemeralPublic)
	if err != nil {
		k.conn.Close()
		return fmt.Errorf("Initiator: could not Unmarshal")
	}

	handshakeHash := sha256.New()
	handshakeHash.Write(ephemeralPublic[:])
	handshakeHash.Write(theirEphemeralPublic[:])

	curve25519.ScalarMult(&ephemeralShared, &ephemeralPrivate,
		&theirEphemeralPublic)

	k.setupKeys(&ephemeralShared)

	err = k.handshakeClient(handshakeHash, &ephemeralPrivate)
	if err != nil {
		k.conn.Close()
		return err
	}

	return nil
}

// Target waits for the key exchange process to commence and progresses through
// all steps.  Note that Target shall close conn if it encounters an error.
// Calling applications must therefore ensure that error is consulted before
// using conn again.
func (k *SigmaKX) Target(conn net.Conn) error {
	k.conn = conn

	// obtain ephemeral keys
	var ephemeralPrivate, ephemeralPublic, ephemeralShared [32]byte
	if _, err := io.ReadFull(rand.Reader, ephemeralPrivate[:]); err != nil {
		k.conn.Close()
		return err
	}
	curve25519.ScalarBaseMult(&ephemeralPublic, &ephemeralPrivate)

	// step 1
	// read XDR encoded ephemeral public key
	var theirEphemeralPublic [32]byte
	_, err := xdr.Unmarshal(k.conn, &theirEphemeralPublic)
	if err != nil {
		k.conn.Close()
		return fmt.Errorf("Target: could not Unmarshal")
	}

	// step 2
	// write XDR encoded ephemeral public key
	_, err = xdr.Marshal(k.conn, ephemeralPublic)
	if err != nil {
		k.conn.Close()
		return fmt.Errorf("Target: could not Marshal")
	}

	handshakeHash := sha256.New()
	handshakeHash.Write(theirEphemeralPublic[:])
	handshakeHash.Write(ephemeralPublic[:])

	curve25519.ScalarMult(&ephemeralShared, &ephemeralPrivate,
		&theirEphemeralPublic)

	k.setupKeys(&ephemeralShared)

	err = k.handshakeServer(handshakeHash, &theirEphemeralPublic)
	if err != nil {
		k.conn.Close()
		return err
	}

	return nil
}

// TheirIdentity returns remote public identity.
func (k *SigmaKX) TheirIdentity() interface{} {
	return k.theirIdentity
}

// setupKeys sets up the read and write keys that are used during key
// exchnagge.
func (k *SigmaKX) setupKeys(ephemeralShared *[32]byte) {
	var writeMagic, readMagic []byte
	if k.isServer {
		writeMagic, readMagic = serverKeysMagic, clientKeysMagic
	} else {
		writeMagic, readMagic = clientKeysMagic, serverKeysMagic
	}

	h := sha256.New()
	h.Write(writeMagic)
	h.Write(ephemeralShared[:])
	h.Sum(k.writeKey[:0])

	h.Reset()
	h.Write(readMagic)
	h.Write(ephemeralShared[:])
	h.Sum(k.readKey[:0])
}

// handshakeClient completes the client to server key exchange.
func (k *SigmaKX) handshakeClient(handshakeHash hash.Hash,
	ephemeralPrivate *[32]byte) error {

	var ephemeralIdentityShared [32]byte
	curve25519.ScalarMult(&ephemeralIdentityShared, ephemeralPrivate,
		&k.theirIdentity)

	digest := handshakeHash.Sum(nil)
	h := hmac.New(sha256.New, ephemeralIdentityShared[:])
	h.Write(serverProofMagic)
	h.Write(digest)
	digest = h.Sum(digest[:0])

	// step 3 read encrypted digest
	digestReceived, err := k.Read()
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(digest, digestReceived) != 1 {
		return errors.New("server identity incorrect")
	}

	var identityShared [32]byte
	curve25519.ScalarMult(&identityShared, &k.ourPrivateIdentity,
		&k.theirIdentity)

	handshakeHash.Write(digest)
	digest = handshakeHash.Sum(digest[:0])

	h = hmac.New(sha256.New, identityShared[:])
	h.Write(clientProofMagic)
	h.Write(digest)

	finalMessage := make([]byte, 32+sha256.Size)
	copy(finalMessage, k.ourPublicIdentity[:])
	h.Sum(finalMessage[32:32])

	// step 4 write encrypted digest
	if err := k.Write(finalMessage); err != nil {
		return err
	}

	return nil
}

// handshakeServer completes the server to client key exchange.
func (k *SigmaKX) handshakeServer(handshakeHash hash.Hash,
	theirEphemeralPublic *[32]byte) error {

	var ephemeralIdentityShared [32]byte
	curve25519.ScalarMult(&ephemeralIdentityShared, &k.ourPrivateIdentity,
		theirEphemeralPublic)

	digest := handshakeHash.Sum(nil)
	h := hmac.New(sha256.New, ephemeralIdentityShared[:])
	h.Write(serverProofMagic)
	h.Write(digest)
	digest = h.Sum(digest[:0])

	// step 3 write encrypted digest
	if err := k.Write(digest); err != nil {
		return err
	}

	handshakeHash.Write(digest)
	digest = handshakeHash.Sum(digest[:0])

	// step 4 read encrypted remote identity
	finalMessage, err := k.Read()
	if err != nil {
		return err
	}

	copy(k.theirIdentity[:], finalMessage[:32])
	var identityShared [32]byte
	curve25519.ScalarMult(&identityShared, &k.ourPrivateIdentity,
		&k.theirIdentity)

	h = hmac.New(sha256.New, identityShared[:])
	h.Write(clientProofMagic)
	h.Write(digest)
	digest = h.Sum(digest[:0])

	if subtle.ConstantTimeCompare(digest, finalMessage[32:]) != 1 {
		return errors.New("bad proof from client")
	}

	return nil
}

func (k *SigmaKX) SetWriteDeadline(t time.Time) {
	k.conn.SetWriteDeadline(t)
}

func (k *SigmaKX) SetReadDeadline(t time.Time) {
	k.conn.SetReadDeadline(t)
}

func (k *SigmaKX) SetMaxMessageSize(size uint) {
	k.maxMessageSize = size
}

// Write encrypts and marshals data to the underlying writer.
func (k *SigmaKX) Write(data []byte) error {
	encrypted := secretbox.Seal(nil, data, &k.writeSequence, &k.writeKey)
	incSequence(&k.writeSequence)

	if uint(len(encrypted)) > k.maxMessageSize {
		return ErrOverflow
	}

	_, err := xdr.Marshal(k.conn, encrypted)
	if err != nil {
		// do't return error because xdr adds payload
		return fmt.Errorf("Write: could not marshal")
	}

	return nil
}

// Read unmarshals and decrypts data from underlying reader.
func (k *SigmaKX) Read() ([]byte, error) {
	var encrypted []byte
	_, err := xdr.UnmarshalLimited(k.conn, &encrypted, k.maxMessageSize)
	if err != nil {
		return nil, err
	}

	decrypted, ok := secretbox.Open(nil, encrypted, &k.readSequence,
		&k.readKey)
	incSequence(&k.readSequence)
	if !ok {
		return nil, ErrDecrypt
	}
	return decrypted, nil
}

// Close closes the underlying connection.
func (k *SigmaKX) Close() {
	k.conn.Close()
}

// incSequence increments the provided nonce.
func incSequence(seq *[24]byte) {
	n := uint32(1)

	for i := 0; i < 8; i++ {
		n += uint32(seq[i])
		seq[i] = byte(n)
		n >>= 8
	}
}
