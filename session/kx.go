// Copyright (c) 2016,2017 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/companyzero/ntruprime"
	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	ErrDecrypt   = errors.New("decrypt failure")
	ErrOverflow  = errors.New("message too large")
	ErrInvalidKx = errors.New("invalid kx")
	ErrMarshal   = errors.New("could not marshal")
	ErrUnmarshal = errors.New("could not unmarshal")
)

// KX allows two peers to derive a pair of shared keys. One peer must trigger
// Initiate (the client) while the other (the server) should call Init once
// followed by Respond for each connection.
type KX struct {
	Conn           net.Conn
	MaxMessageSize uint
	OurPrivateKey  *[ntruprime.PrivateKeySize]byte
	OurPublicKey   *[ntruprime.PublicKeySize]byte
	TheirPublicKey *[ntruprime.PublicKeySize]byte
	writeKey       *[32]byte
	readKey        *[32]byte
	writeSeq       [24]byte
	readSeq        [24]byte
}

// The server keeps a pair of ephemeral keys to ensure key erasure (forward
// secrecy) should the server's long-term keys be compromised.
var (
	ephemeralPublic  [ntruprime.PublicKeySize]byte
	ephemeralPrivate [ntruprime.PrivateKeySize]byte
	ephemeralMutex   sync.Mutex
)

// regenerateEphemeral rotates the server's ephemeral key. It is invoked
// concurrently to the handling of incoming connections, therefore we need to
// acquire a mutex to ensure noninterference.
func regenerateEphemeral() error {
	pk, sk, err := ntruprime.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	ephemeralMutex.Lock()
	copy(ephemeralPublic[:], pk[:])
	copy(ephemeralPrivate[:], sk[:])
	ephemeralMutex.Unlock()
	return nil
}

// Init prepares the server to start responding to kx initiation requests.
// It calls regenerateEphemeral once, and then once every minute. If we fail
// to rotate our ephemeral key, we bring the server down.
func Init() {
	err := regenerateEphemeral()
	if err != nil {
		panic(err)
	}
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			<-ticker.C
			err := regenerateEphemeral()
			if err != nil {
				panic(err)
			}
		}
	}()
}

func (kx *KX) SetWriteDeadline(t time.Time) {
	kx.Conn.SetWriteDeadline(t)
}

func (kx *KX) SetReadDeadline(t time.Time) {
	kx.Conn.SetReadDeadline(t)
}

func (kx *KX) Close() {
	kx.Conn.Close()
}

func (kx *KX) TheirIdentity() interface{} {
	return sha256.Sum256(kx.TheirPublicKey[:])
}

// deriveKeys returns two 32-byte keys determined exclusively by the contents
// of its parameters.
func (kx *KX) deriveKeys(k1, k2, k3 *[32]byte, r1, r2 *[64]byte) (a, b []byte) {
	d := sha512.New()
	d.Write(k1[:])
	d.Write(r1[:])
	d.Write(k2[:])
	d.Write(r2[:])
	d.Write(k3[:])
	k := d.Sum(nil)
	return k[:32], k[32:64]
}

// genKeyAndSendCipher returns a shared key and sends the corresponding
// ciphertext to the peer.
func genKeyAndSendCipher(conn net.Conn, pk *[ntruprime.PublicKeySize]byte) (*[32]byte, error) {
	c, k, err := ntruprime.Encapsulate(rand.Reader, pk)
	if err != nil {
		return nil, err
	}
	_, err = xdr.Marshal(conn, c)
	return k, err
}

// recvCipherAndGetKey returns a shared key obtained by decrypting a ciphertext
// received from the peer using private key sk.
func recvCipherAndGetKey(conn net.Conn, sk *[ntruprime.PrivateKeySize]byte) (*[32]byte, error) {
	c := new([ntruprime.CiphertextSize]byte)
	_, err := xdr.Unmarshal(conn, c)
	if err != nil {
		return nil, err
	}
	return ntruprime.Decapsulate(c, sk)
}

// genRandomAndSendMAC populates a 64-byte array with random values and sends
// it to the peer along with the array's HMAC with mk as the hash-key. Both the
// array and the HMAC are sent encrypted with ek. The 64-byte array
// (unencrypted) is returned.
func genRandomAndSendMAC(kx *KX, ek, mk *[32]byte) (*[64]byte, error) {
	r := new([64]byte)
	_, err := io.ReadFull(rand.Reader, r[:])
	if err != nil {
		return nil, err
	}
	err = kx.writeWithKey(r[:], ek)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, mk[:])
	m.Write(r[:])
	kx.writeWithKey(m.Sum(nil), ek)
	return r, err
}

// recvRandomAndCheckMAC receives a 64-byte array and a corresponding 32-byte
// HMAC. It ensures that the received HMAC matches the array with mk as the
// hash-key. Both the array and the HMAC are expected to be encrypted with ek.
// The contents of the array are returned (decrypted).
func recvRandomAndCheckMAC(kx *KX, ek, mk *[32]byte) (*[64]byte, error) {
	r := new([64]byte)
	payload, err := kx.readWithKey(ek)
	if err != nil {
		return nil, err
	}
	if len(payload) != 64 {
		return nil, ErrUnmarshal
	}
	copy(r[:], payload)
	payload, err = kx.readWithKey(ek)
	if err != nil {
		return nil, err
	}
	if len(payload) != sha256.Size {
		return nil, ErrUnmarshal
	}
	m := hmac.New(sha256.New, mk[:])
	m.Write(r[:])
	if hmac.Equal(payload, m.Sum(nil)) == false {
		return nil, ErrUnmarshal
	}
	return r, nil
}

// recvEncryptedIdentity receives an identity (a public key) encrypted with ek
// from the peer. The decrypted identity is returned.
func recvEncryptedIdentity(kx *KX, ek *[32]byte) (*[ntruprime.PublicKeySize]byte, error) {
	pk := new([ntruprime.PublicKeySize]byte)
	payload, err := kx.readWithKey(ek)
	if err != nil {
		return nil, err
	}
	if len(payload) != ntruprime.PublicKeySize {
		return nil, ErrUnmarshal
	}
	copy(pk[:], payload)
	return pk, nil
}

// Initiate performs a key exchange on behalf of a connecting client. A key
// exchange involves the following variables:
// k1, k2, k3: NTRU Prime shared keys.
// c1, c2, c3: NTRU Prime ciphertexts corresponding to k1, k2, k3.
// r1, r2: random 64-byte arrays.
// From the perspective of the initiator, the process unfolds as follows:
func (kx *KX) Initiate() error {
	// Step 1: Generate k1, send c1.
	k1, err := genKeyAndSendCipher(kx.Conn, kx.TheirPublicKey)
	if err != nil {
		return err
	}
	// Step 2: Send our public key encrypted with k1.
	err = kx.writeWithKey(kx.OurPublicKey[:], k1)
	if err != nil {
		return err
	}

	// Step 3: Receive c2, obtain k2.
	k2, err := recvCipherAndGetKey(kx.Conn, kx.OurPrivateKey)
	if err != nil {
		return err
	}
	// Step 4: Receive the server's ephemeral public key encrypted with k2.
	theirEphemeralPub, err := recvEncryptedIdentity(kx, k2)
	if err != nil {
		return err
	}

	// Step 5: Generate k3, send c3.
	k3, err := genKeyAndSendCipher(kx.Conn, theirEphemeralPub)
	if err != nil {
		return err
	}
	// Step 6: Send r1 and HMAC(r1, k2) encrypted with k1.
	r1, err := genRandomAndSendMAC(kx, k1, k2)
	if err != nil {
		return err
	}

	// Step 7: Receive r2 and HMAC(r2, k1) encrypted with k2.
	r2, err := recvRandomAndCheckMAC(kx, k2, k1)
	if err != nil {
		return err
	}

	// Step 8: Keys = SHA512(k1 + r1 + k2 + r2 + k3)
	kx.readKey = new([32]byte)
	kx.writeKey = new([32]byte)
	a, b := kx.deriveKeys(k1, k2, k3, r1, r2)
	copy(kx.readKey[:], a)
	copy(kx.writeKey[:], b)

	return nil
}

// Respond performs a key exchange on behalf of a responding server. A key
// exchange involves the following variables:
// k1, k2, k3: NTRU Prime shared keys.
// c1, c2, c3: NTRU Prime ciphertexts corresponding to k1, k2, k3.
// r1, r2: random 64-byte arrays.
// From the perspective of the responder, the process unfolds as follows:
func (kx *KX) Respond() error {
	// Step 1: Obtain a copy of our ephemeral keys.
	epk := new([ntruprime.PublicKeySize]byte)
	esk := new([ntruprime.PrivateKeySize]byte)
	ephemeralMutex.Lock()
	copy(epk[:], ephemeralPublic[:])
	copy(esk[:], ephemeralPrivate[:])
	ephemeralMutex.Unlock()

	// Step 2: Receive c1, obtain k1.
	k1, err := recvCipherAndGetKey(kx.Conn, kx.OurPrivateKey)
	if err != nil {
		return err
	}
	// Step 3: Receive the client's public key encrypted with k1.
	kx.TheirPublicKey, err = recvEncryptedIdentity(kx, k1)
	if err != nil {
		return err
	}

	// Step 4: Generate k2, send c2.
	k2, err := genKeyAndSendCipher(kx.Conn, kx.TheirPublicKey)
	if err != nil {
		return err
	}
	// Step 5: Send our ephemeral public key encrypted with k2.
	err = kx.writeWithKey(epk[:], k2)
	if err != nil {
		return err
	}

	// Step 6: Receive c3, obtain k3.
	k3, err := recvCipherAndGetKey(kx.Conn, esk)
	if err != nil {
		return err
	}
	// Step 7: Receive r1 and HMAC(r1, k2) encrypted with k1.
	r1, err := recvRandomAndCheckMAC(kx, k1, k2)
	if err != nil {
		return err
	}

	// Step 8: Send r2 and HMAC(r2, k1) encrypted k2.
	r2, err := genRandomAndSendMAC(kx, k2, k1)
	if err != nil {
		return err
	}

	// Step 9: Keys = SHA512(k1 + r1 + k2 + r2 + k3)
	kx.readKey = new([32]byte)
	kx.writeKey = new([32]byte)
	a, b := kx.deriveKeys(k1, k2, k3, r1, r2)
	copy(kx.readKey[:], b)
	copy(kx.writeKey[:], a)

	return nil
}

func (kx *KX) readWithKey(k *[32]byte) ([]byte, error) {
	var payload []byte
	_, err := xdr.UnmarshalLimited(kx.Conn, &payload, kx.MaxMessageSize)
	if err != nil {
		return nil, ErrUnmarshal
	}
	data, ok := secretbox.Open(nil, payload, &kx.readSeq, k)
	incSeq(&kx.readSeq)
	if ok == false {
		return nil, ErrDecrypt
	}
	return data, nil
}

func (kx *KX) Read() ([]byte, error) {
	data, err := kx.readWithKey(kx.readKey)
	return data, err
}

func (kx *KX) writeWithKey(data []byte, k *[32]byte) error {
	payload := secretbox.Seal(nil, data, &kx.writeSeq, k)
	incSeq(&kx.writeSeq)
	if uint(len(payload)) > kx.MaxMessageSize {
		return ErrOverflow
	}
	_, err := xdr.Marshal(kx.Conn, payload)
	if err != nil {
		return ErrMarshal
	}
	return nil
}

// Write encrypts and marshals data to the underlying writer.
func (kx *KX) Write(data []byte) error {
	return kx.writeWithKey(data, kx.writeKey)
}

// incSeq increments the provided nonce.
func incSeq(seq *[24]byte) {
	n := uint32(1)
	for i := 0; i < 8; i++ {
		n += uint32(seq[i])
		seq[i] = byte(n)
		n >>= 8
	}
}
