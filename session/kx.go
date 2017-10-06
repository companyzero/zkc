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
	"net"
	"sync"
	"time"

	"github.com/companyzero/sntrup4591761"
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
	OurPrivateKey  *[sntrup4591761.PrivateKeySize]byte
	OurPublicKey   *[sntrup4591761.PublicKeySize]byte
	TheirPublicKey *[sntrup4591761.PublicKeySize]byte
	writeKey       *[32]byte
	readKey        *[32]byte
	writeSeq       [24]byte
	readSeq        [24]byte
}

// A pair of ephemeral keys is kept to ensure key erasure (forward secrecy)
// should long-term keys be compromised.
var (
	ephemeralPublic  [sntrup4591761.PublicKeySize]byte
	ephemeralPrivate [sntrup4591761.PrivateKeySize]byte
	ephemeralMutex   sync.Mutex
)

// regenerateEphemeral rotates the server/client's ephemeral key. It is invoked
// concurrently to the operation of the server/client, therefore we need to
// acquire a mutex to ensure noninterference.
func regenerateEphemeral() error {
	pk, sk, err := sntrup4591761.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	ephemeralMutex.Lock()
	copy(ephemeralPublic[:], pk[:])
	copy(ephemeralPrivate[:], sk[:])
	ephemeralMutex.Unlock()
	return nil
}

// zeroEphemeral erases the contents of ephemeralP{ublic,rivate}.
func zeroEphemeral() {
	for i := range ephemeralPublic {
		ephemeralPublic[i] ^= ephemeralPublic[i]
	}
	for i := range ephemeralPrivate {
		ephemeralPrivate[i] ^= ephemeralPrivate[i]
	}
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

type Printable func(int, string, ...interface{})

var diagnosticFunction Printable

// SetDiagnostic allows a function of the Printable type to be
// specified as the routine to be called for instrumentation of the
// kx code.
func SetDiagnostic(f Printable) {
	diagnosticFunction = f
}

func D(id int, fmt string, args ...interface{}) {
	if diagnosticFunction != nil {
		diagnosticFunction(id, fmt, args)
	}
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
func deriveKeys(parts ...*[32]byte) (*[32]byte, *[32]byte) {
	d := sha512.New()
	for _, p := range parts {
		d.Write(p[:])
	}
	k := d.Sum(nil)
	a := new([32]byte)
	b := new([32]byte)
	copy(a[:], k[:32])
	copy(b[:], k[32:64])
	return a, b
}

// genKeyAndSendCipher returns a NTRU Prime shared key and sends the
// corresponding ciphertext to our peer. The transmission is encrypted
// if ek is not nil.
func genKeyAndSendCipher(kx *KX, pk *[sntrup4591761.PublicKeySize]byte, ek *[32]byte) (*[32]byte, error) {
	c, k, err := sntrup4591761.Encapsulate(rand.Reader, pk)
	if err != nil {
		return nil, err
	}
	if ek != nil {
		err = kx.writeWithKey(c[:], ek)
	} else {
		_, err = xdr.Marshal(kx.Conn, c)
	}
	return k, err
}

// recvCipherAndGetKey returns a shared key obtained by decrypting a ciphertext
// received from our peer using private key sk. The received payload is
// decrypted using ek if it is not nil.
func recvCipherAndGetKey(kx *KX, sk *[sntrup4591761.PrivateKeySize]byte, ek *[32]byte) (*[32]byte, int) {
	c := new([sntrup4591761.CiphertextSize]byte)
	if ek != nil {
		x, err := kx.readWithKey(ek)
		if err != nil {
			return nil, 0
		}
		if len(x) != len(c) {
			return nil, 0
		}
		copy(c[:], x)
	} else {
		_, err := xdr.Unmarshal(kx.Conn, c)
		if err != nil {
			return nil, 0
		}
	}
	return sntrup4591761.Decapsulate(c, sk)
}

// sendProof sends a HMAC proof to our peer. The data hashed is formed by the
// concatenation of the parts array. The key used in the HMAC is given by mk.
// The payload is sent encrypted with ek.
func sendProof(kx *KX, mk, ek *[32]byte, parts ...[]byte) ([]byte, error) {
	h := hmac.New(sha256.New, mk[:])
	for _, p := range parts {
		h.Write(p)
	}
	d := h.Sum(nil)
	err := kx.writeWithKey(d, ek)
	if err != nil {
		return nil, err
	}
	return d, err
}

// recvProof receives and verifies a HMAC proof from our peer. The data hashed
// is formed by the concatenation of the parts array. The key used in the HMAC
// is given by mk. The received payload is decrypted with ek.
func recvProof(kx *KX, mk, ek *[32]byte, parts ...[]byte) ([]byte, error) {
	h := hmac.New(sha256.New, mk[:])
	for _, p := range parts {
		h.Write(p)
	}
	d := h.Sum(nil)
	rd, err := kx.readWithKey(ek)
	if err != nil {
		return nil, err
	}
	if len(rd) != sha256.Size {
		return nil, ErrUnmarshal
	}
	D(0, "[session.recvProof] expected proof: %x", d)
	D(0, "[session.recvProof] received proof: %x", rd)
	if hmac.Equal(d, rd) == false {
		return nil, ErrUnmarshal
	}
	return d, nil
}

// recvEncryptedIdentity receives an identity (a public key) encrypted with ek
// from our peer. The decrypted identity is returned.
func recvEncryptedIdentity(kx *KX, ek *[32]byte) (*[sntrup4591761.PublicKeySize]byte, error) {
	pk := new([sntrup4591761.PublicKeySize]byte)
	payload, err := kx.readWithKey(ek)
	if err != nil {
		return nil, err
	}
	if len(payload) != sntrup4591761.PublicKeySize {
		return nil, ErrUnmarshal
	}
	copy(pk[:], payload)
	return pk, nil
}

// Initiate performs a key exchange on behalf of a connecting client. A key
// exchange involves the following variables:
// k1, k2, k3, k4: NTRU Prime shared keys.
// c1, c2, c3, c4: NTRU Prime ciphertexts corresponding to k1, k2, k3, k4.
// From the perspective of the initiator, the process unfolds as follows:
func (kx *KX) Initiate() error {
	if err := regenerateEphemeral(); err != nil {
		return err
	}
	defer zeroEphemeral()

	D(0, "[session.Initiate] ephemeral public:\n%x", ephemeralPublic)
	D(0, "[session.Initiate] ephemeral private:\n%x", ephemeralPrivate)
	D(0, "[session.Initiate] our public key:\n%x", *kx.OurPublicKey)
	D(0, "[session.Initiate] their public key:\n%x", *kx.TheirPublicKey)

	// Step 1: Generate k1, send c1.
	k1, err := genKeyAndSendCipher(kx, kx.TheirPublicKey, nil)
	if err != nil {
		return err
	}
	// Step 2: Send our ephemeral public key encrypted with k1.
	err = kx.writeWithKey(ephemeralPublic[:], k1)
	if err != nil {
		return err
	}

	// Step 3: Receive c2 encrypted with k1, obtain k2.
	k2, ok := recvCipherAndGetKey(kx, &ephemeralPrivate, k1)
	if ok != 1 {
		return ErrInvalidKx
	}
	// Step 4: Receive the server's ephemeral public key encrypted with k2.
	theirEphemeralPub, err := recvEncryptedIdentity(kx, k2)
	if err != nil {
		return err
	}
	// Step 5: Receive server's initial proof binding the ephemeral keys to k1.
	sp, err := recvProof(kx, k1, k2, ephemeralPublic[:], theirEphemeralPub[:])
	if err != nil {
		return err
	}

	// Step 6: Generate k3, send c3 encrypted with k2.
	k3, err := genKeyAndSendCipher(kx, theirEphemeralPub, k2)
	if err != nil {
		return err
	}
	// Step 7: Send our public key encrypted with k3.
	err = kx.writeWithKey(kx.OurPublicKey[:], k3)
	if err != nil {
		return err
	}
	// Step 8: Send our proof to the server encrypted with k3.
	cp, err := sendProof(kx, k2, k3, sp, kx.OurPublicKey[:])
	if err != nil {
		return err
	}

	// Step 9: Receive c4 encrypted with k3, obtain k4.
	k4, ok := recvCipherAndGetKey(kx, kx.OurPrivateKey, k3)
	if ok != 1 {
		return ErrInvalidKx
	}
	// Step 10: Receive server's proof binding its public key to k3.
	_, err = recvProof(kx, k3, k4, cp, kx.TheirPublicKey[:])
	if err != nil {
		return err
	}

	kx.readKey, kx.writeKey = deriveKeys(k1, k2, k3, k4)

	D(0, "[session.Initiate] readKey: %x", *kx.readKey)
	D(0, "[session.Initiate] writeKey: %x", *kx.writeKey)

	return nil
}

// Respond performs a key exchange on behalf of a responding server. A key
// exchange involves the following variables:
// k1, k2, k3, k4: NTRU Prime shared keys.
// c1, c2, c3, c4: NTRU Prime ciphertexts corresponding to k1, k2, k3, k4.
// From the perspective of the responder, the process unfolds as follows:
func (kx *KX) Respond() error {
	// Step 0: Obtain a copy of our ephemeral keys.
	epk := new([sntrup4591761.PublicKeySize]byte)
	esk := new([sntrup4591761.PrivateKeySize]byte)
	ephemeralMutex.Lock()
	copy(epk[:], ephemeralPublic[:])
	copy(esk[:], ephemeralPrivate[:])
	ephemeralMutex.Unlock()

	D(0, "[session.Respond] ephemeral public:\n%x", *epk)
	D(0, "[session.Respond] ephemeral private:\n%x", *esk)
	D(0, "[session.Respond] our public key:\n%x", *kx.OurPublicKey)

	// Step 1: Receive c1, obtain k1.
	k1, ok := recvCipherAndGetKey(kx, kx.OurPrivateKey, nil)
	if ok != 1 {
		return ErrInvalidKx
	}
	// Step 2: Receive the client's ephemeral public key encrypted with k1.
	theirEphemeralPub, err := recvEncryptedIdentity(kx, k1)
	if err != nil {
		return err
	}

	// Step 3: Generate k2, send c2 encrypted with k1.
	k2, err := genKeyAndSendCipher(kx, theirEphemeralPub, k1)
	if err != nil {
		return err
	}
	// Step 4: Send our ephemeral public key encrypted with k2.
	err = kx.writeWithKey(epk[:], k2)
	if err != nil {
		return err
	}
	// Step 5: Send our initial proof.
	sp, err := sendProof(kx, k1, k2, theirEphemeralPub[:], epk[:])
	if err != nil {
		return err
	}

	// Step 6: Receive c3 encrypted with k2, obtain k3.
	k3, ok := recvCipherAndGetKey(kx, esk, k2)
	if ok != 1 {
		return ErrInvalidKx
	}
	// Step 7: Receive the client's public key encrypted with k3.
	kx.TheirPublicKey, err = recvEncryptedIdentity(kx, k3)
	if err != nil {
		return err
	}
	// Step 8: Receive and verify the client proof encrypted with k3.
	cp, err := recvProof(kx, k2, k3, sp, kx.TheirPublicKey[:])
	if err != nil {
		return err
	}

	// Step 9: Generate k4, send c4 encrypted with k3.
	k4, err := genKeyAndSendCipher(kx, kx.TheirPublicKey, k3)
	if err != nil {
		return err
	}
	// Step 10: Send a proof binding our public key to k3.
	_, err = sendProof(kx, k3, k4, cp, kx.OurPublicKey[:])
	if err != nil {
		return err
	}

	kx.writeKey, kx.readKey = deriveKeys(k1, k2, k3, k4)

	D(0, "[session.Respond] their public key:\n%x", *kx.TheirPublicKey)
	D(0, "[session.Respond] readKey: %x", *kx.readKey)
	D(0, "[session.Respond] writeKey: %x", *kx.writeKey)

	return nil
}

func (kx *KX) readWithKey(k *[32]byte) ([]byte, error) {
	var payload []byte
	_, err := xdr.UnmarshalLimited(kx.Conn, &payload, kx.MaxMessageSize)
	if err != nil {
		return nil, err
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
