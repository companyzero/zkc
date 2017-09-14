// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ratchet

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agl/ed25519"
	"github.com/companyzero/sntrup4591761"
	"github.com/companyzero/zkc/blobshare"
	"github.com/companyzero/zkc/ratchet/disk"
	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/curve25519"
)

type client struct {
	PrivateKey     [sntrup4591761.PrivateKeySize]byte
	PublicKey      [sntrup4591761.PublicKeySize]byte
	SigningPrivate [64]byte
	SigningPublic  [32]byte
	Identity       [sha256.Size]byte
}

func nowFunc() time.Time {
	var t time.Time
	return t
}

func newClient() *client {
	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	ntruprimePub, ntruprimePriv, err := sntrup4591761.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	identity := sha256.Sum256(ntruprimePub[:])

	c := client{}
	copy(c.SigningPrivate[:], ed25519Priv[:])
	copy(c.SigningPublic[:], ed25519Pub[:])
	copy(c.PrivateKey[:], ntruprimePriv[:])
	copy(c.PublicKey[:], ntruprimePub[:])
	copy(c.Identity[:], identity[:])

	return &c
}

func pairedRatchet(t *testing.T) (a, b *Ratchet) {
	alice := newClient()
	bob := newClient()

	a = New(rand.Reader)
	a.Now = nowFunc
	a.MyPrivateKey = &alice.PrivateKey
	a.MySigningPublic = &alice.SigningPublic
	a.TheirIdentityPublic = &bob.Identity
	a.TheirSigningPublic = &bob.SigningPublic
	a.TheirPublicKey = &bob.PublicKey

	b = New(rand.Reader)
	b.Now = nowFunc
	b.MyPrivateKey = &bob.PrivateKey
	b.MySigningPublic = &bob.SigningPublic
	b.TheirIdentityPublic = &alice.Identity
	b.TheirSigningPublic = &alice.SigningPublic
	b.TheirPublicKey = &alice.PublicKey

	kxA, kxB := new(KeyExchange), new(KeyExchange)
	if err := a.FillKeyExchange(kxA); err != nil {
		t.Fatal(err)
	}
	if err := b.FillKeyExchange(kxB); err != nil {
		t.Fatal(err)
	}
	if err := a.CompleteKeyExchange(kxB, false); err != nil {
		t.Fatal(err)
	}
	if err := b.CompleteKeyExchange(kxA, true); err != nil {
		t.Fatal(err)
	}

	return
}

func TestExchange(t *testing.T) {
	a, b := pairedRatchet(t)

	msg := []byte(strings.Repeat("test message", 1024*1024))
	encrypted := a.Encrypt(nil, msg)
	result, err := b.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, result) {
		t.Fatalf("result doesn't match: %x vs %x", msg, result)
	}
}

type scriptAction struct {
	// object is one of sendA, sendB or sendDelayed. The first two options
	// cause a message to be sent from one party to the other. The latter
	// causes a previously delayed message, identified by id, to be
	// delivered.
	object int
	// result is one of deliver, drop or delay. If delay, then the message
	// is stored using the value in id. This value can be repeated later
	// with a sendDelayed.
	result int
	id     int
}

const (
	sendA = iota
	sendB
	sendDelayed
	deliver
	drop
	delay
)

func reinitRatchet(t *testing.T, r *Ratchet) *Ratchet {
	state := r.Marshal(nowFunc(), 1*time.Hour)
	newR := New(rand.Reader)
	newR.Now = nowFunc
	newR.MyPrivateKey = r.MyPrivateKey
	newR.TheirIdentityPublic = r.TheirIdentityPublic
	newR.MySigningPublic = r.MySigningPublic
	newR.TheirSigningPublic = r.TheirSigningPublic
	if err := newR.Unmarshal(state); err != nil {
		t.Fatalf("Failed to unmarshal: %s", err)
	}

	return newR

}

func testScript(t *testing.T, script []scriptAction) {
	type delayedMessage struct {
		msg       []byte
		encrypted []byte
		fromA     bool
	}
	delayedMessages := make(map[int]delayedMessage)
	a, b := pairedRatchet(t)

	for i, action := range script {
		switch action.object {
		case sendA, sendB:
			sender, receiver := a, b
			if action.object == sendB {
				sender, receiver = receiver, sender
			}

			var msg [20]byte
			rand.Reader.Read(msg[:])
			encrypted := sender.Encrypt(nil, msg[:])

			switch action.result {
			case deliver:
				result, err := receiver.Decrypt(encrypted)
				if err != nil {
					t.Fatalf("#%d: receiver returned error: %s", i, err)
				}
				if !bytes.Equal(result, msg[:]) {
					t.Fatalf("#%d: bad message: got %x, not %x", i, result, msg[:])
				}
			case delay:
				if _, ok := delayedMessages[action.id]; ok {
					t.Fatalf("#%d: already have delayed message with id %d", i, action.id)
				}
				delayedMessages[action.id] = delayedMessage{msg[:], encrypted, sender == a}
			case drop:
			}
		case sendDelayed:
			delayed, ok := delayedMessages[action.id]
			if !ok {
				t.Fatalf("#%d: no such delayed message id: %d", i, action.id)
			}

			receiver := a
			if delayed.fromA {
				receiver = b
			}

			result, err := receiver.Decrypt(delayed.encrypted)
			if err != nil {
				t.Fatalf("#%d: receiver returned error: %s", i, err)
			}
			if !bytes.Equal(result, delayed.msg) {
				t.Fatalf("#%d: bad message: got %x, not %x", i, result, delayed.msg)
			}
		}

		a = reinitRatchet(t, a)
		b = reinitRatchet(t, b)
	}
}

func TestBackAndForth(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
	})
}

func TestReorder(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendA, delay, 0},
		{sendA, deliver, -1},
		{sendDelayed, deliver, 0},
	})
}

func TestReorderAfterRatchet(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendA, delay, 0},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendDelayed, deliver, 0},
	})
}

func TestDrop(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
	})
}

func TestLots(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
		{sendB, deliver, -1},
	})
}

func TestHalfDiskState(t *testing.T) {
	alice := newClient()
	bob := newClient()

	// half ratchet
	a := New(rand.Reader)
	a.Now = nowFunc
	a.MyPrivateKey = &alice.PrivateKey
	a.MySigningPublic = &alice.SigningPublic
	a.TheirPublicKey = &bob.PublicKey

	// full ratchet
	b := New(rand.Reader)
	b.Now = nowFunc
	b.MyPrivateKey = &bob.PrivateKey
	b.MySigningPublic = &bob.SigningPublic
	b.TheirIdentityPublic = &alice.Identity
	b.TheirSigningPublic = &alice.SigningPublic
	b.TheirPublicKey = &alice.PublicKey

	kxB := new(KeyExchange)
	if err := b.FillKeyExchange(kxB); err != nil {
		panic(err)
	}

	// remainder of alice
	kxA := new(KeyExchange)
	if err := a.FillKeyExchange(kxA); err != nil {
		panic(err)
	}
	a.TheirIdentityPublic = &bob.Identity
	a.TheirSigningPublic = &bob.SigningPublic
	if err := a.CompleteKeyExchange(kxB, false); err != nil {
		panic(err)
	}

	// return kx to bob
	if err := b.CompleteKeyExchange(kxA, true); err != nil {
		panic(err)
	}
}

func TestDiskState(t *testing.T) {
	a, b := pairedRatchet(t)

	msg := []byte("test message")
	encrypted := a.Encrypt(nil, msg)
	result, err := b.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, result) {
		t.Fatalf("result doesn't match: %x vs %x", msg, result)
	}

	encrypted = b.Encrypt(nil, msg)
	result, err = a.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, result) {
		t.Fatalf("result doesn't match: %x vs %x", msg, result)
	}

	// save alice ratchet state to disk
	as := a.Marshal(time.Now(), time.Hour)
	af, err := ioutil.TempFile("", "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(af.Name())
	_, err = xdr.Marshal(af, as)
	if err != nil {
		t.Fatal(err)
	}

	// save bob ratchet state to disk
	bs := b.Marshal(time.Now(), time.Hour)
	bf, err := ioutil.TempFile("", "bob")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(bf.Name())
	_, err = xdr.Marshal(bf, bs)
	if err != nil {
		t.Fatal(err)
	}

	// read back alice
	_, err = af.Seek(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var diskAlice disk.RatchetState
	_, err = xdr.Unmarshal(af, &diskAlice)
	if err != nil {
		t.Fatal(err)
	}
	newAlice := New(rand.Reader)
	err = newAlice.Unmarshal(&diskAlice)
	if err != nil {
		t.Fatal(err)
	}

	// read back bob
	_, err = bf.Seek(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var diskBob disk.RatchetState
	_, err = xdr.Unmarshal(bf, &diskBob)
	if err != nil {
		t.Fatal(err)
	}
	newBob := New(rand.Reader)
	err = newBob.Unmarshal(&diskBob)
	if err != nil {
		t.Fatal(err)
	}

	// send message to alice
	encrypted = newBob.Encrypt(nil, msg)
	result, err = newAlice.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, result) {
		t.Fatalf("result doesn't match: %x vs %x", msg, result)
	}

	encrypted = newAlice.Encrypt(nil, msg)
	result, err = newBob.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, result) {
		t.Fatalf("result doesn't match: %x vs %x", msg, result)
	}
}

func FillKeyExchangeWithPublicPoint(r *Ratchet, kx *KeyExchange, pub *[32]byte) error {
	c, k, err := sntrup4591761.Encapsulate(r.rand, r.TheirPublicKey)
	if err != nil {
		return err
	}
	blobshare.SetNrp(32768, 16, 2)
	key, salt, err := blobshare.NewKey(k[:])
	if err != nil {
		return err
	}
	encrypted, nonce, err := blobshare.Encrypt(pub[:], key)
	if err != nil {
		return err
	}
	packed := blobshare.PackSaltNonce(salt, nonce, encrypted)

	r.MyHalf = k
	copy(kx.Cipher[:], c[:])
	kx.Public = packed

	return nil
}

func testECDHpoint(t *testing.T, a *Ratchet, pubDH *[32]byte) error {
	alice := newClient()
	bob := newClient()

	a.Now = nowFunc
	a.MyPrivateKey = &alice.PrivateKey
	a.MySigningPublic = &alice.SigningPublic
	a.TheirIdentityPublic = &bob.Identity
	a.TheirSigningPublic = &bob.SigningPublic
	a.TheirPublicKey = &bob.PublicKey

	b := New(rand.Reader)
	b.Now = nowFunc
	b.MyPrivateKey = &bob.PrivateKey
	b.MySigningPublic = &bob.SigningPublic
	b.TheirIdentityPublic = &alice.Identity
	b.TheirSigningPublic = &alice.SigningPublic
	b.TheirPublicKey = &alice.PublicKey

	kxA, kxB := new(KeyExchange), new(KeyExchange)
	if err := FillKeyExchangeWithPublicPoint(a, kxA, pubDH); err != nil {
		t.Fatal(err)
	}
	if err := b.FillKeyExchange(kxB); err != nil {
		t.Fatal(err)
	}
	if err := a.CompleteKeyExchange(kxB, false); err != nil {
		return err
	}
	if err := b.CompleteKeyExchange(kxA, true); err != nil {
		return err
	}

	return nil
}

func TestECDHpoints(t *testing.T) {
	a := New(rand.Reader)
	pubDH := new([32]byte)
	// test 1: dh = 0
	err := testECDHpoint(t, a, pubDH)
	if err == nil {
		panic("invalid ECDH kx succeeded")
	}
	// test 2: dh = 1
	a = New(rand.Reader)
	pubDH[0] = 1
	err = testECDHpoint(t, a, pubDH)
	if err == nil {
		panic("invalid ECDH kx succeeded")
	}
	// test 3: Dh = 2^256 - 1
	a = New(rand.Reader)
	for i := 0; i < 32; i++ {
		pubDH[i] = 0xff
	}
	err = testECDHpoint(t, a, pubDH)
	if err == nil {
		panic("invalid ECDH kx succeeded")
	}
	// test 4: make sure testECDHpoint() works
	a = New(rand.Reader)
	curve25519.ScalarBaseMult(pubDH, a.kxPrivate)
	err = testECDHpoint(t, a, pubDH)
	if err != nil {
		panic("valid ECDH kx failed")
	}
}

func TestImpersonation(t *testing.T) {
	alice := newClient()
	bob := newClient()
	chris := newClient()

	b := New(rand.Reader)
	b.Now = nowFunc
	b.MyPrivateKey = &bob.PrivateKey
	b.MySigningPublic = &bob.SigningPublic

	c := New(rand.Reader)
	c.Now = nowFunc
	c.MyPrivateKey = &chris.PrivateKey
	c.MySigningPublic = &chris.SigningPublic

	// pair Bob and Chris
	b.TheirIdentityPublic = &chris.Identity
	b.TheirSigningPublic = &chris.SigningPublic
	b.TheirPublicKey = &chris.PublicKey
	c.TheirIdentityPublic = &bob.Identity
	c.TheirIdentityPublic = &bob.SigningPublic
	c.TheirPublicKey = &bob.PublicKey

	// kx from Bob to Chris
	kxBC := new(KeyExchange)
	if err := b.FillKeyExchange(kxBC); err != nil {
		t.Fatal(err)
	}
	// kx from Chris to Bob
	kxCB := new(KeyExchange)
	if err := c.FillKeyExchange(kxCB); err != nil {
		t.Fatal(err)
	}
	if err := c.CompleteKeyExchange(kxBC, false); err != nil {
		t.Fatal(err)
	}
	if err := b.CompleteKeyExchange(kxCB, true); err != nil {
		t.Fatal(err)
	}

	// Chris knows Bob's public key, and will now impersonate Bob to Alice.
	a := New(rand.Reader)
	a.Now = nowFunc
	a.MyPrivateKey = &alice.PrivateKey
	a.MySigningPublic = &alice.SigningPublic

	notB := New(rand.Reader)
	notB.Now = nowFunc
	notB.MyPrivateKey = &chris.PrivateKey     // I am actually Chris...
	notB.MySigningPublic = &bob.SigningPublic // But Alice will think I am Bob.

	// Alice thinks she's talking to Bob
	a.TheirIdentityPublic = &bob.Identity
	a.TheirSigningPublic = &bob.SigningPublic
	a.TheirPublicKey = &bob.PublicKey

	// While notBob (Chris) knows it's talking to Alice
	notB.TheirIdentityPublic = &alice.Identity
	notB.TheirSigningPublic = &alice.SigningPublic
	notB.TheirPublicKey = &alice.PublicKey

	kxCA := new(KeyExchange)
	if err := notB.FillKeyExchange(kxCA); err != nil {
		t.Fatal(err)
	}
	kxAC := new(KeyExchange)
	if err := a.FillKeyExchange(kxAC); err != nil {
		t.Fatal(err)
	}
	// Here, Chris (notB) is able to complete a kx with Alice on behalf of
	// Bob. Notice that this also works with bogus Dh, Dh1 values:
	// for i := 0; i < len(kxCA.Dh); i++ {
	// 	kxCA.Dh[i] = 0
	// }
	// for i := 0; i < len(kxCA.Dh1); i++ {
	// 	kxCA.Dh1[i] = 0
	// }
	// ^ These could be set to 1 to leak part of a zkclient's private key.
	if err := a.CompleteKeyExchange(kxCA, false); err != nil {
		t.Fatal(err)
	}
	if err := notB.CompleteKeyExchange(kxAC, true); err == nil {
		t.Fatal("kx should not have completed")
	}
}
