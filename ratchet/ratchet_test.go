// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ratchet

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/companyzero/zkc/ratchet/disk"
	"github.com/davecgh/go-xdr/xdr2"

	"golang.org/x/crypto/curve25519"
)

type client struct {
	// priv is an Ed25519 private key.
	priv [64]byte
	// pub is the public key corresponding to priv.
	pub [32]byte
	// identity is a curve25519 private value that's used to authenticate
	// the client to its home server.
	identity, identityPublic [32]byte
}

func nowFunc() time.Time {
	var t time.Time
	return t
}

func newClient() *client {
	c := client{}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	copy(c.priv[:], priv[:])
	copy(c.pub[:], pub[:])
	extra25519.PrivateKeyToCurve25519(&c.identity, priv)
	curve25519.ScalarBaseMult(&c.identityPublic, &c.identity)

	return &c
}

func pairedRatchet(t *testing.T) (a, b *Ratchet) {
	alice := newClient()
	bob := newClient()

	a, b = New(rand.Reader), New(rand.Reader)
	a.Now = nowFunc
	b.Now = nowFunc
	a.MyIdentityPrivate = &alice.identity
	b.MyIdentityPrivate = &bob.identity
	a.TheirIdentityPublic = &bob.identityPublic
	b.TheirIdentityPublic = &alice.identityPublic
	a.MySigningPublic = &alice.pub
	b.MySigningPublic = &bob.pub
	a.TheirSigningPublic = &bob.pub
	b.TheirSigningPublic = &alice.pub

	kxA, kxB := new(KeyExchange), new(KeyExchange)
	if err := a.FillKeyExchange(kxA); err != nil {
		t.Fatal(err)
	}
	if err := b.FillKeyExchange(kxB); err != nil {
		t.Fatal(err)
	}
	if err := a.CompleteKeyExchange(kxB, true); err != nil {
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
	newR.MyIdentityPrivate = r.MyIdentityPrivate
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
	a, b := New(rand.Reader), New(rand.Reader)
	a.Now = nowFunc
	a.MyIdentityPrivate = &alice.identity
	a.MySigningPublic = &alice.pub

	// full ratchet
	b.Now = nowFunc
	b.MyIdentityPrivate = &bob.identity
	b.MySigningPublic = &bob.pub
	b.TheirIdentityPublic = &alice.identityPublic
	b.TheirSigningPublic = &alice.pub

	kxB := new(KeyExchange)
	if err := b.FillKeyExchange(kxB); err != nil {
		panic(err)
	}

	// remainder of alice
	kxA := new(KeyExchange)
	if err := a.FillKeyExchange(kxA); err != nil {
		panic(err)
	}
	a.TheirIdentityPublic = &bob.identityPublic
	a.TheirSigningPublic = &bob.pub
	if err := a.CompleteKeyExchange(kxB, true); err != nil {
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

func TestECDHpoints(y *testing.T) {
	alice := newClient()
	bob := newClient()

	a, b := New(rand.Reader), New(rand.Reader)
	a.Now = nowFunc
	b.Now = nowFunc
	a.MyIdentityPrivate = &alice.identity
	b.MyIdentityPrivate = &bob.identity
	a.TheirIdentityPublic = &bob.identityPublic
	b.TheirIdentityPublic = &alice.identityPublic
	a.MySigningPublic = &alice.pub
	b.MySigningPublic = &bob.pub
	a.TheirSigningPublic = &bob.pub
	b.TheirSigningPublic = &alice.pub

	kxA := new(KeyExchange)
	if err := a.FillKeyExchange(kxA); err != nil {
		panic(err)
	}

	// test 1: Dh = 0
	kxA.Dh = make([]byte, 32)
	err := b.CompleteKeyExchange(kxA, true)
	if err == nil {
		panic("invalid ECDH kx succeeded")
	}

	// test 2: Dh = 1
	kxA.Dh[0] = 1
	err = b.CompleteKeyExchange(kxA, true)
	if err == nil {
		panic("invalid ECDH kx succeeded")
	}

	// test 3: Dh = 2^256 - 1
	for i := 0; i < 32; i++ {
		kxA.Dh[i] = 0xff
	}
	err = b.CompleteKeyExchange(kxA, true)
	if err == nil {
		panic("invalid ECDH kx succeeded")
	}

	return
}

func TestImpersonation(t *testing.T) {
	alice := newClient()
	bob := newClient()
	chris := newClient()

	b := New(rand.Reader)
	b.Now = nowFunc
	b.MyIdentityPrivate = &bob.identity
	b.MySigningPublic = &bob.pub

	c := New(rand.Reader)
	c.Now = nowFunc
	c.MyIdentityPrivate = &chris.identity
	c.MySigningPublic = &chris.pub

	// pair Bob and Chris
	b.TheirIdentityPublic = &chris.identityPublic
	b.TheirSigningPublic = &chris.pub
	c.TheirIdentityPublic = &bob.identityPublic
	c.TheirIdentityPublic = &bob.pub

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
	if err := c.CompleteKeyExchange(kxBC, true); err != nil {
		t.Fatal(err)
	}
	if err := b.CompleteKeyExchange(kxCB, true); err != nil {
		t.Fatal(err)
	}

	// Chris knows Bob's public key, and will now impersonate Bob to Alice.
	a := New(rand.Reader)
	a.Now = nowFunc
	a.MyIdentityPrivate = &alice.identity
	a.MySigningPublic = &alice.pub

	notB := New(rand.Reader)
	notB.Now = nowFunc
	notB.MyIdentityPrivate = &chris.identity // I am actually Chris...
	notB.MySigningPublic = &bob.pub          // But Alice will think I am Bob.

	// Alice thinks she's talking to Bob
	a.TheirIdentityPublic = &bob.identityPublic
	a.TheirSigningPublic = &bob.pub

	// While notBob (Chris) knows it's talking to Alice
	notB.TheirIdentityPublic = &alice.identityPublic
	notB.TheirSigningPublic = &alice.pub

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
	if err := a.CompleteKeyExchange(kxCA, true); err != nil {
		t.Fatal(err)
	}
	if err := notB.CompleteKeyExchange(kxAC, true); err != nil {
		t.Fatal(err)
	}

	// see if we can go back and forth
	msg := []byte("test message")
	encrypted := a.Encrypt(nil, msg)
	result, err := notB.Decrypt(encrypted)
	if err == nil {
		t.Fatal("should not have decrypted")
	}
	if bytes.Equal(msg, result) {
		t.Fatalf("results match: %x vs %x", msg, result)
	}

	// reverse direction
	encrypted = notB.Encrypt(nil, msg)
	result, err = a.Decrypt(encrypted)
	if err == nil {
		t.Fatal("should not have decrypted")
	}
	if bytes.Equal(msg, result) {
		t.Fatalf("results match: %x vs %x", msg, result)
	}
}
