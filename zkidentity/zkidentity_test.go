// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package zkidentity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/companyzero/zkc/ratchet"
	"github.com/davecgh/go-spew/spew"
	"github.com/pmezard/go-difflib/difflib"
)

var (
	alice *FullIdentity
	bob   *FullIdentity
	chris *FullIdentity
)

func pairedRatchet() (a, b *ratchet.Ratchet) {
	a, b = ratchet.New(rand.Reader), ratchet.New(rand.Reader)
	a.MyIdentityPrivate = &alice.PrivateIdentity
	a.MySigningPublic = &alice.Public.Key
	a.TheirIdentityPublic = &bob.Public.Identity
	a.TheirSigningPublic = &bob.Public.Key

	b.MyIdentityPrivate = &bob.PrivateIdentity
	b.MySigningPublic = &bob.Public.Key
	b.TheirIdentityPublic = &alice.Public.Identity
	b.TheirSigningPublic = &alice.Public.Key

	kxA, kxB := new(ratchet.KeyExchange), new(ratchet.KeyExchange)
	if err := a.FillKeyExchange(kxA); err != nil {
		panic(err)
	}
	if err := b.FillKeyExchange(kxB); err != nil {
		panic(err)
	}
	if err := a.CompleteKeyExchange(kxB, true); err != nil {
		panic(err)
	}
	if err := b.CompleteKeyExchange(kxA, true); err != nil {
		panic(err)
	}
	return
}

func pairedImpersonatedRatchet() (a, b, c *ratchet.Ratchet) {
	a, b = ratchet.New(rand.Reader), ratchet.New(rand.Reader)
	a.MyIdentityPrivate = &alice.PrivateIdentity
	a.MySigningPublic = &alice.Public.Key
	a.TheirIdentityPublic = &bob.Public.Identity
	a.TheirSigningPublic = &bob.Public.Key

	b.MyIdentityPrivate = &chris.PrivateIdentity // I am chris
	b.MySigningPublic = &bob.Public.Key          // pretending to be bob
	b.TheirIdentityPublic = &alice.Public.Identity
	b.TheirSigningPublic = &alice.Public.Key

	kxA, kxB := new(ratchet.KeyExchange), new(ratchet.KeyExchange)
	if err := a.FillKeyExchange(kxA); err != nil {
		panic(err)
	}
	if err := b.FillKeyExchange(kxB); err != nil {
		panic(err)
	}
	if err := a.CompleteKeyExchange(kxB, true); err != nil {
		panic(err)
	}
	if err := b.CompleteKeyExchange(kxA, true); err != nil {
		panic(err)
	}
	return
}

func TestNew(t *testing.T) {
	var err error

	alice, err = New("alice mcmoo", "alice")
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}

	bob, err = New("bob laroo", "bob")
	if err != nil {
		t.Fatalf("New bob: %v", err)
	}

	chris, err = New("chris mordor", "chris")
	if err != nil {
		t.Fatalf("New chris: %v", err)
	}
}

func TestEncryptDecryptSmall(t *testing.T) {
	a, b := pairedRatchet()

	msg := []byte("test message")
	encrypted := a.Encrypt(nil, msg)
	result, err := b.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, result) {
		t.Fatalf("result doesn't match: %x vs %x", msg, result)
	}
}

func TestEncryptImpersonatedDecryptSmall(t *testing.T) {
	a, b, c := pairedImpersonatedRatchet()
	_ = c

	msg := []byte("test message")
	encrypted := a.Encrypt(nil, msg)
	result, err := b.Decrypt(encrypted)
	if err == nil {
		t.Fatal("should not have decrypted")
	}
	if bytes.Equal(msg, result) {
		t.Fatalf("results match: %x vs %x", msg, result)
	}
}

func TestEncryptImpersonatedDecryptSmallReversed(t *testing.T) {
	a, b, c := pairedImpersonatedRatchet()
	_ = c

	msg := []byte("test message")
	encrypted := b.Encrypt(nil, msg)
	result, err := a.Decrypt(encrypted)
	if err == nil {
		t.Fatal("should not have decrypted")
	}
	if bytes.Equal(msg, result) {
		t.Fatalf("results match: %x vs %x", msg, result)
	}
}

func TestEncryptDecryptLarge(t *testing.T) {
	a, b := pairedRatchet()

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

func TestMarshalUnmarshal(t *testing.T) {
	am, err := alice.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	a, err := UnmarshalFullIdentity(am)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(a, alice) {
		t.Fatalf("marshal/unmarshal failed")
	}
}

func TestMarshalUnmarshalChanged(t *testing.T) {
	alice.Public.Nick = "a"
	err := alice.RecalculateDigest()
	if err != nil {
		t.Fatal(err)
	}

	am, err := alice.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	a, err := UnmarshalFullIdentity(am)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(a, alice) {
		t.Fatalf("marshal/unmarshal failed")
	}
}

func TestMarshalUnmarshalPublic(t *testing.T) {
	am, err := alice.Public.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	a, err := UnmarshalPublicIdentity(am)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(*a, alice.Public) {
		d := difflib.UnifiedDiff{
			A:        difflib.SplitLines(spew.Sdump(*a)),
			B:        difflib.SplitLines(spew.Sdump(alice.Public)),
			FromFile: "original",
			ToFile:   "current",
			Context:  3,
		}
		text, err := difflib.GetUnifiedDiffString(d)
		if err != nil {
			panic(err)
		}
		t.Fatalf("marshal/unmarshal failed %v", text)
	}
}

func TestString(t *testing.T) {
	s := fmt.Sprintf("%v", alice.Public)
	ss := hex.EncodeToString(alice.Public.Identity[:])
	if s != ss {
		t.Fatalf("stringer not working")
	}
}

func TestSign(t *testing.T) {
	message := []byte("this is a message")
	signature := alice.SignMessage(message)
	if !alice.Public.VerifyMessage(message, signature) {
		t.Fatalf("corrupt signature")
	}
}
