// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addressbook

import (
	"bytes"
	"testing"

	"github.com/companyzero/zkc/zkidentity"
)

func TestDel(t *testing.T) {
	alice, err := zkidentity.New("alice mcmoo", "alice")
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}
	bob, err := zkidentity.New("bob mcbob", "bob")
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}
	ab := New()
	_, err = ab.Add(alice.Public)
	if err != nil {
		t.Fatalf("could not add alice")
	}
	_, err = ab.Add(bob.Public)
	if err != nil {
		t.Fatalf("could not add bob")
	}
	err = ab.Del(alice.Public.Identity)
	if err != nil {
		t.Fatalf("unexpected error in Del: %v", err)
	}

	// negative
	err = ab.Del(alice.Public.Identity)
	if err != ErrNotFound {
		t.Fatalf("unexpected error in Del: %v", err)
	}
}

func TestDuplicate(t *testing.T) {
	alice, err := zkidentity.New("alice mcmoo", "alice")
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}
	ab := New()
	_, err = ab.Add(alice.Public)
	if err != nil {
		t.Fatalf("could not add alice")
	}

	// same alice
	nick1, err := ab.Add(alice.Public)
	if err != nil {
		t.Fatalf("could not add same alice: %v", err)
	}

	// new alice
	alice.Public.Identity[0] = 0x01
	nick2, err := ab.Add(alice.Public)
	if err != ErrDuplicateNick {
		t.Fatalf("nick not duplicate")
	}

	if nick1+"_" != nick2 {
		t.Fatalf("nick not underscored %v %v", nick1, nick2)
	}
}

func TestFindNickAndIdentity(t *testing.T) {
	alice, err := zkidentity.New("alice mcmoo", "alice")
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}
	bob, err := zkidentity.New("bob mcbob", "bob")
	if err != nil {
		t.Fatalf("New bob: %v", err)
	}
	ab := New()
	_, err = ab.Add(bob.Public)
	if err != nil {
		t.Fatalf("could not add bob")
	}
	_, err = ab.Add(alice.Public)
	if err != nil {
		t.Fatalf("could not add alice")
	}
	id, err := ab.FindNick(alice.Public.Nick)
	if err != nil {
		t.Fatal(err)
	}
	if id.Nick != alice.Public.Nick {
		t.Fatalf("invalid nick")
	}

	id, err = ab.FindIdentity(alice.Public.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id.Identity[:], alice.Public.Identity[:]) {
		t.Fatalf("invalid identity")
	}

	// negative
	_, err = ab.FindNick("moo")
	if err != ErrNotFound {
		t.Fatal(err)
	}
	_, err = ab.FindIdentity([zkidentity.IdentitySize]byte{0x11})
	if err != ErrNotFound {
		t.Fatal(err)
	}
}

func TestAll(t *testing.T) {
	alice, err := zkidentity.New("alice mcmoo", "alice")
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}
	bob, err := zkidentity.New("bob moo", "bob")
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}
	ab := New()
	_, err = ab.Add(alice.Public)
	if err != nil {
		t.Fatalf("could not add alice")
	}
	_, err = ab.Add(bob.Public)
	if err != nil {
		t.Fatalf("could not add bob")
	}

	all := ab.All()
	if len(all) != 2 {
		t.Fatalf("invalid All")
	}
}
