// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package account

import (
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/companyzero/zkc/zkidentity"
)

var (
	a *Account
)

func init() {
	root, err := ioutil.TempDir("", "zkserver")
	if err != nil {
		panic(err)
	}
	a, err = New(root)
	if err != nil {
		panic(err)
	}
}

func TestCreate(t *testing.T) {
	t.Logf("tmpdir: %v", a.root)
	pi := zkidentity.PublicIdentity{}
	err := a.Create(pi, false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeliver(t *testing.T) {
	to := zkidentity.PublicIdentity{}
	from := zkidentity.PublicIdentity{}
	from.Identity[0] = 1
	from.Identity[31] = 32

	// 0
	id, err := a.Deliver(to.Identity, from.Identity, []byte("payload0"))
	if err != nil {
		t.Fatal(err)
	}
	err = a.Delete(to.Identity, filepath.Base(id))
	if err != nil {
		t.Fatal(err)
	}

	// 1
	id, err = a.Deliver(to.Identity, from.Identity, []byte("payload1"))
	if err != nil {
		t.Fatal(err)
	}
	err = a.Delete(to.Identity, filepath.Base(id))
	if err != nil {
		t.Fatal(err)
	}

	// 1
	id, err = a.Deliver(to.Identity, from.Identity, []byte("payload2"))
	if err != nil {
		t.Fatal(err)
	}
	err = a.Delete(to.Identity, filepath.Base(id))
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteDoesntExist(t *testing.T) {
	to := zkidentity.PublicIdentity{}
	err := a.Delete(to.Identity, "moo")
	if err == nil {
		t.Fatal("file should have not existed")
	}
}

func TestNotify(t *testing.T) {
	to := zkidentity.PublicIdentity{}
	from := zkidentity.PublicIdentity{}
	from.Identity[0] = 1
	from.Identity[31] = 32

	c1 := make(chan *Notification, 1)
	err := a.Online(from.Identity, c1)
	if err != nil {
		t.Fatalf("from: %v", err)
	}

	c2 := make(chan *Notification, 1)
	err = a.Online(to.Identity, c2)
	if err != nil {
		t.Fatalf("to: %v", err)
	}

	wait := make(chan bool)
	go func() {
		c1r := false
		c2r := false
		for {
			select {
			case n := <-c1:
				t.Logf("c1: %x -> %x", n.From, n.To)
				c1r = true
			case n := <-c2:
				t.Logf("c2: %x -> %x", n.From, n.To)
				c2r = true
			}

			if c1r && c2r {
				wait <- true
				return
			}
		}
	}()

	// deliver message
	id, err := a.Deliver(to.Identity, from.Identity, []byte("payload0"))
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatalf("timeout")
	}

	// test offline
	a.Offline(from.Identity)
	a.Offline(to.Identity)

	err = a.Delete(to.Identity, filepath.Base(id))
	if err != nil {
		t.Fatal(err)
	}
}
