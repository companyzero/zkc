// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package account

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-spew/spew"
	"github.com/davecgh/go-xdr/xdr2"
)

func newAccount(t *testing.T) (*Account, error) {
	root, err := ioutil.TempDir("", "zkserver")
	if err != nil {
		return nil, err
	}
	t.Logf("tmpdir: %v", root)
	return New(root)
}

func TestUpgradeDiskMessage(t *testing.T) {
	// this test verifies that upgrading a disk message works as expected.
	type diskMessageOld struct {
		From     [zkidentity.IdentitySize]byte
		Received int64
		Payload  []byte
		// New diskMessage has a boolean here
	}
	var from [zkidentity.IdentitySize]byte
	copy(from[:], []byte("from"))
	dmo := diskMessageOld{
		From:     from,
		Received: time.Now().Unix(),
		Payload:  []byte("payload"),
	}
	var b bytes.Buffer
	_, err := xdr.Marshal(&b, dmo)
	if err != nil {
		t.Fatal(err)
	}

	var dm diskMessage
	br := bytes.NewReader(b.Bytes())
	_, err = xdr.Unmarshal(br, &dm)
	if uerr, ok := err.(*xdr.UnmarshalError); err != nil && (!ok ||
		uerr.ErrorCode != xdr.ErrIO || uerr.Err != io.EOF) {
		t.Fatal(err)
	}
	if dmo.From != dm.From || dmo.Received != dm.Received ||
		!bytes.Equal(dmo.Payload, dm.Payload) || dm.Cleartext {
		t.Fatalf("corrupt during upgrade: want %v, got %v",
			spew.Sdump(dmo), spew.Sdump(dm))
	}

	// Make sure we don't trip on nil
	err = nil
	if uerr, ok := err.(*xdr.UnmarshalError); err != nil && (!ok ||
		uerr.ErrorCode != xdr.ErrIO || uerr.Err != io.EOF) {
		t.Fatalf("Expected nil")
	}

	// Make sure we fail with extra data
	_, err = b.Write([]byte{0xff})
	if err != nil {
		t.Fatal(err)
	}
	br = bytes.NewReader(b.Bytes())
	_, err = xdr.Unmarshal(br, &dm)
	if uerr, ok := err.(*xdr.UnmarshalError); err != nil && (!ok ||
		uerr.ErrorCode != xdr.ErrIO || uerr.Err != io.EOF) {
		t.Log("Got the correct error")
	} else {
		t.Fatal(err)
	}
}

func TestCreate(t *testing.T) {
	a, err := newAccount(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(a.root)

	pi := zkidentity.PublicIdentity{}
	err = a.Create(pi, false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeliver(t *testing.T) {
	a, err := newAccount(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(a.root)

	to := zkidentity.PublicIdentity{}
	from := zkidentity.PublicIdentity{}
	from.Identity[0] = 1
	from.Identity[31] = 32

	err = a.Create(to, false)
	if err != nil {
		t.Fatal(err)
	}
	err = a.Create(from, false)
	if err != nil {
		t.Fatal(err)
	}

	// 0
	id, err := a.Deliver(to.Identity, from.Identity, []byte("payload0"),
		false)
	if err != nil {
		t.Fatal(err)
	}
	err = a.Delete(to.Identity, filepath.Base(id))
	if err != nil {
		t.Fatal(err)
	}

	// 1
	id, err = a.Deliver(to.Identity, from.Identity, []byte("payload1"),
		false)
	if err != nil {
		t.Fatal(err)
	}
	err = a.Delete(to.Identity, filepath.Base(id))
	if err != nil {
		t.Fatal(err)
	}

	// 1
	id, err = a.Deliver(to.Identity, from.Identity, []byte("payload2"),
		false)
	if err != nil {
		t.Fatal(err)
	}
	err = a.Delete(to.Identity, filepath.Base(id))
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteDoesntExist(t *testing.T) {
	a, err := newAccount(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(a.root)

	to := zkidentity.PublicIdentity{}
	err = a.Delete(to.Identity, "moo")
	if err == nil {
		t.Fatal("file should have not existed")
	}
}

//func TestNotify(t *testing.T) {
//	a, err := newAccount(t)
//	if err != nil {
//		t.Fatal(err)
//	}
//	defer os.RemoveAll(a.root)
//
//	to := zkidentity.PublicIdentity{}
//	from := zkidentity.PublicIdentity{}
//	from.Identity[0] = 1
//	from.Identity[31] = 32
//
//	err = a.Create(to, false)
//	if err != nil {
//		t.Fatal(err)
//	}
//	err = a.Create(from, false)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	c1 := make(chan *Notification, 1)
//	c2 := make(chan *Notification, 1)
//
//	var wg sync.WaitGroup
//	wg.Add(2)
//	go func() {
//		c1r := false
//		c2r := false
//		for {
//			select {
//			case n, ok := <-c1:
//				if !ok {
//					return
//				}
//				c1r = true
//				t.Logf("c1: %x -> %x", n.From, n.To)
//				wg.Add(-1)
//			case n, ok := <-c2:
//				if !ok {
//					return
//				}
//				c2r = true
//				t.Logf("c2: %x -> %x", n.From, n.To)
//				wg.Add(-1)
//			}
//			if c1r && c2r {
//				return
//			}
//		}
//	}()
//
//	err = a.Online(from.Identity, c1)
//	if err != nil {
//		t.Fatalf("from: %v", err)
//	}
//
//	err = a.Online(to.Identity, c2)
//	if err != nil {
//		t.Fatalf("to: %v", err)
//	}
//
//	// deliver message
//	id, err := a.Deliver(to.Identity, from.Identity, []byte("payload0"), false)
//	if err != nil {
//		t.Fatal(err)
//	}
//	id2, err := a.Deliver(from.Identity, to.Identity, []byte("payload1"), false)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	wg.Wait()
//
//	// test offline
//	a.Offline(from.Identity)
//	a.Offline(to.Identity)
//
//	err = a.Delete(to.Identity, filepath.Base(id))
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	err = a.Delete(from.Identity, filepath.Base(id2))
//	if err != nil {
//		t.Fatal(err)
//	}
//}
