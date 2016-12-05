// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sigma

import (
	"bytes"
	"net"
	"sync"
	"testing"

	"github.com/companyzero/zkc/zkidentity"
)

var (
	alice    *zkidentity.FullIdentity
	bob      *zkidentity.FullIdentity
	aliceSKX *SigmaKX
	bobSKX   *SigmaKX
)

func init() {
	var err error
	alice, err = zkidentity.New("Alice The Malice", "alice")
	if err != nil {
		panic(err)
	}

	bob, err = zkidentity.New("Bob The Builder", "bob")
	if err != nil {
		panic(err)
	}
}

func TestKXAndTransport(t *testing.T) {
	msg := []byte("this is a message of sorts")

	aliceSKX = NewClient(&alice.Public.Identity, &alice.PrivateIdentity,
		&bob.Public.Identity, 1024)
	t.Logf("alice fingerprint: %v", alice.Public.Fingerprint())
	bobSKX = NewServer(&bob.Public.Identity,
		&bob.PrivateIdentity, 1024)
	t.Logf("bob fingerprint: %v", bob.Public.Fingerprint())

	wg := sync.WaitGroup{}
	wg.Add(2)
	wait := make(chan bool)
	go func() {
		defer wg.Done()
		listener, err := net.Listen("tcp", "127.0.0.1:12346")
		if err != nil {
			wait <- false
			t.Fatal(err)
		}
		wait <- true // start client

		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}

		err = bobSKX.Target(conn)
		if err != nil {
			t.Fatal(err)
		}

		// read
		received, err := bobSKX.Read()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(received, msg) {
			t.Fatalf("message not identical")
		}

		// write
		err = bobSKX.Write(msg)
		if err != nil {
			t.Fatal(err)
		}
	}()

	ok := <-wait
	if !ok {
		t.Fatalf("server not started")
	}

	conn, err := net.Dial("tcp", "127.0.0.1:12346")
	if err != nil {
		t.Fatal(err)
	}

	err = aliceSKX.Initiator(conn)
	if err != nil {
		t.Fatalf("initiator %v", err)
	}

	err = aliceSKX.Write(msg)
	if err != nil {
		t.Error(err)
		// fallthrough
	} else {

		// read
		received, err := aliceSKX.Read()
		if err != nil {
			t.Error(err)
			// fallthrough
		} else {
			if !bytes.Equal(received, msg) {
				t.Errorf("message not identical")
				// fallthrough
			}
		}
	}

	wg.Done()
	wg.Wait()
}
