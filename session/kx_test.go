// Copyright (c) 2016,2017 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/companyzero/zkc/zkidentity"
	"golang.org/x/sync/errgroup"
)

var mtx sync.Mutex

func log(id int, format string, args ...interface{}) {
	mtx.Lock()
	defer mtx.Unlock()
	t := time.Now().Format(time.UnixDate)
	fmt.Fprintf(os.Stderr, t+" "+format+"\n", args...)
}

func loadIdentities(t *testing.T) (alice, bob *zkidentity.FullIdentity) {
	f, err := os.Open("testdata/alice.blob")
	if err != nil {
		panic(err)
	}
	blob1 := new([3076]byte)
	_, err = io.ReadFull(f, blob1[:])
	if err != nil {
		panic(err)
	}
	alice, err = zkidentity.UnmarshalFullIdentity(blob1[:])
	if err != nil {
		panic(err)
	}

	f, err = os.Open("testdata/bob.blob")
	if err != nil {
		panic(err)
	}
	blob2 := new([3072]byte)
	_, err = io.ReadFull(f, blob2[:])
	if err != nil {
		panic(err)
	}
	bob, err = zkidentity.UnmarshalFullIdentity(blob2[:])
	if err != nil {
		panic(err)
	}
	return alice, bob
}

func newIdentities(t *testing.T) (alice, bob *zkidentity.FullIdentity) {
	alice, err := zkidentity.New("Alice The Malice", "alice")
	if err != nil {
		panic(err)
	}
	bob, err = zkidentity.New("Bob The Builder", "bob")
	if err != nil {
		panic(err)
	}
	return alice, bob
}

func testKX(t *testing.T, alice, bob *zkidentity.FullIdentity) {
	loadIdentities(t)
	SetDiagnostic(log)

	Init()
	aliceKX := new(KX)
	aliceKX.MaxMessageSize = 4096
	aliceKX.OurPublicKey = &alice.Public.Key
	aliceKX.OurPrivateKey = &alice.PrivateKey
	aliceKX.TheirPublicKey = &bob.Public.Key
	t.Logf("alice fingerprint: %v", alice.Public.Fingerprint())

	bobKX := new(KX)
	bobKX.MaxMessageSize = 4096
	bobKX.OurPublicKey = &bob.Public.Key
	bobKX.OurPrivateKey = &bob.PrivateKey
	t.Logf("bob fingerprint: %v", bob.Public.Fingerprint())

	msg := []byte("this is a message of sorts")
	eg := errgroup.Group{}
	wait := make(chan bool)
	eg.Go(func() error {
		listener, err := net.Listen("tcp", "127.0.0.1:12346")
		if err != nil {
			wait <- false
			return err
		}
		defer listener.Close()
		wait <- true // start client

		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()

		bobKX.Conn = conn
		err = bobKX.Respond()
		if err != nil {
			return err
		}

		// read
		received, err := bobKX.Read()
		if err != nil {
			return err
		}
		if !bytes.Equal(received, msg) {
			return fmt.Errorf("message not identical")
		}

		// write
		return bobKX.Write(msg)
	})

	ok := <-wait
	if !ok {
		t.Fatalf("server not started")
	}

	conn, err := net.Dial("tcp", "127.0.0.1:12346")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	aliceKX.Conn = conn
	err = aliceKX.Initiate()
	if err != nil {
		t.Fatalf("initiator %v", err)
	}

	err = aliceKX.Write(msg)
	if err != nil {
		t.Error(err)
		// fallthrough
	} else {

		// read
		received, err := aliceKX.Read()
		if err != nil {
			t.Error(err)
			// fallthrough
		} else if !bytes.Equal(received, msg) {
			t.Errorf("message not identical")
			// fallthrough
		}
	}

	if err := eg.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestStaticIdentities(t *testing.T) {
	alice, bob := loadIdentities(t)
	testKX(t, alice, bob)
}

func TestRandomIdentities(t *testing.T) {
	alice, bob := newIdentities(t)
	testKX(t, alice, bob)
}
