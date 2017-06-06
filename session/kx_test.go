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
)

var (
	alice    *zkidentity.FullIdentity
	bob      *zkidentity.FullIdentity
	aliceKX *KX
	bobKX   *KX
)

var mtx sync.Mutex

func log(id int, format string, args ...interface{}) {
	mtx.Lock()
	defer mtx.Unlock()
	t := time.Now().Format(time.UnixDate)
	fmt.Fprintf(os.Stderr, t+" "+format+"\n", args...)
}

func loadIdentities(t *testing.T) {
	f, err := os.Open("testdata/alice.blob")
	if err != nil {
		panic(err)
	}
	blob1 := new([3092]byte)
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
	blob2 := new([3088]byte)
	_, err = io.ReadFull(f, blob2[:])
	if err != nil {
		panic(err)
	}
	bob, err = zkidentity.UnmarshalFullIdentity(blob2[:])
	if err != nil {
		panic(err)
	}
}

func TestKX(t *testing.T) {
	loadIdentities(t)
	SetDiagnostic(log)

	Init()
	aliceKX := new(KX)
	aliceKX.MaxMessageSize = 4096
	aliceKX.OurPublicKey = &alice.Public.Key
	aliceKX.OurPrivateKey = &alice.PrivateKey
	aliceKX.TheirPublicKey = &bob.Public.Key
	t.Logf("alice fingerprint: %v", alice.Public.Fingerprint())

	bobKX :=  new(KX)
	bobKX.MaxMessageSize = 4096
	bobKX.OurPublicKey = &bob.Public.Key
	bobKX.OurPrivateKey = &bob.PrivateKey
	t.Logf("bob fingerprint: %v", bob.Public.Fingerprint())

	msg := []byte("this is a message of sorts")
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

		bobKX.Conn = conn
		err = bobKX.Respond()
		if err != nil {
			t.Fatal(err)
		}

		// read
		received, err := bobKX.Read()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(received, msg) {
			t.Fatalf("message not identical")
		}

		// write
		err = bobKX.Write(msg)
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
