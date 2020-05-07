// Copyright (c) 2016-2020 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tagstack

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

var size = 10

func TestUnderflow(t *testing.T) {
	ts := New(size)

	t.Logf("at %v ts %#v", ts.at, ts.stack)
	// note <= to induce failure
	for i := 0; i <= size; i++ {
		x, err := ts.Pop()
		if i == size && errors.Is(err, ErrUnderflow) {
			return
		}
		t.Logf("x %v", x)
	}
	t.Fatalf("underflow")
}

func TestOverflow(t *testing.T) {
	ts := New(size)
	err := ts.Push(uint32(size))
	if !errors.Is(err, ErrOverflow) {
		t.Fatalf("expected overflow")
	}
}

func TestPushPop(t *testing.T) {
	ts := New(size)

	t.Logf("at %v ts %#v", ts.at, ts.stack)
	for i := 0; i < size; i++ {
		_, err := ts.Pop()
		if err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < size; i++ {
		// reverse order
		err := ts.Push(uint32(size - 1 - i))
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("at %v ts %#v", ts.at, ts.stack)

	for i := 0; i < size; i++ {
		x, err := ts.Pop()
		if err != nil {
			t.Fatal(err)
		}
		if x != uint32(i) {
			t.Fatalf("unexpected tag got %v want %v",
				x, i)
		}
	}
}

func TestRace(t *testing.T) {
	testSize := 4000 // pretty much max go routines
	ts := New(testSize)

	c := make(chan uint32, testSize)
	e := make(chan error, 1)
	for i := 0; i < testSize; i++ {
		go func() {
			x, err := ts.Pop()
			if err != nil {
				err = fmt.Errorf("TestRace: ts.Pop failed: %v", err)
				e <- err
				return
			}
			go func(xx uint32) {
				r := rand.New(rand.NewSource(time.Now().UnixNano()))
				wait := r.Intn(2000)
				time.Sleep(time.Duration(wait) * time.Nanosecond)
				err := ts.Push(xx)
				if err != nil {
					err = fmt.Errorf("TestRace: ts.Push failed: %v", err)
					e <- err
					return
				}
				c <- xx
			}(x)
		}()
	}

	count := 0
	for {
		select {
		case err := <-e:
			t.Fatal(err)
		case <-c:
		}
		count++
		if count == testSize {
			break
		}
	}

	seen := make([]int, testSize)
	for i := 0; i < testSize; i++ {
		tag := ts.stack[i]
		seen[tag]++
	}

	for i := 0; i < testSize; i++ {
		if seen[i] != 1 {
			t.Errorf("corrupt tag %v seen %v", i, seen[i])
		}
	}
}
