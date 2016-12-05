// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// tagstack is a package that manages concurrent safe tag stacks.  A caller
// uses the provided Push and Pop functions to push uint32 values onto/from the
// stack.  It is the callers responsibility ensure uniqueness of the tags if
// this is desired.
//
// tagstack deliberately uses uint32 instead of interface{} for performance
// reasons.
package tagstack

import (
	"errors"
	"sync"
)

var (
	ErrOverflow  = errors.New("overflow")
	ErrUnderflow = errors.New("underflow")
)

// TagStack is an opaque type that contains the tag stack.
type TagStack struct {
	sync.Mutex

	at    int
	stack []uint32

	blocking bool
	stackC   chan uint32
}

// NewBlocking returns a pointer to a TagStack structure.
func NewBlocking(depth int) *TagStack {
	s := TagStack{
		stackC:   make(chan uint32, depth),
		blocking: true,
	}

	for i := 0; i < depth; i++ {
		s.stackC <- uint32(i)
	}

	return &s
}

// New returns a pointer to a TagStack structure.
func New(depth int) *TagStack {
	s := TagStack{
		stack: make([]uint32, depth),
	}

	for k := range s.stack {
		s.stack[k] = uint32(k)
	}
	s.at = depth

	return &s
}

// Push appends x to then end of the stack.  If the stack will overflow it will
// return an error.
func (s *TagStack) Push(x uint32) error {
	if s.blocking {
		s.stackC <- x
		return nil
	}

	s.Lock()
	defer s.Unlock()

	if s.at < len(s.stack) {
		s.stack[s.at] = x
		s.at++
		return nil
	}

	return ErrOverflow
}

// Pop returns the current tag on the stack.  If the stack will underflow it
// will return an error.
func (s *TagStack) Pop() (uint32, error) {
	if s.blocking {
		tag := <-s.stackC
		return tag, nil
	}

	s.Lock()
	defer s.Unlock()

	if s.at > 0 {
		s.at--
		return s.stack[s.at], nil
	}

	return 0, ErrUnderflow
}

// Depth returns the tag stack depth.
func (s *TagStack) Depth() int {
	if s.blocking {
		return len(s.stackC)
	}

	return len(s.stack)
}
