// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package debug

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/companyzero/ttk"
)

var (
	ErrNoSubystems        = errors.New("no subsystems specified")
	ErrDuplicateSubsystem = errors.New("duplicate subsystem")
)

type Debug struct {
	sync.Mutex
	mask       uint64
	filename   string
	format     string
	subsystems map[int]string
	debug      bool // debug enabled?
	trace      bool // trace enabled?
}

func (d *Debug) Log(id int, format string, args ...interface{}) {
	s := ttk.Unescape(fmt.Sprintf(format, args...))
	d.log(id, "[LOG] ", s)
}

func (d *Debug) Info(id int, format string, args ...interface{}) {
	d.log(id, "[INF] ", format, args...)
}

func (d *Debug) Warn(id int, format string, args ...interface{}) {
	d.log(id, "[WAR] ", format, args...)
}

func (d *Debug) Error(id int, format string, args ...interface{}) {
	d.log(id, "[ERR] ", format, args...)
}

func (d *Debug) Critical(id int, format string, args ...interface{}) {
	d.log(id, "[CRI] ", format, args...)
}

func (d *Debug) Dbg(id int, format string, args ...interface{}) {
	// let it race!
	if !d.debug {
		return
	}

	d.log(id, "[DBG] ", format, args...)
}

func (d *Debug) T(id int, format string, args ...interface{}) {
	// let it race!
	if !d.trace {
		return
	}

	d.log(id, "[TRC] ", format, args...)
}

func (d *Debug) log(id int, prefix string, format string, args ...interface{}) {
	d.Lock()
	defer d.Unlock()

	s, found := d.subsystems[id]
	if !found {
		s = "[UNK]"
	}

	var err error
	f, err := os.OpenFile(d.filename, os.O_CREATE|os.O_RDWR|os.O_APPEND,
		0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log error: %v", err)
		return
	}
	defer f.Close()

	t := time.Now().Format(d.format)
	fmt.Fprintf(f, t+" "+s+prefix+format+"\n", args...)
}

func New(filename, format string) (*Debug, error) {
	// make sure we can open file
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()

	d := Debug{
		subsystems: make(map[int]string),
		format:     format,
		filename:   filename,
	}

	return &d, nil
}

func (d *Debug) Register(id int, name string) error {
	d.Lock()
	defer d.Unlock()

	_, found := d.subsystems[id]
	if found {
		return ErrDuplicateSubsystem
	}
	d.subsystems[id] = name
	return nil
}

func (d *Debug) EnableDebug() {
	d.Lock()
	defer d.Unlock()

	d.debug = true
}

func (d *Debug) DisableDebug() {
	d.Lock()
	defer d.Unlock()

	d.debug = false
}

func (d *Debug) EnableTrace() {
	d.Lock()
	defer d.Unlock()

	d.trace = true
}

func (d *Debug) DisableTrace() {
	d.Lock()
	defer d.Unlock()

	d.trace = false
}
