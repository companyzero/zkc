// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mitchellh/go-homedir"
)

type completion struct {
	all      []string
	at       int
	previous int
	mode     int // user settable for context purposes
}

const (
	modeNick = iota
	modeFile
)

func (c *completion) Next(s string) string {
	if len(c.all) == 0 {
		c.at = 0
		return s
	}
	if s == "" {
		c.at = 0
		c.previous = 0
		return c.all[0]
	}
	if c.at == c.previous && c.all[c.at] == s {
		// next
		if c.at+1 < len(c.all) {
			c.at++
			c.previous = c.at
			return c.all[c.at]
		}
		c.at = 0
		c.previous = 0
		return c.all[c.at]
	}
	for i, v := range c.all {
		// complete partial
		if strings.HasPrefix(v, s) {
			c.at = i
			c.previous = i
			return v
		}
	}

	c.at = 0
	c.previous = -1
	return s
}

func (z *ZKC) completeNick(at string) string {
	if z.cctx == nil || z.cctx.mode != modeNick {
		// setup completion array
		a := z.ab.All()
		c := &completion{
			all:      make([]string, 0, len(a)),
			mode:     modeNick,
			previous: -1,
		}
		for _, v := range a {
			c.all = append(c.all, v.Nick)
		}
		sort.Strings(c.all)

		z.cctx = c
	}

	return z.cctx.Next(at)
}

func (z *ZKC) completeNickCommandLine(args []string) {
	var c string
	switch len(args) {
	case 1:
		c = ""
		return
	case 2:
		c = args[1]
	default:
		return
	}
	// complete nick
	nick := z.completeNick(c)
	//mw.zkc.PrintfT(0, "Nick: %v", nick)
	cmd := args[0] + " " + nick
	z.mw.setCmd(cmd) // XXX not called from queue context!
}

func (z *ZKC) completeDir(at string) string {
	if z.cctx == nil || z.cctx.mode != modeFile {
		// setup completion array
		ef, err := homedir.Expand(at)
		if err != nil {
			z.cctx = nil
			return ""
		}
		at = ef

		// TODO: check err
		files, _ := filepath.Glob(ef + string(os.PathSeparator) + "*")
		sort.Strings(files)

		c := &completion{
			all:      files,
			mode:     modeFile,
			previous: -1,
		}
		z.cctx = c
	}

	return z.cctx.Next(at)
}

func (z *ZKC) completeDirCommandLine(args []string) {
	if len(args) != 3 {
		return
	}
	if strings.HasSuffix(args[2], string(os.PathSeparator)) ||
		args[2] == "~" {
		z.cctx = nil
	}

	// complete dir/file
	fsname := z.completeDir(args[2])
	//mw.zkc.PrintfT(0, "Nick: %v", fsname)
	cmd := args[0] + " " + args[1] + " " + fsname
	z.mw.setCmd(cmd) // XXX not called from queue context!
}
