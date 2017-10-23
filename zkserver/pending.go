// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"path"
	"strconv"
	"time"

	"github.com/companyzero/zkc/inidb"
)

func (z *ZKS) prunePending(pending *inidb.INIDB) {
	r := pending.Records("")
	for k, v := range r {
		t, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			// token corrupt, remove from db and complain
			z.Error(idApp, "corrupt token %v", k)
			_ = pending.Del("", k)
			continue
		}
		ts := time.Unix(t, 0)
		if ts.Before(time.Now()) {
			// token expired, remove from db
			_ = pending.Del("", k)
			continue
		}
	}

	// save db back
	err := pending.Save()
	if err != nil {
		z.Error(idApp, "could not save pending db: %v", err)
	}
}

func (z *ZKS) validToken(token string, conn net.Conn) bool {
	// open db
	pending, err := inidb.New(path.Join(z.settings.Root, pendingPath),
		true, 10)
	if err != nil {
		z.Error(idApp, "could not open pending db: %v", err)
		return false
	}
	defer z.prunePending(pending) // kill all expired records

	// get token
	v, err := pending.Get("", token)
	if err != nil {
		z.Dbg(idApp, "%v invalid token %v", conn.RemoteAddr(), token)
		return false
	}

	// delete token
	err = pending.Del("", token)
	if err != nil {
		z.Error(idApp, "could not delete token %v", conn.RemoteAddr(),
			token)
		return false
	}

	// check expiration
	t, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		z.Error(idApp, "%v corrupt token %v", conn.RemoteAddr(), token)
		return false
	}
	ts := time.Unix(t, 0)
	if ts.Before(time.Now()) {
		z.Dbg(idApp, "%v token expired %v", conn.RemoteAddr(), token)
		return false
	}

	return true
}
