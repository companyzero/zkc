// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/companyzero/ttk"
	"github.com/companyzero/zkc/tools"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/nsf/termbox-go"
)

type acceptWindow struct {
	zkc *ZKC // pointer to client context

	// widgets
	questionInput *ttk.Edit
	question      string
	title         *ttk.Label
	status        *ttk.Label

	// parameters
	host  string
	conn  net.Conn
	cs    *tls.ConnectionState
	pid   *zkidentity.PublicIdentity
	token string
}

var (
	_       ttk.Windower = (*acceptWindow)(nil)
	acceptW *ttk.Window
)

func (aw *acceptWindow) Status(w *ttk.Window, bad bool, format string,
	args ...interface{}) {

	ttk.Queue(func() {
		if bad {
			aw.status.SetAttributes(ttk.Attributes{
				Fg: termbox.ColorBlack,
				Bg: termbox.ColorRed,
			})
		} else {
			aw.status.SetAttributes(ttk.Attributes{
				Fg: termbox.ColorYellow,
				Bg: termbox.ColorBlue,
			})
		}
		aw.status.SetText(format, args...)
		aw.status.Render()
		ttk.Flush()
	})
}

func (aw *acceptWindow) Render(w *ttk.Window) {
	// do nothing for now
}

func (aw *acceptWindow) Init(w *ttk.Window) {
	// anchor
	ax := 2
	ay := 2

	// currently at
	y := 0

	aw.title = w.AddStatus(0, ttk.JustifyCenter, "Accept server identity?")
	aw.title.SetAttributes(ttk.Attributes{
		Fg: termbox.ColorYellow,
		Bg: termbox.ColorBlue,
	})

	aw.status = w.AddStatus(-2, ttk.JustifyLeft,
		"Type yes to accept server identity")
	aw.status.SetAttributes(ttk.Attributes{
		Fg: termbox.ColorYellow,
		Bg: termbox.ColorBlue,
	})

	w.AddLabel(ax, ay+y, "The authenticity of host %v (%v) can't be "+
		"established.", aw.host, aw.conn.RemoteAddr())
	y += 2
	w.AddLabel(ax, ay+y, "Server name: %v", aw.pid.Name)
	y++
	cert := aw.cs.PeerCertificates[0].Raw
	w.AddLabel(ax, ay+y, "Outer server fingerprint: %v",
		tools.Fingerprint(cert))
	y++
	w.AddLabel(ax, ay+y, "Inner server fingerprint: %v",
		aw.pid.Fingerprint())
	y++

	y++
	s := fmt.Sprintf("Are you sure you want to continue connecting (yes/no)?")
	w.AddLabel(ax, ay+y, s)
	aw.questionInput = w.AddEdit(ax+len(s)+1, ay+y, -2, &aw.question)
}

func (aw *acceptWindow) KeyHandler(w *ttk.Window, k ttk.Key) {
	switch k.Key {
	case termbox.KeyEnter:
		if strings.ToLower(aw.question) != "yes" {
			ttk.Focus(aw.zkc.ttkWW)
			aw.zkc.focus(0)
			return
		}

		err := aw.zkc.finalizeAccountCreation(aw.conn, aw.cs, aw.pid,
			aw.token)
		if err != nil {
			aw.Status(w, true, fmt.Sprintf("%v", err))
			return
		}
	}
}
