// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strings"

	"github.com/companyzero/ttk"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-xdr/xdr2"
	"github.com/nsf/termbox-go"
)

var (
	defaultStatus = "hit enter on Token field to create account"
)

type welcomeWindow struct {
	zkc *ZKC // pointer to client context

	// widgets
	nameInput   *ttk.Edit
	name        string
	nickInput   *ttk.Edit
	nick        string
	serverInput *ttk.Edit
	server      string
	tokenInput  *ttk.Edit
	token       string
	title       *ttk.Label
	status      *ttk.Label
}

var (
	_ ttk.Windower = (*welcomeWindow)(nil)
)

func (ww *welcomeWindow) Status(w *ttk.Window, bad bool, format string,
	args ...interface{}) {

	ttk.Queue(func() {
		if bad {
			ww.status.SetAttributes(ttk.Attributes{
				Fg: termbox.ColorBlack,
				Bg: termbox.ColorRed,
			})
		} else {
			ww.status.SetAttributes(ttk.Attributes{
				Fg: termbox.ColorYellow,
				Bg: termbox.ColorBlue,
			})
		}
		ww.status.SetText(format, args...)
		ww.status.Render()
		ttk.Flush()
	})
}

func (ww *welcomeWindow) Render(w *ttk.Window) {
	// do nothing for now
}

func (ww *welcomeWindow) Init(w *ttk.Window) {
	// anchor
	ax := 2
	ay := 2

	// currently at
	y := 0

	ww.title = w.AddStatus(0, ttk.JustifyCenter,
		"Welcome to Zero Knowledge Communications!")
	ww.title.SetAttributes(ttk.Attributes{
		Fg: termbox.ColorYellow,
		Bg: termbox.ColorBlue,
	})

	ww.status = w.AddStatus(-2, ttk.JustifyLeft, defaultStatus)
	ww.status.SetAttributes(ttk.Attributes{
		Fg: termbox.ColorYellow,
		Bg: termbox.ColorBlue,
	})

	w.AddLabel(ax, ay+y, "zkc detected that this is the first time "+
		"it is run.")
	y += 2
	w.AddLabel(ax, ay+y, "You must create an account on a remote server.")
	y++

	y++
	w.AddLabel(ax, ay+y, "Name:")
	ww.nameInput = w.AddEdit(ax+10, ay+y, -2, &ww.name)
	y++
	w.AddLabel(ax, ay+y, "Nick:")
	ww.nickInput = w.AddEdit(ax+10, ay+y, -2, &ww.nick)
	y++

	w.AddLabel(ax, ay+y, "Server:")
	ww.server = "127.0.0.1:12345" // XXX use proper default
	ww.serverInput = w.AddEdit(ax+10, ay+y, -2, &ww.server)
	y++
	w.AddLabel(ax, ay+y, "Token:")
	ww.tokenInput = w.AddEdit(ax+10, ay+y, -2, &ww.token)
	y++

	y++
	w.AddLabel(ax, ay+y, "Name is your actual name or alias and it is known to the server.")
	y++
	w.AddLabel(ax, ay+y, "Nick is your prefered short name, e.g. jd for John Doe")
	y++
	w.AddLabel(ax, ay+y, "Server must contain a full URL to a server.")

	y++
	w.AddLabel(ax, ay+y, "Token is provided by the server administrator, if necessary.")
}

func (ww *welcomeWindow) KeyHandler(w *ttk.Window, k ttk.Key) {
	switch k.Key {
	case termbox.KeyArrowUp:
		k.Widget.KeyHandler(termbox.Event{Key: termbox.KeyEnter})
		w.FocusPrevious()
	case termbox.KeyArrowDown:
		// simulate key enter to save off text from entry
		k.Widget.KeyHandler(termbox.Event{Key: termbox.KeyEnter})
		w.FocusNext()
	case termbox.KeyEnter:
		// wait for action
		if ww.tokenInput != k.Widget {
			w.FocusNext()
			return
		}

		// save off entries
		ww.zkc.id.Public.Name = ww.name
		ww.zkc.id.Public.Nick = ww.nick
		ww.zkc.serverAddress = ww.server
		if ww.zkc.id.Public.Name == "" || ww.zkc.id.Public.Nick == "" ||
			ww.zkc.serverAddress == "" {
			ww.Status(w, true, "Name, Nick and Server are "+
				"required fields")
			return
		}

		// dial remote
		ww.Status(w, false, "Dialing %v", ww.server)
		conn, cs, err := ww.zkc.preSessionPhase()
		if err != nil {
			ww.Status(w, true, "Could not dial %v: %v",
				ww.server, err)
			return
		}

		var pid zkidentity.PublicIdentity

		if ww.zkc.serverIdentity == nil {
			// awful hack to get fingerprint

			// tell remote we want its public identity
			_, err = xdr.Marshal(conn, rpc.InitialCmdIdentify)
			if err != nil {
				ww.Status(w, true,
					"Connection closed during identify")
				return
			}

			// get server identity
			_, err = xdr.Unmarshal(conn, &pid)
			if err != nil {
				ww.Status(w, true,
					"Could not obtain remote identity")
				return
			}

			ww.Status(w, false, "Connected to: %v %v", pid.Name,
				pid.Fingerprint())

			aw := &acceptWindow{
				zkc:   ww.zkc,
				host:  ww.server,
				conn:  conn,
				cs:    cs,
				pid:   &pid,
				token: strings.Replace(ww.token, " ", "", -1),
			}
			ww.zkc.ttkAW = ttk.NewWindow(aw)
			ttk.Focus(ww.zkc.ttkAW)
		} else {
			pid = *ww.zkc.serverIdentity
			ww.Status(w, false, "Connected to: %v %v", pid.Name,
				pid.Fingerprint())
			err := ww.zkc.finalizeAccountCreation(conn, cs, &pid,
				strings.Replace(ww.token, " ", "", -1))
			if err != nil {
				ww.Status(w, true, fmt.Sprintf("%v", err))
			}
		}
	}
}
