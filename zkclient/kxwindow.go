// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"

	"github.com/companyzero/ttk"
	"github.com/companyzero/zkc/blobshare"
	"github.com/davecgh/go-xdr/xdr2"
	"github.com/nsf/termbox-go"
)

type kxWindow struct {
	zkc *ZKC // pointer to client context

	title  *ttk.Label
	status *ttk.Label

	passwordInput *ttk.Edit
	password      string
}

var (
	_ ttk.Windower = (*kxWindow)(nil)
)

func (kw *kxWindow) Status(w *ttk.Window, bad bool, format string,
	args ...interface{}) {

	ttk.Queue(func() {
		if bad {
			kw.status.SetAttributes(ttk.Attributes{
				Fg: termbox.ColorBlack,
				Bg: termbox.ColorRed,
			})
		} else {
			kw.status.SetAttributes(ttk.Attributes{
				Fg: termbox.ColorYellow,
				Bg: termbox.ColorBlue,
			})
		}
		kw.status.SetText(format, args...)
		kw.status.Render()
		ttk.Flush()
	})
}
func (kw *kxWindow) Render(w *ttk.Window) {
	// do nothing for now
}

func (kw *kxWindow) Init(w *ttk.Window) {
	// anchor
	ax := 2
	ay := 2

	// currently at
	y := 0

	kw.title = w.AddStatus(0, ttk.JustifyCenter, "Key Exchange")
	kw.title.SetAttributes(ttk.Attributes{
		Fg: termbox.ColorYellow,
		Bg: termbox.ColorBlue,
	})

	kw.status = w.AddStatus(-2, ttk.JustifyLeft, defaultKXStatus)
	kw.status.SetAttributes(ttk.Attributes{
		Fg: termbox.ColorYellow,
		Bg: termbox.ColorBlue,
	})

	w.AddLabel(ax, ay+y, "In order to exchange keys you must send a special message to the other party.")
	y++
	w.AddLabel(ax, ay+y, "This message contains your public identity and is encrypted using a password derived key.")
	y++
	w.AddLabel(ax, ay+y, "After uploading the message the server will provide you with a PIN.")
	y++
	w.AddLabel(ax, ay+y, "The PIN and password is provided to your counter party.")
	y++
	w.AddLabel(ax, ay+y, "The PIN is used to identify the identity blob and the password is used to decrypt it.")
	y++
	w.AddLabel(ax, ay+y, "Password is readable during typing!")
	y++
	w.AddLabel(ax, ay+y, "Press F10 to return to main window.")
	y++

	y++
	w.AddLabel(ax, ay+y, "Password")
	kw.passwordInput = w.AddEdit(ax+10, ay+y, -2, &kw.password)
}

func (kw *kxWindow) KeyHandler(w *ttk.Window, k ttk.Key) {
	switch k.Key {
	case termbox.KeyArrowUp:
		w.FocusPrevious()
	case termbox.KeyArrowDown:
		w.FocusNext()
	case termbox.KeyEnter:
		if kw.passwordInput != k.Widget {
			w.FocusNext()
			return
		}

		var myid bytes.Buffer
		_, err := xdr.Marshal(&myid, kw.zkc.id.Public)
		if err != nil {
			kw.Status(w, true, "Could not marshal identity")
			return
		}

		// encrypt public identity
		kw.Status(w, false, "encrypting public identity")

		blobshare.SetNrp(32768, 16, 2)
		key, salt, err := blobshare.NewKey([]byte(kw.password))
		if err != nil {
			kw.Status(w, true, "Could not create key: %v ", err)
			return
		}

		encrypted, nonce, err := blobshare.Encrypt(myid.Bytes(), key)
		if err != nil {
			kw.Status(w, true, "Could not encrypt: %v ", err)
			return
		}

		packed := blobshare.PackSaltNonce(salt, nonce, encrypted)

		// send to server
		kw.Status(w, false, "contacting server")
		err = kw.zkc.rendezvous(packed)
		if err != nil {
			kw.Status(w, true, "Could not send key exchange: %v",
				err)
			return
		}

		// save key
		err = kw.zkc.saveKey(key)
		if err != nil {
			kw.Status(w, true, "Could not save key: %v", err)
			return
		}

		kw.zkc.Dbg(idZKC, "step 1 (initiate) idkx")

		fallthrough
	case termbox.KeyF10:
		// clear password edit for next call
		ttk.Queue(func() {
			kw.password = ""
			kw.passwordInput.SetText(&kw.password, true)
		})

		// reset status
		kw.Status(w, false, defaultKXStatus)

		// focus on main window, reply will show on console
		ttk.Focus(kw.zkc.ttkMW)
	}
}
