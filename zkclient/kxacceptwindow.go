// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path"

	"github.com/companyzero/ttk"
	"github.com/companyzero/zkc/blobshare"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-xdr/xdr2"
	"github.com/nsf/termbox-go"
)

type kxAcceptWindow struct {
	zkc *ZKC // pointer to client context

	title  *ttk.Label
	status *ttk.Label

	passwordInput *ttk.Edit
	password      string

	// must be set prior to invocation
	rendezvousPullReply *rpc.RendezvousPullReply
}

var (
	_ ttk.Windower = (*kxAcceptWindow)(nil)
)

const (
	defaultKXStatus = "hit enter to accept, F10 to abort"
)

func (ka *kxAcceptWindow) Status(w *ttk.Window, bad bool, format string,
	args ...interface{}) {

	ttk.Queue(func() {
		if bad {
			ka.status.SetAttributes(ttk.Attributes{
				Fg: termbox.ColorBlack,
				Bg: termbox.ColorRed,
			})
		} else {
			ka.status.SetAttributes(ttk.Attributes{
				Fg: termbox.ColorYellow,
				Bg: termbox.ColorBlue,
			})
		}
		ka.status.SetText(format, args...)
		ka.status.Render()
		ttk.Flush()
	})
}

func (ka *kxAcceptWindow) Render(w *ttk.Window) {
	ka.password = ""
}

func (ka *kxAcceptWindow) Init(w *ttk.Window) {
	// anchor
	ax := 2
	ay := 2

	// currently at
	y := 0

	ka.title = w.AddStatus(0, ttk.JustifyCenter, "Key Exchange Decrypt")
	ka.title.SetAttributes(ttk.Attributes{
		Fg: termbox.ColorYellow,
		Bg: termbox.ColorBlue,
	})

	ka.status = w.AddStatus(-2, ttk.JustifyLeft, defaultKXStatus)
	ka.status.SetAttributes(ttk.Attributes{
		Fg: termbox.ColorYellow,
		Bg: termbox.ColorBlue,
	})

	w.AddLabel(ax, ay+y, "Enter the shared password in order to finalize the key exchange")
	y++
	w.AddLabel(ax, ay+y, "Password is readable during typing!")
	y++
	w.AddLabel(ax, ay+y, "Press F10 to return to main window.")
	y++

	y++
	w.AddLabel(ax, ay+y, "Password")
	ka.passwordInput = w.AddEdit(ax+10, ay+y, -2, &ka.password)
	y++
}

func (ka *kxAcceptWindow) KeyHandler(w *ttk.Window, k ttk.Key) {
	switch k.Key {
	case termbox.KeyArrowUp:
		w.FocusPrevious()
	case termbox.KeyArrowDown:
		w.FocusNext()
	case termbox.KeyEnter:
		if ka.passwordInput != k.Widget {
			w.FocusNext()
			return
		}

		// decrypt public identity
		ka.Status(w, false, "decrypting public identity")

		blobshare.SetNrp(32768, 16, 2)
		saltR, nonceR, dataR, err := blobshare.UnpackSaltNonce(ka.rendezvousPullReply.Blob)
		if err != nil {
			ka.Status(w, true, "Could not unpack: %v", err)
			return
		}

		dk, err := blobshare.DeriveKey([]byte(ka.password), saltR)
		if err != nil {
			ka.Status(w, true, "Could not derive key: %v", err)
			return
		}

		decrypted, err := blobshare.Decrypt(dk, nonceR, dataR)
		if err != nil {
			ka.Status(w, true, "Could not decrypt blob: %v", err)
			return
		}

		// unmarshal into public identity
		var identity zkidentity.PublicIdentity
		br := bytes.NewReader(decrypted)
		_, err = xdr.Unmarshal(br, &identity)
		if err != nil {
			ka.Status(w, true, "Could not unmarshal public "+
				"identity")
			return
		}

		// make sure we don't add ourselves
		if bytes.Equal(ka.zkc.id.Public.Identity[:], identity.Identity[:]) {
			ka.Status(w, true, "can't add self to address book")
			return
		}

		// see if identity exists
		newIdentity := true
		if ka.zkc.identityExists(identity.Identity) {
			// under ratchet reset conditions there are no files
			ids := hex.EncodeToString(identity.Identity[:])
			fullPath := path.Join(ka.zkc.settings.Root, inboundDir, ids)
			_, err1 := os.Stat(path.Join(fullPath, ratchetFilename))
			_, err2 := os.Stat(path.Join(fullPath, halfRatchetFilename))
			if !(err1 == nil || err2 == nil) {
				// make sure keys are the same
				ka.zkc.PrintfT(-1, "pretend keys are the same")
				newIdentity = false // skip saving identity
			} else {
				// complain
				ka.Status(w, true, "identity already exists")
				return
			}
		}

		// accept fingerprint
		acfpw := &acceptCFPWindow{
			zkc:         ka.zkc,
			pid:         &identity,
			dk:          dk,
			newIdentity: newIdentity,
		}
		ka.zkc.ttkACFPW = ttk.NewWindow(acfpw)
		ttk.Focus(ka.zkc.ttkACFPW)

	case termbox.KeyF10:
		// clear password edit for next call
		ttk.Queue(func() {
			ka.password = ""
			ka.passwordInput.SetText(&ka.password, true)
		})

		// reset status
		ka.Status(w, false, defaultKXStatus)

		// focus on main window, reply will show on console
		ttk.Focus(ka.zkc.ttkMW)
	}
}
