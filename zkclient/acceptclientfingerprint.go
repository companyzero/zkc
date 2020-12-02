// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"strings"

	"github.com/companyzero/ttk"
	"github.com/companyzero/zkc/blobshare"
	"github.com/companyzero/zkc/ratchet"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/nsf/termbox-go"
)

type acceptCFPWindow struct {
	zkc *ZKC // pointer to client context

	// widgets
	questionInput *ttk.Edit
	question      string
	title         *ttk.Label
	status        *ttk.Label

	// parameters
	pid         *zkidentity.PublicIdentity // fetched Public Identity
	dk          *[32]byte                  // blob derived key
	newIdentity bool                       // save identity if true
}

var (
	_ ttk.Windower = (*acceptCFPWindow)(nil)
)

func (aw *acceptCFPWindow) Status(w *ttk.Window, bad bool, format string,
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

func (aw *acceptCFPWindow) Render(w *ttk.Window) {
	// do nothing for now
}

func (aw *acceptCFPWindow) Init(w *ttk.Window) {
	// anchor
	ax := 2
	ay := 2

	// currently at
	y := 0

	aw.title = w.AddStatus(0, ttk.JustifyCenter, "Accept client identity?")
	aw.title.SetAttributes(ttk.Attributes{
		Fg: termbox.ColorYellow,
		Bg: termbox.ColorBlue,
	})

	aw.status = w.AddStatus(-2, ttk.JustifyLeft,
		"Type yes to accept client identity")
	aw.status.SetAttributes(ttk.Attributes{
		Fg: termbox.ColorYellow,
		Bg: termbox.ColorBlue,
	})

	w.AddLabel(ax, ay+y, "The authenticity of user %v (%v) can't be "+
		"established.", aw.pid.Name, aw.pid.Fingerprint())
	y += 2
	w.AddLabel(ax, ay+y, "Name: %v", aw.pid.Name)
	y++
	w.AddLabel(ax, ay+y, "Nick: %v", aw.pid.Nick)
	y++
	w.AddLabel(ax, ay+y, "Fingerprint: %v", aw.pid.Fingerprint())
	y++

	// XXX make this a verbose option?
	//w.AddLabel(ax, ay+y, "Key: %x", aw.pid.Key)
	//y++
	//w.AddLabel(ax, ay+y, "Identity: %x", aw.pid.Identity)
	//y++
	//w.AddLabel(ax, ay+y, "Signature: %x", aw.pid.Signature)
	//y++

	y++
	s := "Are you sure you want to continue connecting (yes/no)?"
	w.AddLabel(ax, ay+y, s)
	aw.questionInput = w.AddEdit(ax+len(s)+1, ay+y, -2, &aw.question)
}

func (aw *acceptCFPWindow) KeyHandler(w *ttk.Window, k ttk.Key) {
	switch k.Key {
	case termbox.KeyEnter:
		if strings.ToLower(aw.question) != "yes" {
			// write reject notice to log
			aw.zkc.PrintfT(0, "Rejected user %v nick %v "+
				"fingerprint %v", aw.pid.Name, aw.pid.Nick,
				aw.pid.Fingerprint())
			ttk.Focus(aw.zkc.ttkMW)
			return
		}

		// do something
		aw.zkc.Dbg(idZKC, "step 1 (complete) idkx")

		aw.Status(w, false, "success")

		// setup a new ratchet
		r := ratchet.New(rand.Reader)
		r.MyPrivateKey = &aw.zkc.id.PrivateKey
		r.MySigningPublic = &aw.zkc.id.Public.SigKey
		r.TheirIdentityPublic = &aw.pid.Identity
		r.TheirSigningPublic = &aw.pid.SigKey
		r.TheirPublicKey = &aw.pid.Key

		kxRatchet := new(ratchet.KeyExchange)
		err := r.FillKeyExchange(kxRatchet)
		if err != nil {
			aw.Status(w, true, "could not setup ratchet key "+
				"exchange: %v", err)
			return
		}

		// return id + kx
		idkx := rpc.IdentityKX{
			Identity: aw.zkc.id.Public,
			KX:       *kxRatchet,
		}
		idkxXDR := &bytes.Buffer{}
		_, err = xdr.Marshal(idkxXDR, idkx)
		if err != nil {
			aw.Status(w, true, "could not marshal IdentityKX")
			return
		}

		// encrypt idkx
		encrypted, nonce, err := blobshare.Encrypt(idkxXDR.Bytes(),
			aw.dk)
		if err != nil {
			aw.Status(w, true, "could not encrypt IdentityKX %v",
				err)
			return
		}

		aw.zkc.Dbg(idZKC, "step 2 (cache) idkx")

		// send cache command, step 2 of idkx
		err = aw.zkc.cache(aw.pid.Identity,
			blobshare.PackNonce(nonce, encrypted))
		if err != nil {
			aw.Status(w, true, "could not send IdentityKX %v", err)
			return
		}

		//
		// if we get here save off identity, half ratchet and derived key
		//

		// store public identity if this is a new identity
		if aw.newIdentity {
			err = aw.zkc.saveIdentity(*aw.pid)
			if err != nil {
				aw.Status(w, true, "Could not save identity: %v",
					err)
				return
			}
		}

		// save derived key, needed in step 3 of idkx
		err = aw.zkc.saveKey(aw.dk)
		if err != nil {
			aw.Status(w, true, "Could not save key: %v", err)
			return
		}

		// save half ratchet, needed in step 3 of idkx
		aw.zkc.ratchetMtx.Lock()
		err = aw.zkc.updateRatchet(r, true)
		if err != nil {
			aw.zkc.ratchetMtx.Unlock()
			aw.Status(w, true, "Could not half ratchet: %v", err)
			return
		}
		aw.zkc.ratchetMtx.Unlock()

		aw.zkc.PrintfT(0, "Accepted user %v nick %v "+
			"fingerprint %v", aw.pid.Name, aw.pid.Nick,
			aw.pid.Fingerprint())
		ttk.Focus(aw.zkc.ttkMW)
	}
}
