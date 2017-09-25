// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path"

	"github.com/companyzero/zkc/rpc"
)

func (z *ZKC) handleJanitorMessage(msg rpc.Message, p rpc.Push,
	jm rpc.JanitorMessage) error {

	nick := hex.EncodeToString(p.From[:])
	id, err := z.ab.FindIdentity(p.From)
	if err == nil {
		nick = id.Nick
	}

	var line1, line2 string
	switch jm.Command {
	case rpc.CRPCJanitorRatchetReset:
		line1 = fmt.Sprintf("remote sent reset ratchet message: %v",
			jm.Reason)
		line2 = fmt.Sprintf("if you initiated a reset this means "+
			"the other side completed the reset and you can "+
			"perform a key exchange. Others type: /reset %v", nick)
	case rpc.CRPCJanitorDeleted:
		line1 = fmt.Sprintf("remote sent delete user message: %v",
			jm.Reason)
		line2 = fmt.Sprintf("remote user %v will no longer receive "+
			"your messages.", nick)
	default:
		return fmt.Errorf("remote invalid janitor message: %v",
			jm.Command)
	}

	z.PrintfT(0, "%v", REDBOLD+line1+RESET)
	if line2 != "" {
		z.PrintfT(0, "%v", line2)
	}
	z.RLock()
	if z.active != 0 {
		z.PrintfT(-1, "%v", REDBOLD+line1+RESET)
		if line2 != "" {
			z.PrintfT(-1, "%v", line2)
		}
	}
	z.RUnlock()

	return nil
}

// reset kills the current ratchet state with the provided nick.
func (z *ZKC) reset(nick string) error {
	id, err := z.ab.FindNick(nick)
	if err != nil {
		return err
	}

	ids := hex.EncodeToString(id.Identity[:])
	fullPath := path.Join(z.settings.Root, inboundDir, ids)

	// always remove half ratchet
	os.Remove(path.Join(fullPath, halfRatchetFilename))

	// assert any ratchet file exists for sanity
	_, err = os.Stat(path.Join(fullPath, ratchetFilename))
	if err != nil {
		return fmt.Errorf("ratchet file does not exists for %v", nick)
	}

	z.PrintfT(-1, REDBOLD+"ratchet reset initiated with: %v"+RESET, nick)

	f := func() {
		// delete ratchets from disk
		err := os.Remove(path.Join(fullPath, ratchetFilename))
		if err != nil {
			z.PrintfT(-1, "could not remove ratchet for %v: %v",
				nick, err)
		}
	}

	// try to tell the other side
	z.scheduleCRPCCB(true, &id.Identity, rpc.JanitorMessage{
		Command: rpc.CRPCJanitorRatchetReset,
		Reason:  "please reset ratchet",
	}, f)

	return nil
}
