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

func (z *ZKC) handleJanitorMessage(msg rpc.Message, p rpc.Push, jm rpc.JanitorMessage) error {

	nick := hex.EncodeToString(p.From[:])
	id, err := z.ab.FindIdentity(p.From)
	if err == nil {
		nick = id.Nick
	}

	var line1, line2 string
	switch jm.Command {
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

func (z *ZKC) handleResetRatchet(from [32]byte) error {
	pid, err := z.loadIdentity(from)
	if err != nil {
		return err
	}

	ids := hex.EncodeToString(from[:])
	fullPath := path.Join(z.settings.Root, inboundDir, ids)

	// always remove half ratchet
	os.Remove(path.Join(fullPath, halfRatchetFilename))

	// delete ratchet from disk
	os.Remove(path.Join(fullPath, ratchetFilename))

	z.FloodfT(pid.Nick, REDBOLD+"Requesting key exchange with: %v %v"+RESET,
		pid.Nick, ids)

	return z.step1IDKX(*pid)
}
