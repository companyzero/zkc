// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"path"

	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/session"
	"github.com/companyzero/zkc/zkidentity"
)

// think about establishing whitelist or just blind deliver
func (z *ZKS) handleCache(writer chan *RPCWrapper, kx *session.KX,
	msg rpc.Message, cache rpc.Cache) error {

	// sanity
	if msg.Command != rpc.TaggedCmdCache {
		return fmt.Errorf("invalid cache command")
	}

	// deliver message
	var (
		from [zkidentity.IdentitySize]byte
		ok   bool
	)
	from, ok = kx.TheirIdentity().([32]byte)
	if !ok {
		return fmt.Errorf("invalid identity type")
	}
	filename, err := z.account.Deliver(cache.To, from, cache.Payload)
	if err != nil {
		return fmt.Errorf("delivery failed: %v", err)
	}

	// ack
	writer <- &RPCWrapper{
		Message: rpc.Message{
			Command: rpc.TaggedCmdAcknowledge,
			Tag:     msg.Tag,
		},
		Payload: rpc.Empty{},
	}

	// dont eval if not in debug mode
	if z.settings.Debug {
		z.Dbg(idApp, "handleCache: %v -> %v: %v",
			hex.EncodeToString(cache.To[:]),
			hex.EncodeToString(from[:]),
			path.Base(filename))
	}

	return nil
}
