// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkclient/addressbook"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-xdr/xdr2"
)

// addressBookDel permanently removes nick from the address book.
func (z *ZKC) addressBookDel(nick string) error {
	id, err := z.ab.FindNick(nick)
	if err != nil {
		return fmt.Errorf("nick not found: %v", nick)
	}

	f := func() {
		err = z.ab.Del(id.Identity)
		if err != nil {
			z.PrintfT(-1, REDBOLD+
				"could not delete %v from address book: %v"+
				RESET,
				nick, err)
			return
		}

		filename := path.Join(z.settings.Root, inboundDir,
			hex.EncodeToString(id.Identity[:]))
		err = os.RemoveAll(filename)
		if err != nil {
			z.PrintfT(-1, REDBOLD+"delete %v: %v"+RESET, nick, err)
			return
		}
		z.PrintfT(-1, "deleted user: %v", nick)
	}

	// try to tell the other side
	z.scheduleCRPCCB(true, &id.Identity, rpc.JanitorMessage{
		Command: rpc.CRPCJanitorDeleted,
		Reason:  "remote user deleted",
	}, f)

	return nil
}

// addressBookAdd adds a new identity to the address book and warns if a
// duplicate nick was found.
func (z *ZKC) addressBookAdd(id zkidentity.PublicIdentity) error {
	// make sure we don't add ourselves
	if bytes.Equal(z.id.Public.Identity[:], id.Identity[:]) {
		return fmt.Errorf("can't add self to address book")
	}

	nick, err := z.ab.Add(id)
	if err != nil {
		if err == addressbook.ErrDuplicateNick {
			z.PrintfT(0, "warning duplicate nick added: %v -> %v",
				id.Nick, nick)
		}
	}
	return err
}

// addressBookConversation returns an existing conversation from nick.
func (z *ZKC) addressBookConversation(nick string) (*conversation, int, error) {
	// create a new conversation if nick exists
	id, err := z.ab.FindNick(nick)
	if err != nil {
		return nil, -1, fmt.Errorf("nick not found: %v", nick)
	}

	return z.getConversation(id.Identity)
}

// addressBookFind looks for id in addressbook.  Additionally it returns self if
// that matches.  Note this is usually not what you want!
func (z *ZKC) addressBookFind(id [zkidentity.IdentitySize]byte) (*zkidentity.PublicIdentity, error) {
	if bytes.Equal(id[:], z.id.Public.Identity[:]) {
		return &z.id.Public, nil
	}
	return z.ab.FindIdentity(id)
}

// loadIdentities loads all identities from their respective home directories.
func (z *ZKC) loadIdentities() error {
	fi, err := ioutil.ReadDir(path.Join(z.settings.Root, inboundDir))
	if err != nil {
		return err
	}

	for _, v := range fi {
		// read
		filename := path.Join(z.settings.Root, inboundDir, v.Name(),
			identityFilename)
		idXDR, err := ioutil.ReadFile(filename)
		if err != nil {
			z.PrintfT(0, "read identity: %v %v", filename, err)
			continue
		}
		var idDisk zkidentity.PublicIdentity
		br := bytes.NewReader(idXDR)
		_, err = xdr.Unmarshal(br, &idDisk)
		if err != nil {
			z.PrintfT(0, "unmarshal public identity %v: %v",
				filename, err)
			continue
		}

		err = z.addressBookAdd(idDisk)
		if err != nil {
			z.PrintfT(0, "unable to add to address book: %v", err)
			continue
		}
	}

	return nil
}
