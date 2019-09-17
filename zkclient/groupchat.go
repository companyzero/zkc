// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	xdr "github.com/davecgh/go-xdr/xdr2"
)

const validLetters = "abcdefghijklmnopqrstuvwyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWYZ" +
	"1234567890" +
	"_-@."

func validName(name string) error {
	var found bool
	for _, c := range []byte(name) {
		found = false
		for _, v := range []byte(validLetters) {
			if c == v {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid name")
		}
	}

	return nil
}

func (z *ZKC) gcSaveDisk(name string) error {
	z.RLock()
	defer z.RUnlock()

	return z._gcSaveDisk(name)
}

func (z *ZKC) _deleteGroup(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	filename := path.Join(z.settings.Root, groupchatDir, name)

	delete(z.groups, name)
	return os.Remove(filename)
}

func (z *ZKC) _gcSaveDisk(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	filename := path.Join(z.settings.Root, groupchatDir, name)

	gc, found := z.groups[name]
	if !found {
		return fmt.Errorf("groupchat doesn't exist")
	}

	// make xdr
	var bb bytes.Buffer
	_, err := xdr.Marshal(&bb, gc)
	if err != nil {
		return fmt.Errorf("could not marshal groupchat: %v", name)
	}

	// lay on disk
	return ioutil.WriteFile(filename, bb.Bytes(), 0600)
}

func (z *ZKC) gcNew(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: /gc new <name>")
	}

	// see if gc already exists on disk
	filename := path.Join(z.settings.Root, groupchatDir, args[2])
	_, err := os.Stat(filename)
	if err == nil {
		return fmt.Errorf("groupchat already exists on disk")
	}

	// see if gc already exists in memory
	z.Lock()
	_, found := z.groups[args[2]]
	if found {
		z.Unlock()
		return fmt.Errorf("groupchat already exists in memory")
	}
	z.groups[args[2]] = rpc.GroupList{
		Name:       args[2],
		Generation: 0,
		Timestamp:  time.Now().Unix(),
		Members:    [][zkidentity.IdentitySize]byte{z.id.Public.Identity},
	}
	z.Unlock()

	err = z.gcSaveDisk(args[2])
	if err != nil {
		return fmt.Errorf("could not create new group: %v", args[2])
	}

	z.PrintfT(-1, "group chat created: %v", z.settings.GcColor+args[2]+RESET)

	return nil
}

func (z *ZKC) gcInvite(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: /gc invite <groupchat> <nick>")
	}

	id, err := z.ab.FindNick(args[3])
	if err != nil {
		return err
	}

	z.RLock()
	defer z.RUnlock()

	g, found := z.groups[args[2]]
	if !found {
		return fmt.Errorf("group chat not found: %v", args[2])
	}
	if len(g.Members) == 0 {
		return fmt.Errorf("group chat %v has no administrator", args[2])
	}
	if !bytes.Equal(g.Members[0][:], z.id.Public.Identity[:]) {
		return fmt.Errorf("must be administrator to invite to: %v",
			args[2])
	}

	// make sure id isn't in group already
	for _, v := range g.Members {
		if bytes.Equal(v[:], id.Identity[:]) {
			return fmt.Errorf("already a member: %v", args[3])
		}
	}

	// keep track of invites
	gi, err := z.inviteDBAdd(id.Identity, "come join me!", g)
	if err != nil {
		return fmt.Errorf("could not invite %v to group chat %v: %v",
			args[3], args[2], err)
	}

	// send CRPC
	z.scheduleCRPC(true, &id.Identity, *gi)

	z.PrintfT(-1, "group chat %v invite sent to %v",
		z.settings.GcColor+args[2]+RESET,
		z.settings.PmColor+args[3]+RESET)

	return nil
}

func (z *ZKC) gcJoin(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: /gc join <group> <token>")
	}

	token, err := strconv.ParseUint(args[3], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid token: %v", err)
	}

	z.Lock()
	defer z.Unlock()

	_, found := z.groups[args[2]]
	if found {
		return fmt.Errorf("group chat already exist: %v", args[2])
	}

	// pull info from joins table
	from, err := z.getJoin(args[2], token)
	if err != nil {
		return fmt.Errorf("join not found: %v %v", args[2], args[3])
	}

	// send RPC
	z.scheduleCRPC(true, &from, rpc.GroupJoin{
		Name:  args[2],
		Token: token,
	})

	// save group with just name and administrator
	z.groups[args[2]] = rpc.GroupList{
		Name:    args[2],
		Members: [][zkidentity.IdentitySize]byte{from},
	}

	err = z._gcSaveDisk(args[2])
	if err != nil {
		return fmt.Errorf("invalid token: %v", err)
	}

	// delete join from table
	err = z.delJoin(args[2], token)
	if err != nil {
		return fmt.Errorf("could not delete join from db %v %v: %v",
			args[2], token, err)
	}

	z.PrintfT(-1, "Joined group chat: %v", z.settings.GcColor+args[2]+RESET)

	return nil
}

func (z *ZKC) gcKick(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: /gc kick <group> <nick>|<identity>")
	}

	// find nick or identity
	nick := strings.Trim(args[3], " ")
	id, err := z.ab.FindNick(nick)
	if err != nil {
		// try to find identity
		i, e := hex.DecodeString(nick)
		if e != nil {
			return fmt.Errorf("nick not found: %v %v", nick, e)
		}
		if len(i) != sha256.Size {
			return fmt.Errorf("not a valid identity: %v", nick)
		}
		var ii [sha256.Size]byte
		copy(ii[:], i)
		id, err = z.ab.FindIdentity(ii)
		if err != nil {
			// identity not found so synthesize one to perform a
			// kick anyway
			id = &zkidentity.PublicIdentity{}
			copy(id.Identity[:], ii[:])
		}
	}

	// remove from group
	z.Lock()
	defer z.Unlock()

	gc, found := z.groups[args[2]]
	if !found {
		return fmt.Errorf("group not found: %v", args[2])
	}

	if len(gc.Members) == 0 {
		return fmt.Errorf("gcKick group %v has no administrator",
			args[2])
	}

	// make sure we are list administrator
	if !bytes.Equal(gc.Members[0][:], z.id.Public.Identity[:]) {
		return fmt.Errorf("not group chat administrator")
	}

	// make sure we aren't kicking admin
	if bytes.Equal(gc.Members[0][:], id.Identity[:]) {
		return fmt.Errorf("cannot kick administrator")
	}

	// new group membership list
	ngc := rpc.GroupList{
		Name:       gc.Name,
		Generation: gc.Generation,
		Timestamp:  time.Now().Unix(),
	}
	ngc.Generation++

	ngc.Members = make([][zkidentity.IdentitySize]byte, 0, len(gc.Members))
	// warn if user is not in kicklist but do it anyway
	found = false
	for _, m := range gc.Members {
		if !bytes.Equal(m[:], id.Identity[:]) {
			ngc.Members = append(ngc.Members, m)
		} else {
			found = true
		}
	}
	if !found {
		z.PrintfT(-1, "WARNING: %v not part of %v, sending kick "+
			"message anyway", args[3], args[2])
	}

	reason := "you have been a bad boy!" // make setable

	got := 0                    // acks seen
	want := len(gc.Members) - 1 // acks required
	f := func() {
		z.Lock()
		defer z.Unlock()

		// only do stuff on last ack
		got++
		if got != want {
			return
		}

		z.Dbg(idZKC, "gcKick: callback")

		// find conversation
		var (
			k = -1
			v *conversation
		)
		for k, v = range z.conversation {
			if v.id.Nick == args[2] {
				break
			}
		}

		// make sure group has not vanished
		_, found := z.groups[args[2]]
		if !found {
			z.PrintfT(0, REDBOLD+
				"group no longer exists: %v"+
				RESET, args[2], err)
			return
		}

		// set new group in memory
		z.groups[args[2]] = ngc

		// save to disk
		err = z._gcSaveDisk(args[2])
		if err != nil {
			em := fmt.Sprintf(REDBOLD+
				"could not save group to disk %v: %v"+
				RESET, args[2], err)
			z.PrintfT(0, "%v", em)
			// echo on conversation window
			if k > 0 {
				z.PrintfT(k, "%v", em)
			}
			return
		}

		km := fmt.Sprintf("%v was kicked of group chat %v: %v",
			z.settings.PmColor+args[3]+RESET,
			z.settings.GcColor+args[2]+RESET,
			reason)
		z.PrintfT(0, "%v", km)
		// echo on conversation window
		if k > 0 {
			z.PrintfT(k, "%v", km)
		}
	}

	// send new list to everyone including kickee if still part of the list
	for j := 1; j < len(gc.Members); j++ {
		z.Dbg(idZKC, "sending kick %v to: %x", args[2], gc.Members[j])
		z.scheduleCRPCCB(true, &gc.Members[j], rpc.GroupKick{
			Member:       id.Identity,
			Reason:       reason,
			Parted:       false,
			NewGroupList: ngc,
		}, f)
	}

	return nil
}

func (z *ZKC) gcPart(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: /gc part <group>")
	}

	z.RLock()
	defer z.RUnlock()

	gc, found := z.groups[args[2]]
	if !found {
		return fmt.Errorf("group not found: %v", args[2])
	}

	if len(gc.Members) == 0 {
		return fmt.Errorf("gcPart group %v has no administrator",
			args[2])
	}

	// make sure we are NOT the list administrator
	if bytes.Equal(gc.Members[0][:], z.id.Public.Identity[:]) {
		return fmt.Errorf("administrator can not part group chat")
	}

	// tell administrator
	z.scheduleCRPC(true, &gc.Members[0], rpc.GroupPart{
		Name:   args[2],
		Reason: "done here", // make this part of command
	})

	return nil
}

func (z *ZKC) gcKill(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: /gc kill <group>")
	}

	// remove group
	z.Lock()
	defer z.Unlock()

	if !z.online {
		return fmt.Errorf("cannot kill group while offline")
	}

	gc, found := z.groups[args[2]]
	if !found {
		return fmt.Errorf("group not found: %v", args[2])
	}

	// make sure we are list administrator
	send := true
	if len(gc.Members) == 0 {
		// XXX delete it anyway
		z.PrintfT(-1, REDBOLD+"group %v has no administrator, "+
			"group will be deleted!"+RESET, args[2])
		send = false
	}

	if send {
		if !bytes.Equal(gc.Members[0][:], z.id.Public.Identity[:]) {
			return fmt.Errorf("not group chat administrator")
		}
		// tell everyone
		for i := 1; i < len(gc.Members); i++ {
			// send kill to everyone
			z.scheduleCRPC(true, &gc.Members[i], rpc.GroupKill{
				Name:   args[2],
				Reason: "group chat killed",
			})
		}
	}

	// delete group
	err := z._deleteGroup(args[2])
	if err != nil {
		return fmt.Errorf("could not delete group chat %v: %v",
			args[2], err)
	}

	z.PrintfT(0, "group chat killed: %v",
		z.settings.GcColor+args[2]+RESET)

	// echo on conversation window
	for k, v := range z.conversation {
		if v.id.Nick == args[2] {
			z.PrintfT(k, REDBOLD+"group chat killed"+RESET)
			break
		}
	}

	return nil
}

func (z *ZKC) gcMessage(args []string, msg string, mode rpc.MessageMode) error {
	if len(args) < 4 {
		return fmt.Errorf("usage: /gc m|me <group> <message>")
	}

	c, win, err := z.groupConversation(args[2])
	if err != nil {
		return fmt.Errorf("can't find conversation: %v", err)
	}
	_ = c

	z.RLock()
	defer z.RUnlock()

	gc, found := z.groups[args[2]]
	if !found {
		return fmt.Errorf("group not found: %v", args[2])
	}

	// send to everyone except self
	for i := 0; i < len(gc.Members); i++ {
		if bytes.Equal(gc.Members[i][:], z.id.Public.Identity[:]) {
			continue
		}

		//z.Dbg(idSnd, "schedule CRPC")
		z.scheduleCRPC(true, &gc.Members[i], rpc.GroupMessage{
			Name:       args[2],
			Generation: gc.Generation,
			Message:    msg,
			Mode:       mode,
		})
	}

	// echo
	var nick string
	if mode == rpc.MessageModeMe {
		nick = fmt.Sprintf("* %v", z.settings.NickColor+z.id.Public.Nick+RESET)
	} else {
		nick = fmt.Sprintf("<%v>", z.settings.NickColor+z.id.Public.Nick+RESET)
	}
	z.PrintfT(win, "%v %v", nick, msg)

	return nil
}

func (z *ZKC) gc(action string, args []string) error {
	switch args[1] {
	case "new":
		return z.gcNew(args)

	case "invite":
		return z.gcInvite(args)

	case "join":
		return z.gcJoin(args)

	case "kick":
		return z.gcKick(args)

	case "me":
		if len(args) < 3 {
			return fmt.Errorf("not enough arguments for /gc me")
		}
		msg := strings.TrimSpace(strings.TrimPrefix(action, "/gc"))
		msg = strings.TrimSpace(strings.TrimPrefix(msg, "me"))
		msg = strings.TrimRight(strings.TrimPrefix(msg, args[2]+" "), " ")
		return z.gcMessage(args, msg, rpc.MessageModeMe)

	case "m":
		if len(args) < 3 {
			return fmt.Errorf("not enough arguments for /gc m")
		}
		msg := strings.TrimSpace(strings.TrimPrefix(action, "/gc"))
		msg = strings.TrimSpace(strings.TrimPrefix(msg, "m"))
		msg = strings.TrimRight(strings.TrimPrefix(msg, args[2]+" "), " ")
		return z.gcMessage(args, msg, rpc.MessageModeNormal)

	case "part":
		return z.gcPart(args)

	case "kill":
		return z.gcKill(args)

	default:
		return fmt.Errorf("invalid gc subcommand: %v", args[1])
	}

	// not reached
}
