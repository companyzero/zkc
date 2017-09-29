// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"time"

	"github.com/companyzero/zkc/inidb"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/tools"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-xdr/xdr2"
)

const (
	invitesFilename = "invites/invites.ini"
	joinsFilename   = "joins/joins.ini"
)

// join db format:
// [group]
// from_id = rpc.GroupInvite

// invite db format:
// [group]
// to_id = rpv.GroupInvite

// unmarshalInvite decodes an inidb base64 string into an Invite.
func unmarshalInvite(b64 string) (*rpc.GroupInvite, error) {
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("could not decode base64 invite")
	}

	var invite rpc.GroupInvite
	br := bytes.NewReader(blob)
	_, err = xdr.Unmarshal(br, &invite)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal invite record")
	}

	return &invite, nil
}

// listJoins  displays all current replied to joins.
func (z *ZKC) listJoins(args []string) {
	z.PrintfT(-1, "Pending joins:")

	jdb, err := inidb.New(path.Join(z.settings.Root, joinsFilename),
		false, 10)
	if err != nil {
		return
	}

	z.listInvitesJoins(jdb, args)
}

// listInvites displays all current open invites.
func (z *ZKC) listInvites(args []string) {
	z.PrintfT(-1, "Pending invites:")

	idb, err := inidb.New(path.Join(z.settings.Root, invitesFilename),
		false, 10)
	if err != nil {
		return
	}

	z.listInvitesJoins(idb, args)
}

// listInvites displays all current open invites.
func (z *ZKC) listInvitesJoins(db *inidb.INIDB, args []string) {
	tables := db.Tables()
	for _, group := range tables {
		records := db.Records(group)
		for id, r := range records {
			invite, err := unmarshalInvite(r)
			if err != nil {
				z.Error(idZKC, "corrupt invite/join db %v:%v",
					group,
					id)
				continue
			}
			idx, err := hex.DecodeString(id)
			if err != nil {
				z.Error(idZKC, "corrupt invite/join db %v:%v",
					group,
					id)
				continue
			}
			var idxx [zkidentity.IdentitySize]byte
			copy(idxx[:], idx)
			pid, err := z.ab.FindIdentity(idxx)
			if err != nil {
				z.Error(idZKC, "could not find identity %v:%v",
					group,
					id)
				continue
			}
			z.PrintfT(-1, "    %v: %v %v %v",
				group,
				pid.Nick,
				invite.Token,
				time.Unix(invite.Expires, 0))
		}
	}
}

// inviteDBAdd adds an identity to the invites database and returns a token
// that can be used to validate a join request.
func (z *ZKC) inviteDBAdd(id [zkidentity.IdentitySize]byte, description string, group rpc.GroupList) (*rpc.GroupInvite, error) {

	ids := hex.EncodeToString(id[:])

	plist := make([]string, len(group.Members))
	for i := range group.Members {
		id, err := z.loadIdentity(group.Members[i])
		if err == nil {
			plist[i] = id.Nick
		}
	}

	// open db
	idb, err := inidb.New(path.Join(z.settings.Root, invitesFilename),
		true, 10)
	if err != nil && err != inidb.ErrCreated {
		return nil, fmt.Errorf("could not open invites db: %v", err)
	}
	err = idb.Lock()
	if err != nil {
		return nil, fmt.Errorf("could not lock invites db: %v", err)
	}
	// not much error recovery to do on unlock
	defer idb.Unlock()

	_, err = idb.Get(group.Name, ids)
	if err == nil {
		// if invite is expired create a new one
		return nil, fmt.Errorf("already invited, XXX add expiration check here")
	}

	// create new token
	var (
		token uint64
		retry int
	)
	for retry = 5; retry > 0; retry-- {
		token, err = tools.RandomUint64()
		if err != nil {
			// out of entropy
			time.Sleep(500 * time.Millisecond)
			continue
		}

		// make token a bit shorter
		token %= 1000000

		break
	}
	if retry == 0 {
		return nil, fmt.Errorf("out of entropy")
	}

	// always create table since it is a no-op if it exists
	idb.NewTable(group.Name)

	// add invite to database
	var b bytes.Buffer
	gi := rpc.GroupInvite{
		Name:        group.Name,
		Members:     plist,
		Token:       token,
		Description: description,
		Expires:     time.Now().Add(24 * time.Hour).Unix(),
	}
	_, err = xdr.Marshal(&b, gi)
	if err != nil {
		return nil, fmt.Errorf("could not marshal invite record")
	}
	err = idb.Set(group.Name, ids, base64.StdEncoding.EncodeToString(b.Bytes()))
	if err != nil {
		return nil, fmt.Errorf("could not set invite record: %v", err)
	}

	// write back to disk
	err = idb.Save()
	if err != nil {
		return nil, fmt.Errorf("could not save invite db: %v", err)
	}

	return &gi, nil
}

func (z *ZKC) joinDBAdd(from [zkidentity.IdentitySize]byte,
	gi rpc.GroupInvite) error {

	froms := hex.EncodeToString(from[:])

	// open db
	jdb, err := inidb.New(path.Join(z.settings.Root, joinsFilename),
		true, 10)
	if err != nil && err != inidb.ErrCreated {
		return fmt.Errorf("could not open joins db: %v", err)
	}
	err = jdb.Lock()
	if err != nil {
		return fmt.Errorf("could not lock joins db: %v", err)
	}
	// not much error recovery to do on unlock
	defer jdb.Unlock()

	_, err = jdb.Get(gi.Name, froms)
	if err == nil {
		return fmt.Errorf("join already seen: %v", gi.Name)
	}

	// always create table since it is a no-op if it exists
	jdb.NewTable(gi.Name)

	// add invite to join db
	var b bytes.Buffer
	_, err = xdr.Marshal(&b, gi)
	if err != nil {
		return fmt.Errorf("could not marshal join record")
	}
	err = jdb.Set(gi.Name, froms,
		base64.StdEncoding.EncodeToString(b.Bytes()))
	if err != nil {
		return fmt.Errorf("could not set join record: %v", err)
	}

	// write back to disk
	err = jdb.Save()
	if err != nil {
		return fmt.Errorf("could not save join db: %v", err)
	}

	return nil
}

func (z *ZKC) getJoin(group string, token uint64) ([zkidentity.IdentitySize]byte,
	error) {
	jdb, err := inidb.New(path.Join(z.settings.Root, joinsFilename),
		false, 10)
	if err != nil {
		return [zkidentity.IdentitySize]byte{},
			fmt.Errorf("could not open joins db: %v", err)
	}

	records := jdb.Records(group)
	for id, r := range records {
		invite, err := unmarshalInvite(r)
		if err != nil {
			z.Error(idZKC, "corrupt join db %v:%v",
				group,
				id)
			continue
		}
		if token != invite.Token {
			continue
		}
		idx, err := hex.DecodeString(id)
		if err != nil {
			z.Error(idZKC, "corrupt join db %v:%v",
				group,
				id)
			continue
		}

		var idxx [zkidentity.IdentitySize]byte
		copy(idxx[:], idx)
		return idxx, nil
	}

	return [zkidentity.IdentitySize]byte{},
		fmt.Errorf("token not found: %v", token)
}

func (z *ZKC) delJoin(group string, token uint64) error {
	jdb, err := inidb.New(path.Join(z.settings.Root, joinsFilename),
		false, 10)
	if err != nil {
		return fmt.Errorf("could not open joins db: %v", err)
	}

	err = jdb.Lock()
	if err != nil {
		return fmt.Errorf("could not lock joins db: %v", err)
	}
	// not much error recovery to do on unlock
	defer jdb.Unlock()

	records := jdb.Records(group)
	if len(records) != 1 {
		return fmt.Errorf("invalid join table")
	}
	for id, r := range records {
		// we search for record to make sure everything is cool
		invite, err := unmarshalInvite(r)
		if err != nil {
			z.Error(idZKC, "corrupt join db %v:%v",
				group,
				id)
			continue
		}
		if token != invite.Token {
			continue
		}

		// delete table
		err = jdb.DelTable(group)
		if err != nil {
			return err
		}

		// write back to disk
		err = jdb.Save()
		if err != nil {
			return fmt.Errorf("could not save join db: %v", err)
		}

		return nil
	}

	return fmt.Errorf("not found")
}

func (z *ZKC) delInvite(from [zkidentity.IdentitySize]byte,
	gj rpc.GroupJoin) error {

	froms := hex.EncodeToString(from[:])

	idb, err := inidb.New(path.Join(z.settings.Root, invitesFilename),
		false, 10)
	if err != nil {
		return fmt.Errorf("could not open invites db: %v", err)
	}

	err = idb.Lock()
	if err != nil {
		return fmt.Errorf("could not lock invites db: %v", err)
	}
	// not much error recovery to do on unlock
	defer idb.Unlock()

	// verify originator and token
	r, err := idb.Get(gj.Name, froms)
	if err != nil {
		return fmt.Errorf("invitee not found %v: %v", gj.Name, froms)
	}
	invite, err := unmarshalInvite(r)
	if err != nil {
		return fmt.Errorf("corrupt invites db %v:%v", gj.Name, froms)
	}
	if invite.Token != gj.Token {
		return fmt.Errorf("invalid token %v %v: %v",
			gj.Name, froms, gj.Token)
	}

	// delete record
	err = idb.Del(gj.Name, froms)
	if err != nil {
		return fmt.Errorf("could not delete %v %v: %v",
			gj.Name, froms, err)
	}

	// write back to disk
	err = idb.Save()
	if err != nil {
		return fmt.Errorf("could not save invites db: %v", err)
	}

	return nil
}
