// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/companyzero/zkc/zkserver/socketapi"
	xdr "github.com/davecgh/go-xdr/xdr2"
)

// replyAccountFailure marshals and sends a CreateAccountReply with
// Error set.
func (z *ZKS) accountReplyFailure(msg string, conn net.Conn,
	ca rpc.CreateAccount) {
	z.T(idApp, "accountReplyFailure: %v %v %v",
		conn.RemoteAddr(),
		msg,
		ca.PublicIdentity.Fingerprint())
	car := rpc.CreateAccountReply{
		Error: rpc.ErrCreateDisallowed.Error(),
	}
	_, err := xdr.Marshal(conn, car)
	if err != nil {
		z.Error(idApp, "could not marshal CreateAccountReply")
		return
	}
}

func (z *ZKS) handleAccountCreate(conn net.Conn, ca rpc.CreateAccount) error {
	z.T(idApp, "handleAccountCreate: %v %v",
		conn.RemoteAddr(),
		ca.PublicIdentity.Fingerprint())
	// check policy
	switch z.settings.CreatePolicy {
	default:
		fallthrough
	case "no":
		z.accountReplyFailure("disallowing account create", conn, ca)
		return fmt.Errorf("disallowing account create")
	case "token":
		if !z.validToken(ca.Token, conn) {
			z.accountReplyFailure("invalid account create token",
				conn, ca)
			return fmt.Errorf("invalid account create token")
		}
	case "yes":
	}

	// try to create account
	err := z.account.Create(ca.PublicIdentity, false)
	if err != nil {
		z.Error(idApp, "%v could not create account: %v",
			conn.RemoteAddr(),
			err)
		// fallthrough to answer
	} else {
		z.Info(idApp, "created account %v: %v",
			conn.RemoteAddr(),
			ca.PublicIdentity.Fingerprint())
	}

	// send reply
	car := rpc.CreateAccountReply{}
	if err != nil {
		car.Error = rpc.ErrInternalError.Error()
	}
	_, err = xdr.Marshal(conn, car)
	if err != nil {
		return fmt.Errorf("could not marshal CreateAccountReply")
	}

	return nil
}

func (z *ZKS) handleIdentityFind(writer chan *RPCWrapper, msg rpc.Message, nick string) error {
	reply := RPCWrapper{
		Message: rpc.Message{
			Command: rpc.TaggedCmdIdentityFindReply,
			Tag:     msg.Tag,
		},
	}
	payload := rpc.IdentityFindReply{
		Nick: nick,
	}
	id, err := z.account.Find(nick)
	if err != nil {
		payload.Error = fmt.Sprintf("nick not found: %v", nick)
	} else {
		payload.Identity = *id
	}
	reply.Payload = payload
	writer <- &reply
	return nil
}

// handleIdentityDisable always returns an answer to the disable command.
func (z *ZKS) handleIdentityDisable(ud socketapi.SocketCommandUserDisable) (udr *socketapi.SocketCommandUserDisableReply) {
	udr = &socketapi.SocketCommandUserDisableReply{}
	id, err := hex.DecodeString(ud.Identity)
	if err != nil {
		udr.Error = err.Error()
		return
	}
	if len(id) != zkidentity.IdentitySize {
		udr.Error = err.Error()
		return
	}
	var pid [zkidentity.IdentitySize]byte
	copy(pid[:], id)
	err = z.account.Disable(pid)
	if err != nil {
		udr.Error = err.Error()
		return
	}

	return
}

// handleIdentityEnable always returns an answer to the enable command.
func (z *ZKS) handleIdentityEnable(ue socketapi.SocketCommandUserEnable) (uer *socketapi.SocketCommandUserEnableReply) {
	uer = &socketapi.SocketCommandUserEnableReply{}
	id, err := hex.DecodeString(ue.Identity)
	if err != nil {
		uer.Error = err.Error()
		return
	}
	if len(id) != zkidentity.IdentitySize {
		uer.Error = err.Error()
		return
	}
	var pid [zkidentity.IdentitySize]byte
	copy(pid[:], id)
	err = z.account.Enable(pid)
	if err != nil {
		uer.Error = err.Error()
		return
	}

	return
}
