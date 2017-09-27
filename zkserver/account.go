// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"net"

	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/session"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-xdr/xdr2"
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

func (z *ZKS) handleAccountCreate(kx *session.KX, ca rpc.CreateAccount) error {
	if ca.PublicIdentity.Verify() == false {
		return fmt.Errorf("failed to verify identity")
	}
	if ca.PublicIdentity.Identity != kx.TheirIdentity() {
		return fmt.Errorf("identity mismatch")
	}

	conn := kx.Conn
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
	var bb bytes.Buffer
	_, err = xdr.Marshal(&bb, car)
	if err != nil {
		return fmt.Errorf("could not marshal CreateAccountReply")
	}
	err = kx.Write(bb.Bytes())
	if err != nil {
		return fmt.Errorf("could not write CreateAccountReply")
	}

	return nil
}

func (z *ZKS) handleIdentityPush(writer chan *RPCWrapper, msg rpc.Message, id [zkidentity.IdentitySize]byte) error {
	reply := RPCWrapper{
		Message: rpc.Message{
			Command: rpc.TaggedCmdIdentityPushReply,
			Tag:     msg.Tag,
		},
	}
	payload := new(rpc.IdentityPushReply)
	err := z.account.Push(id)
	if err != nil {
		payload.Error = "server error; identity push failed"
	}
	reply.Payload = payload
	writer <- &reply
	return nil
}

func (z *ZKS) handleIdentityFind(writer chan *RPCWrapper, msg rpc.Message, nick string) error {
	reply := RPCWrapper{
		Message: rpc.Message{
			Command: rpc.TaggedCmdIdentityFindReply,
			Tag:     msg.Tag,
		},
	}
	payload := new(rpc.IdentityFindReply)
	id, err := z.account.Find(nick)
	if err != nil {
		payload.Error = fmt.Sprintf("%v", err) // XXX
	} else {
		payload.Identity = *id
	}
	reply.Payload = payload
	writer <- &reply
	return nil
}
