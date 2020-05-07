// Copyright (c) 2016-2020 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/companyzero/zkc/inidb"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/tools"
	xdr "github.com/davecgh/go-xdr/xdr2"
)

//func (z *ZKS) pruneRendezvous(rz *inidb.INIDB) error {
//	r := rz.Records("")
//	for k, v := range r {
//		rzXDR, err := base64.StdEncoding.DecodeString(v)
//		if err != nil {
//			return fmt.Errorf("corrupt rendezvous record: %v", k)
//		}
//		rzRecord := rpc.Rendezvous{} // deliberate instantiate
//		br := bytes.NewReader(rzXDR)
//		_, err = z.unmarshal(br, &rzRecord)
//		if err != nil {
//			return fmt.Errorf("could not unmarshal rendezvous "+
//				"record: %v", k)
//		}
//
//		t := time.Now().Add(rzRecord.Expiration * time.Hour)
//		//	t, err := strconv.ParseInt(v, 10, 64)
//		//	if err != nil {
//		//		// token corrupt, remove from db and complain
//		//		z.Dbg(idApp, "corrupt token %v", k)
//		//		_ = rz.Del("", k)
//		//		continue
//		//	}
//		//	ts := time.Unix(t, 0)
//		//	if ts.Before(time.Now()) {
//		//		// token expired, remove from db
//		//		_ = rz.Del("", k)
//		//		continue
//		//	}
//	}
//
//}

func (z *ZKS) handleRendezvousPull(writer chan *RPCWrapper,
	msg rpc.Message, r rpc.RendezvousPull) error {

	z.T(idRPC, "handleRendezvousPull tag %v", msg.Tag)

	// always reply from here on out (provided non fatal error)
	reply := RPCWrapper{
		Message: rpc.Message{
			Command: rpc.TaggedCmdRendezvousPullReply,
			Tag:     msg.Tag,
		},
	}

	// default error
	payload := rpc.RendezvousPullReply{
		Error: "internal error, contact server administrator",
	}

	// open db
	rz, err := inidb.New(path.Join(z.settings.Root, rendezvousPath),
		true, 10)
	if err != nil && !errors.Is(err, inidb.ErrCreated) {
		return fmt.Errorf("could not open rendezvous db: %v", err)
	}

	// vars to deal with go bitching about goto
	var (
		rzXDR    []byte
		rzRecord rpc.Rendezvous
		br       *bytes.Reader
	)

	// get token
	v, err := rz.Get("", r.Token)
	if err != nil {
		payload.Error = fmt.Sprintf("invalid PIN")
		goto bad
	}

	// decode value
	rzXDR, err = base64.StdEncoding.DecodeString(v)
	if err != nil {
		payload.Error = fmt.Sprintf("internal error base64decode")
		goto bad
	}
	br = bytes.NewReader(rzXDR)
	_, err = z.unmarshal(br, &rzRecord)
	if err != nil {
		payload.Error = fmt.Sprintf("internal error unmarshal")
		goto bad
	}

	// XXX check for expiration here

	// setup reply
	payload.Error = ""
	payload.Token = r.Token
	payload.Blob = rzRecord.Blob
bad:
	reply.Payload = payload
	writer <- &reply
	return nil
}

// handleRendezvous handles all aspects of a Rendezvous message.  This
// includes the client reply.  Note that returning an error from this
// function will result in a closed connection.
func (z *ZKS) handleRendezvous(writer chan *RPCWrapper,
	msg rpc.Message, r rpc.Rendezvous) error {

	z.T(idRPC, "handleRendezvous tag %v", msg.Tag)

	// always reply from here on out (provided non fatal error)
	reply := RPCWrapper{
		Message: rpc.Message{
			Command: rpc.TaggedCmdRendezvousReply,
			Tag:     msg.Tag,
		},
	}

	// default error
	payload := rpc.RendezvousReply{
		Error: "internal error, contact server administrator",
	}

	// do these declarations before goto to shut go compiler up
	retry := 25

	// open db
	rz, err := inidb.New(path.Join(z.settings.Root, rendezvousPath),
		true, 10)
	if err != nil && !errors.Is(err, inidb.ErrCreated) {
		return fmt.Errorf("could not open rendezvous db: %v",
			err)
	}
	//defer z.pruneRendezvous(rz) // kill all expired records
	defer func() {
		// save db back
		err := rz.Save()
		if err != nil {
			z.Error(idApp, "could not save rendezvous db: %v", err)
		}
	}()

	// sanitize inputs
	if len(r.Blob) > 4096 {
		payload.Error = "invalid blob size"
		goto bad
	}
	if exp, err := strconv.ParseUint(r.Expiration, 10, 64); err != nil ||
		exp > 168 {
		payload.Error = "invalid expiration"
		goto bad
	}

	// store blob
	for retry > 0 {
		token, err := tools.RandomUint64()
		if err != nil {
			// out of entropy
			time.Sleep(500 * time.Millisecond)
			retry--
			continue
		}
		token %= 1000000
		tokenS := strconv.FormatUint(token, 10)

		// get token
		_, err = rz.Get("", tokenS)
		if err == nil {
			// duplicate
			retry--
			continue
		}

		// value = base64(xdr(TaggedCmdRendezvous))
		var b bytes.Buffer
		_, err = xdr.Marshal(&b, r)
		if err != nil {
			z.Error(idRPC, "handleRendezvous: could not marshal")
			goto bad
		}
		err = rz.Set("", tokenS,
			base64.StdEncoding.EncodeToString(b.Bytes()))
		if err != nil {
			// db error
			retry--
			z.Error(idRPC, "could not insert in rendezvous db: %v",
				err)
			continue
		}

		// success
		payload.Error = ""
		payload.Token = tokenS
		break
	}

bad:
	reply.Payload = payload
	writer <- &reply
	return nil
}
