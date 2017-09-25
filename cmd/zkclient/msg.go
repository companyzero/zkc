// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/companyzero/zkc/ratchet"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-spew/spew"
	"github.com/davecgh/go-xdr/xdr2"
)

const (
	maxMsg  = 16
	maxBulk = 4
)

type queueDepth struct {
	hi int
	lo int
}

type wireMsg struct {
	// id == nil -> msg contains PRPC, payload contains PRPC payload
	// id != nil payload -> CRPC
	id *[zkidentity.IdentitySize]byte

	msg rpc.Message // PRPC

	payload interface{} // always set

	callback func()
}

func (z *ZKC) scheduler() {
	z.Dbg(idSnd, "scheduler")

	// make global queues
	z.hi = make(chan wireMsg, maxMsg)
	z.lo = make(chan wireMsg, maxBulk)
	z.depth = make(chan struct{})
	z.queueW = make(chan *queueDepth)

	// local crap
	mtx := sync.Mutex{}               // msg and bulk mutex
	hi := make([]wireMsg, 0, maxMsg)  // high prio messages
	lo := make([]wireMsg, 0, maxBulk) // low prio messages
	execute := make(chan bool, 2)     // tell them there is work

	queueHi := func(m wireMsg) {
		// queue message
		mtx.Lock()
		hi = append(hi, m)
		mtx.Unlock()

		// tell executer there is work
		select {
		case execute <- true:
		default:
		}
	}

	drainHi := func() {
		for {
			select {
			case m := <-z.hi:
				queueHi(m)
				continue

			default:
				return
			}
		}
	}

	// work queue
	go func() {
		//defer z.wg.Done()
		for {
			select {
			case <-z.done:
				return

			case m := <-z.hi:
				queueHi(m)
				drainHi()

			case b := <-z.lo:
				drainHi()

				// queue message
				mtx.Lock()
				lo = append(lo, b)
				mtx.Unlock()

				// tell executer there is work
				select {
				case execute <- true:
				default:
				}
			}
		}
	}()

	// send to net
	go func() {
		//defer z.wg.Done()
		var (
			err    error
			m      wireMsg
			hiPrio bool
		)
		for {
			select {
			case <-z.done:
				return
			case <-z.depth:
				mtx.Lock()
				z.queueW <- &queueDepth{
					hi: len(hi),
					lo: len(lo),
				}
				mtx.Unlock()
			case <-execute:
				for {
					// get work off high prio queue
					mtx.Lock()
					if len(hi) == 0 {
						// check low prio work
						if len(lo) == 0 {
							mtx.Unlock()
							break
						}
						// low prio work
						hiPrio = false
						m = lo[0]
					} else {
						// high prio work
						hiPrio = true
						m = hi[0]
					}
					mtx.Unlock()

					// actually do work
					//z.Dbg(idSnd, "m.id %x %v", m.id, hiPrio)
					if m.id != nil {
						err = z.cacheCRPC(*m.id,
							m.payload, m.callback)
						if err != nil {
							z.PrintfT(-1, REDBOLD+
								"CRPC (rescheduled): %v"+
								RESET,
								err)
							break
						}
					} else {
						if z.settings.Debug &&
							m.msg.Command != rpc.TaggedCmdPing {
							z.Dbg(idZKC, "write PRPC %v%v",
								spew.Sdump(m.msg),
								spew.Sdump(m.payload))
						}
						err = z.writeMessage(&m.msg, m.payload)
						if err != nil {
							z.PrintfT(-1, REDBOLD+
								"PRPC (rescheduled): %v"+
								RESET,
								err)
							break
						}
					}

					// if we got here we can dequeue
					mtx.Lock()
					if hiPrio {
						hi = hi[1:]
					} else {
						lo = lo[1:]
					}
					mtx.Unlock()
				}
			}
		}
	}()
}

func (z *ZKC) queueDepth() (*queueDepth, error) {
	select {
	case z.depth <- struct{}{}:
	default:
		return nil, fmt.Errorf("could not obtain queue depth")
	}

	return <-z.queueW, nil
}

func (z *ZKC) scheduleCRPCCB(hi bool, id *[zkidentity.IdentitySize]byte,
	payload interface{}, f func()) {

	m := wireMsg{
		id:       id,
		payload:  payload,
		callback: f,
	}
	if hi {
		//z.Dbg(idSnd, "sending CRPC hi")
		z.hi <- m
	} else {
		//z.Dbg(idSnd, "sending CRPC lo")
		z.lo <- m
	}
	//z.Dbg(idSnd, "sending CRPC done")
}

func (z *ZKC) scheduleCRPC(hi bool, id *[zkidentity.IdentitySize]byte,
	payload interface{}) {

	m := wireMsg{
		id:      id,
		payload: payload,
	}
	if hi {
		//z.Dbg(idSnd, "sending CRPC hi")
		z.hi <- m
	} else {
		//z.Dbg(idSnd, "sending CRPC lo")
		z.lo <- m
	}
	//z.Dbg(idSnd, "sending CRPC done")
}

func (z *ZKC) schedulePRPC(hi bool, msg rpc.Message, payload interface{}) {
	m := wireMsg{
		msg:     msg,
		payload: payload,
	}
	if hi {
		//z.Dbg(idSnd, "sending PRPC hi")
		z.hi <- m
	} else {
		//z.Dbg(idSnd, "sending PRPC lo")
		z.lo <- m
	}
	//z.Dbg(idSnd, "sending PRPC done")
}

func (z *ZKC) compress(payload interface{}) ([]byte, string, error) {
	var (
		bb  bytes.Buffer
		err error
	)

	switch p := payload.(type) {
	case rpc.PrivateMessage:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal private message")
		}
	case rpc.GroupInvite:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal group invite")
		}
	case rpc.GroupJoin:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal group join")
		}
	case rpc.GroupList:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal group list")
		}

	case rpc.GroupMessage:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal group message")
		}

	case rpc.GroupKill:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal group kill")
		}

	case rpc.GroupKick:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal group kick")
		}

	case rpc.GroupPart:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal group part")
		}

	case rpc.ChunkNew:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal chunk new")
		}

	case rpc.Chunk:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal chunk")
		}

	case rpc.JanitorMessage:
		_, err = xdr.Marshal(&bb, p)
		if err != nil {
			return nil, "",
				fmt.Errorf("could not marshal janitor message")
		}

	default:
		return nil, "", fmt.Errorf("invalid type %T", payload)
	}

	// see if it is worth compressing
	var (
		w  io.Writer
		cb bytes.Buffer
	)

	w = zlib.NewWriter(&cb)
	w.Write(bb.Bytes())

	// leave this here in case we use other compressions later
	if wc, ok := w.(io.WriteCloser); ok {
		wc.Close()
	}

	if bb.Len() < len(cb.Bytes()) {
		return bb.Bytes(), rpc.CRPCCompNone, nil
	}

	return cb.Bytes(), rpc.CRPCCompZLIB, nil
}

func (z *ZKC) crpc(r *ratchet.Ratchet, payload interface{}) ([]byte, error) {
	cmd := rpc.CRPC{}

	p, compression, err := z.compress(payload)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %v ", err)
	}
	cmd.Compression = compression

	// set payload type
	switch payload.(type) {
	case rpc.PrivateMessage:
		cmd.Command = rpc.CRPCCmdPrivateMessage
	case rpc.GroupInvite:
		cmd.Command = rpc.CRPCCmdGroupInvite
	case rpc.GroupJoin:
		cmd.Command = rpc.CRPCCmdGroupJoin
	case rpc.GroupList:
		cmd.Command = rpc.CRPCCmdGroupList
	case rpc.GroupMessage:
		cmd.Command = rpc.CRPCCmdGroupMessage
	case rpc.GroupPart:
		cmd.Command = rpc.CRPCCmdGroupPart
	case rpc.GroupKill:
		cmd.Command = rpc.CRPCCmdGroupKill
	case rpc.GroupKick:
		cmd.Command = rpc.CRPCCmdGroupKick
	case rpc.ChunkNew:
		cmd.Command = rpc.CRPCCmdChunkNew
	case rpc.Chunk:
		cmd.Command = rpc.CRPCCmdChunk
	case rpc.JanitorMessage:
		cmd.Command = rpc.CRPCCmdJanitorMessage
	default:
		return nil, fmt.Errorf("unknown crpc type: %T", payload)
	}

	cmd.Timestamp = time.Now().Unix()

	// encode CRPC
	var bb bytes.Buffer
	_, err = xdr.Marshal(&bb, cmd)
	if err != nil {
		return nil,
			fmt.Errorf("could not marshal CRPC")
	}

	// append payload
	bb.Write(p)

	// encrypt CRPC
	blob := r.Encrypt(nil, bb.Bytes())

	return blob, nil
}

func (z *ZKC) pm(id [zkidentity.IdentitySize]byte, message string, mode uint32) error {
	z.scheduleCRPC(true, &id,
		rpc.PrivateMessage{
			Text: message,
			Mode: mode,
		})

	return nil
}

func (z *ZKC) isOnline() bool {
	z.RLock()
	defer z.RUnlock()
	return z.online
}

func (z *ZKC) cacheCRPC(id [zkidentity.IdentitySize]byte, payload interface{},
	f func()) error {
	// best effort to detect if we are offline
	if !z.isOnline() {
		return fmt.Errorf("not online")
	}

	z.ratchetMtx.Lock()
	defer z.ratchetMtx.Unlock()

	// get ratchet
	r, err := z.loadRatchet(id, false)
	if err != nil {
		// This error is special, we have not completed KX with remote.
		// We can also not return failure here because there is no way
		// to reschedule this.
		z.PrintfT(-1, REDBOLD+"Message cannot be delivered: %v"+RESET,
			err)
		z.PrintfT(-1, REDBOLD+"Make sure that you complete KX with: %v"+
			RESET, hex.EncodeToString(id[:]))
		return nil
	}

	// compose RPC
	m, err := z.crpc(r, payload)
	if err != nil {
		return fmt.Errorf("could not compose %T: %v", payload, err)
	}

	// message
	tag, err := z.tagStack.Pop()
	if err != nil {
		return fmt.Errorf("could not obtain tag: %v", err)
	}

	z.Lock()
	z.tagCallback[tag] = f
	z.Unlock()

	msg := &rpc.Message{
		Command: rpc.TaggedCmdCache,
		Tag:     tag,
	}

	if z.settings.Debug &&
		msg.Command != rpc.TaggedCmdPing {
		z.Dbg(idZKC, "write CRPC: %v%v%v",
			spew.Sdump(msg),
			spew.Sdump(r.TheirIdentityPublic),
			spew.Sdump(payload))
	}

	err = z.writeMessage(msg,
		rpc.Cache{
			To:      *r.TheirIdentityPublic,
			Payload: m,
		})
	if err != nil {
		z.Lock()
		z.tagCallback[tag] = nil
		z.Unlock()
		// return tag
		err2 := z.tagStack.Push(tag)
		if err2 != nil {
			// we really are in deep shit now
			return fmt.Errorf("could not push tag, internal "+
				"state corrupt, please quit: %v %v", err, err2)
		}

		return err
	}

	// save ratchet only if we sent
	err = z.updateRatchet(r, false)
	if err != nil {
		return fmt.Errorf("critical error: could not update ratchet: %v",
			err)
	}

	return nil
}
