// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/companyzero/sntrup4591761"
	"github.com/companyzero/zkc/blobshare"
	"github.com/companyzero/zkc/inidb"
	"github.com/companyzero/zkc/ratchet"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-spew/spew"
	"github.com/davecgh/go-xdr/xdr2"
)

// ratchetError is a special error type that is used to determine if a ratchet
// was wedged.
type ratchetError struct {
	err string
}

func (re *ratchetError) Error() string {
	return re.err
}

func (z *ZKC) printID(id *zkidentity.PublicIdentity) {
	z.PrintfT(-1, "Identity   : %v", id)
	z.PrintfT(-1, "Fingerprint: %v", id.Fingerprint())
	z.PrintfT(-1, "Name       : %v", id.Name)
	z.PrintfT(-1, "Nick       : %v", id.Nick)
}

func (z *ZKC) printKX(id *zkidentity.PublicIdentity) {
	z.FloodfT(id.Nick, "Client to Client Key Exchange complete:")
	z.FloodfT(id.Nick, "Identity   : %v", id)
	z.FloodfT(id.Nick, "Fingerprint: %v", id.Fingerprint())
	z.FloodfT(id.Nick, "Name       : %v", id.Name)
	z.FloodfT(id.Nick, "Nick       : %v", id.Nick)
}

func (z *ZKC) step3IDKX(msg rpc.Message, p rpc.Push) error {
	nonce, encrypted, err := blobshare.UnpackNonce(p.Payload)
	if err != nil {
		return fmt.Errorf("could not unpack KX")
	}

	//
	// try decrypting with all blob keys
	//

	// open db
	kdb, err := inidb.New(path.Join(z.settings.Root, blobKeysPath), true,
		10)
	if err != nil && err != inidb.ErrCreated {
		return fmt.Errorf("could not open blobkeys database: %v", err)
	}

	// no need to lock since we are reading only
	var key [32]byte
	for k, v := range kdb.Records("") {
		keyb, err := hex.DecodeString(v)
		if err != nil {
			// should not happen so complain and move on
			z.Error(idZKC, "could not hex decode blobkey: %v", k)
			continue
		}
		copy(key[:], keyb)

		decrypted, err := blobshare.Decrypt(&key, nonce, encrypted)
		if err != nil {
			// wrong key, moving on
			continue
		}
		z.Dbg(idZKC, "step 3 (push) got key")

		var kx rpc.KX
		br := bytes.NewReader(decrypted)
		_, err = xdr.Unmarshal(br, &kx)
		if err != nil {
			return fmt.Errorf("could not unmarshal KX")
		}

		z.ratchetMtx.Lock()

		// get half ratchet
		r, err := z.loadRatchet(p.From, true)
		if err != nil {
			z.ratchetMtx.Unlock()
			return fmt.Errorf("could not load ratchet: %v", err)
		}

		// complete idkx
		err = r.CompleteKeyExchange(&kx.KX, true)
		if err != nil {
			z.ratchetMtx.Unlock()
			return fmt.Errorf("could not complete key exchange: %v",
				err)
		}

		// save full ratchet to disk
		err = z.updateRatchet(r, false)
		if err != nil {
			z.ratchetMtx.Unlock()
			return fmt.Errorf("could not save ratchet kx %v", err)
		}

		// remove half ratchet
		err = z.removeRatchet(p.From, true)
		if err != nil {
			z.ratchetMtx.Unlock()
			return fmt.Errorf("could not remove half ratchet kx %v",
				err)
		}
		z.ratchetMtx.Unlock()

		// sanity
		id, err := z.loadIdentity(p.From)
		if err != nil {
			return fmt.Errorf("could not obtain identity "+
				"record: %v", err)
		}
		if !bytes.Equal(p.From[:], id.Identity[:]) {
			return fmt.Errorf("identities don't match")
		}

		err = z.addressBookAdd(*id)
		if err != nil {
			return fmt.Errorf("could not add to address "+
				"book: %v", err)
		}

		z.printKX(id)

		z.Dbg(idZKC, "step 3 (push) idkx complete %v",
			hex.EncodeToString(p.From[:]))

		return nil
	}

	z.Dbg(idZKC, "kx step 3: unknown blobkey %x", p.From)
	nick := hex.EncodeToString(p.From[:])
	id, err := z.ab.FindIdentity(p.From)
	if err == nil {
		nick = id.Nick
	}
	return fmt.Errorf("kx step 3 not complete with: %v", nick)
}

func (z *ZKC) step2IDKX(msg rpc.Message, p rpc.Push) error {
	if p.Payload == nil {
		return fmt.Errorf("server sent a message without a payload")
	}

	nonce, encrypted, err := blobshare.UnpackNonce(p.Payload)
	if err != nil {
		return fmt.Errorf("could not unpack IdentityKX")
	}

	//
	// try decrypting with all blob keys
	//

	// open db
	kdb, err := inidb.New(path.Join(z.settings.Root, blobKeysPath), true,
		10)
	if err != nil && err != inidb.ErrCreated {
		return fmt.Errorf("could not open blobkeys database: %v", err)
	}

	// no need to lock since we are reading only
	var key [32]byte
	for k, v := range kdb.Records("") {
		keyb, err := hex.DecodeString(v)
		if err != nil {
			// should not happen so complain and move on
			z.Error(idZKC, "could not hex decode blobkey: %v", k)
			continue
		}
		copy(key[:], keyb)

		decrypted, err := blobshare.Decrypt(&key, nonce, encrypted)
		if err != nil {
			// wrong key, moving on
			continue
		}

		var idkx rpc.IdentityKX
		br := bytes.NewReader(decrypted)
		_, err = xdr.Unmarshal(br, &idkx)
		if err != nil {
			return fmt.Errorf("could not unmarshal IdentityKX")
		}

		if bytes.Equal(idkx.Identity.Identity[:], z.id.Public.Identity[:]) {
			return fmt.Errorf("can't kx with self")
		}

		// create a new ratchet from idkx
		r := ratchet.New(rand.Reader)
		r.MyPrivateKey = &z.id.PrivateKey
		r.MySigningPublic = &z.id.Public.SigKey
		r.TheirIdentityPublic = &idkx.Identity.Identity
		r.TheirSigningPublic = &idkx.Identity.SigKey
		r.TheirPublicKey = &idkx.Identity.Key

		kxRatchet := new(ratchet.KeyExchange)
		err = r.FillKeyExchange(kxRatchet)
		if err != nil {
			return fmt.Errorf("could not setup ratchet key "+
				"exchange: %v", err)
		}

		// finalize ratchet
		err = r.CompleteKeyExchange(&idkx.KX, false)
		if err != nil {
			return fmt.Errorf("could not complete key exchange: %v",
				err)
		}

		// save identity and ratchet
		err = z.saveIdentity(idkx.Identity)
		if err != nil {
			return fmt.Errorf("could not save identity %v", err)
		}

		z.ratchetMtx.Lock()
		err = z.updateRatchet(r, false)
		if err != nil {
			z.ratchetMtx.Unlock()
			return fmt.Errorf("could not save ratchet kx %v", err)
		}
		z.ratchetMtx.Unlock()

		// send kxRatchet to the other end
		kx := rpc.KX{
			KX: *kxRatchet,
		}
		kxXDR := &bytes.Buffer{}
		_, err = xdr.Marshal(kxXDR, kx)
		if err != nil {
			return fmt.Errorf("could not marshal KX")
		}

		// encrypt kx
		encrypted, nonce, err := blobshare.Encrypt(kxXDR.Bytes(), &key)
		if err != nil {
			return fmt.Errorf("could not encrypt KX %v", err)
		}

		// send cache command, step 3 of idkx
		err = z.cache(idkx.Identity.Identity,
			blobshare.PackNonce(nonce, encrypted))
		if err != nil {
			return fmt.Errorf("could not send KX %v", err)
		}

		err = z.addressBookAdd(idkx.Identity)
		if err != nil {
			return fmt.Errorf("could not add to address book: %v",
				err)
		}

		z.printKX(&idkx.Identity)

		z.Dbg(idZKC, "step 2 (push) idkx complete %v",
			hex.EncodeToString(idkx.Identity.Identity[:]))

		return nil
	}

	z.Dbg(idZKC, "kx step 2: unknown blobkey %x", p.From)
	nick := hex.EncodeToString(p.From[:])
	id, err := z.ab.FindIdentity(p.From)
	if err == nil {
		nick = id.Nick
	}
	return fmt.Errorf("kx step 2 not complete with: %v", nick)
}

func (z *ZKC) step2IDKX2(msg rpc.Message, p rpc.Push) error {
	if p.Payload == nil {
		return fmt.Errorf("server sent a message without a payload")
	}
	if len(p.Payload) < sntrup4591761.CiphertextSize {
		return fmt.Errorf("server sent a short payload")
	}

	z.Log(0, "[step2IDKX]: payload = %v", p.Payload)

	c := new([sntrup4591761.CiphertextSize]byte)
	copy(c[:], p.Payload)
	k, ok := sntrup4591761.Decapsulate(c, &z.id.PrivateKey)
	if ok != 1 {
		return fmt.Errorf("could not decap key")
	}

	nonce, encrypted, err := blobshare.UnpackNonce(p.Payload[sntrup4591761.CiphertextSize:])
	if err != nil {
		return fmt.Errorf("could not unpack IdentityKX")
	}

	decrypted, err := blobshare.Decrypt(k, nonce, encrypted)
	if err != nil {
		return fmt.Errorf("could not decrypt half ratchet: %v", err)
	}

	var idkx rpc.IdentityKX
	br := bytes.NewReader(decrypted)
	_, err = xdr.Unmarshal(br, &idkx)
	if err != nil {
		return fmt.Errorf("could not unmarshal IdentityKX")
	}

	if bytes.Equal(idkx.Identity.Identity[:], z.id.Public.Identity[:]) {
		return fmt.Errorf("can't kx with self")
	}

	// create a new ratchet from idkx
	r := ratchet.New(rand.Reader)
	r.MyPrivateKey = &z.id.PrivateKey
	r.MySigningPublic = &z.id.Public.SigKey
	r.TheirIdentityPublic = &idkx.Identity.Identity
	r.TheirSigningPublic = &idkx.Identity.SigKey
	r.TheirPublicKey = &idkx.Identity.Key

	kxRatchet := new(ratchet.KeyExchange)
	err = r.FillKeyExchange(kxRatchet)
	if err != nil {
		return fmt.Errorf("could not setup ratchet kx: %v", err)
	}

	// finalize ratchet
	err = r.CompleteKeyExchange(&idkx.KX, false)
	if err != nil {
		return fmt.Errorf("could not complete kx: %v", err)
	}

	// save identity and ratchet
	err = z.saveIdentity(idkx.Identity)
	if err != nil {
		return fmt.Errorf("could not save identity %v", err)
	}

	z.ratchetMtx.Lock()
	err = z.updateRatchet(r, false)
	if err != nil {
		z.ratchetMtx.Unlock()
		return fmt.Errorf("could not save ratchet kx %v", err)
	}
	z.ratchetMtx.Unlock()

	// send kxRatchet to the other end
	kx := rpc.KX{
		KX: *kxRatchet,
	}
	kxXDR := &bytes.Buffer{}
	_, err = xdr.Marshal(kxXDR, kx)
	if err != nil {
		return fmt.Errorf("could not marshal KX")
	}

	// encrypt kx
	encrypted, nonce, err = blobshare.Encrypt(kxXDR.Bytes(), k)
	if err != nil {
		return fmt.Errorf("could not encrypt KX %v", err)
	}

	// send cache command, step 3 of idkx
	err = z.cache(idkx.Identity.Identity, blobshare.PackNonce(nonce, encrypted))
	if err != nil {
		return fmt.Errorf("could not send KX %v", err)
	}

	err = z.addressBookAdd(idkx.Identity)
	if err != nil {
		return fmt.Errorf("could not add to address book: %v", err)
	}

	z.printKX(&idkx.Identity)

	z.Dbg(idZKC, "step 2 (push) idkx complete %v", hex.EncodeToString(idkx.Identity.Identity[:]))

	return nil
}

func (z *ZKC) handlePush(msg rpc.Message, p rpc.Push) error {
	// see if identity is valid
	empty := make([]byte, 32)
	if bytes.Equal(empty, p.From[:]) {
		return fmt.Errorf("received message from invalid identity")
	}

	// See if we are a proxy push that is unencrypted. This is a special
	// command that should only be used for ratchet resets.
	if msg.Cleartext {
		var pc rpc.ProxyCmd
		brProxy := bytes.NewReader(p.Payload)
		_, err := xdr.Unmarshal(brProxy, &pc)
		if err == nil && pc.Command == rpc.ProxyCmdResetRatchet {
			// We got a ratchet reset command
			nick := z.nickFromId(p.From)
			n := nick
			if n != "" {
				n += " "
			}
			z.FloodfT(nick, REDBOLD+"Received ratchet reset "+
				"command from: %v%x"+RESET, n, p.From)
			z.FloodfT(nick, REDBOLD+"Ratchet reset message: "+
				"%v"+RESET, pc.Message)
			return z.handleResetRatchet(p.From)
		} else if err == nil {
			return fmt.Errorf("Invalid proxy command: %v",
				pc.Command)
		}
		return fmt.Errorf("Can't decode proxy command: %v", err)
	}

	// see if identity exists
	if !z.identityExists(p.From) {
		// step 2 of idkx
		z.Dbg(idZKC, "step 2 (push) idkx")
		if z.directory {
			return z.step2IDKX2(msg, p)
		} else {
			return z.step2IDKX(msg, p)
		}
	}

	// see if ratchet exists
	if !z.ratchetExists(p.From) {
		// step 3 of idkx
		z.Dbg(idZKC, "step 3 (push) idkx")
		return z.step3IDKX(msg, p)
	}

	//
	// we are in full comm mode with the other side
	//

	z.ratchetMtx.Lock()

	// get ratchet
	r, err := z.loadRatchet(p.From, false)
	if err != nil {
		z.ratchetMtx.Unlock()
		return fmt.Errorf("could not load ratchet: %v", err)
	}

	decrypted, err := r.Decrypt(p.Payload)
	if err != nil {
		z.ratchetMtx.Unlock()
		return &ratchetError{
			err: fmt.Sprintf("could not decrypt: %v", err),
		}
	}

	// update ratchet on disk
	err = z.updateRatchet(r, false)
	if err != nil {
		z.ratchetMtx.Unlock()
		return err
	}
	z.ratchetMtx.Unlock()

	// decode CRPC
	var crpc rpc.CRPC
	br := bytes.NewReader(decrypted)
	_, err = xdr.Unmarshal(br, &crpc)
	if err != nil {
		return fmt.Errorf("unmarshal crpc failed")
	}

	// decompress Payload
	var rd io.Reader
	switch crpc.Compression {
	case rpc.CRPCCompNone:
		rd = br
	case rpc.CRPCCompZLIB:
		rd, _ = zlib.NewReader(br)
	default:
		return fmt.Errorf("invalid compression: %v", crpc.Compression)
	}

	// decode Payload
	switch crpc.Command {
	case rpc.CRPCCmdPrivateMessage:
		var pm rpc.PrivateMessage
		_, err = xdr.Unmarshal(rd, &pm)
		if err != nil {
			return fmt.Errorf("unmarshal private message")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v%v",
				pm,
				spew.Sdump(msg),
				spew.Sdump(&p.From),
				spew.Sdump(pm))
		}

		return z.handlePm(msg, p, pm)

	case rpc.CRPCCmdGroupInvite:
		var gi rpc.GroupInvite
		_, err = xdr.Unmarshal(rd, &gi)
		if err != nil {
			return fmt.Errorf("unmarshal group chat invite")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v%v",
				gi,
				spew.Sdump(msg),
				spew.Sdump(&p.From),
				spew.Sdump(gi))
		}

		return z.handleGroupInvite(msg, p, gi)

	case rpc.CRPCCmdGroupJoin:
		var gj rpc.GroupJoin
		_, err = xdr.Unmarshal(rd, &gj)
		if err != nil {
			return fmt.Errorf("unmarshal group chat join")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v%v",
				gj,
				spew.Sdump(msg),
				spew.Sdump(&p.From),
				spew.Sdump(gj))
		}

		return z.handleGroupJoin(msg, p, gj)

	case rpc.CRPCCmdGroupKill:
		var gk rpc.GroupKill
		_, err = xdr.Unmarshal(rd, &gk)
		if err != nil {
			return fmt.Errorf("unmarshal group chat kill")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v%v",
				gk,
				spew.Sdump(msg),
				spew.Sdump(&p.From),
				spew.Sdump(gk))
		}

		return z.handleGroupKill(msg, p, gk)

	case rpc.CRPCCmdGroupKick:
		var gk rpc.GroupKick
		_, err = xdr.Unmarshal(rd, &gk)
		if err != nil {
			return fmt.Errorf("unmarshal group chat kick")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v%v",
				gk,
				spew.Sdump(msg),
				spew.Sdump(&p.From),
				spew.Sdump(gk))
		}

		return z.handleGroupKick(msg, p, gk)

	case rpc.CRPCCmdGroupPart:
		var gp rpc.GroupPart
		_, err = xdr.Unmarshal(rd, &gp)
		if err != nil {
			return fmt.Errorf("unmarshal group chat part")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v%v",
				gp,
				spew.Sdump(msg),
				spew.Sdump(&p.From),
				spew.Sdump(gp))
		}

		return z.handleGroupPart(msg, p, gp)

	case rpc.CRPCCmdGroupList:
		var gl rpc.GroupList
		_, err = xdr.Unmarshal(rd, &gl)
		if err != nil {
			return fmt.Errorf("unmarshal group chat list")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v%v",
				gl,
				spew.Sdump(msg),
				spew.Sdump(&p.From),
				spew.Sdump(gl))
		}

		return z.handleGroupList(msg, p, gl)

	case rpc.CRPCCmdGroupMessage:
		var gm rpc.GroupMessage
		_, err = xdr.Unmarshal(rd, &gm)
		if err != nil {
			return fmt.Errorf("unmarshal group chat message")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v%v",
				gm,
				spew.Sdump(msg),
				spew.Sdump(&p.From),
				spew.Sdump(gm))
		}

		return z.handleGroupMessage(msg, p, gm)

	case rpc.CRPCCmdChunkNew:
		var cn rpc.ChunkNew
		_, err = xdr.Unmarshal(rd, &cn)
		if err != nil {
			return fmt.Errorf("unmarshal chunk new")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v%v",
				cn,
				spew.Sdump(msg),
				spew.Sdump(&p.From),
				spew.Sdump(cn))
		}

		return z.handleChunkNew(msg, p, cn)

	case rpc.CRPCCmdChunk:
		var c rpc.Chunk
		_, err = xdr.Unmarshal(rd, &c)
		if err != nil {
			return fmt.Errorf("unmarshal chunk")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v",
				c,
				spew.Sdump(msg),
				spew.Sdump(&p.From))
		}

		return z.handleChunk(msg, p, c)

	case rpc.CRPCCmdJanitorMessage:
		var jm rpc.JanitorMessage
		_, err = xdr.Unmarshal(rd, &jm)
		if err != nil {
			return fmt.Errorf("unmarshal janitor message")
		}
		if z.settings.Debug {
			z.Dbg(idZKC, "%T%v%v",
				jm,
				spew.Sdump(msg),
				spew.Sdump(&p.From))
		}

		return z.handleJanitorMessage(msg, p, jm)

	default:
		return fmt.Errorf("invalid push command: %v", crpc.Command)
	}

	// not reached
}

func (z *ZKC) handlePm(msg rpc.Message, p rpc.Push,
	pm rpc.PrivateMessage) error {

	c, win, err := z.getConversation(p.From)
	if err != nil {
		return fmt.Errorf("unknown conversation: %v", err)
	}

	var n string
	if pm.Mode == rpc.MessageModeMe {
		n = fmt.Sprintf("* %v", z.settings.PmColor+c.nick+RESET)
	} else {
		n = fmt.Sprintf("<%v>", z.settings.PmColor+c.nick+RESET)
	}
	z.PrintfTS(win, time.Unix(p.Received, 0), "%v %v", n, pm.Text)

	// annoy people
	if z.settings.Beep {
		fmt.Printf("\a")
	}

	// reply to tag
	return nil
}

func (z *ZKC) handleGroupInvite(msg rpc.Message, p rpc.Push,
	gi rpc.GroupInvite) error {

	id, err := z.ab.FindIdentity(p.From)
	if err != nil {
		z.PrintfT(0, "invite from unknown identity: %v",
			hex.EncodeToString(p.From[:]))
		return nil
	}

	// add invite to join database
	err = z.joinDBAdd(p.From, gi)
	if err != nil {
		z.PrintfT(0, "could not join %v: %v",
			gi.Name, err)
		return nil
	}

	z.PrintfT(0, "%v invited you to group chat: %v %v",
		z.settings.PmColor+id.Nick+RESET,
		z.settings.GcColor+gi.Name+RESET,
		gi.Description)
	z.PrintfT(0, "group chat participants:")
	for i := range gi.Members {
		id, err := z.ab.FindNick(gi.Members[i])
		if err != nil {
			z.PrintfT(0, "handleGroupInvite: "+
				"FindNick: %v (?): %v", gi.Members[i], err)
			err = z.find(gi.Members[i])
			if err != nil {
				z.PrintfT(0, "handleGroupInvite: "+
					"find: %v (?): %v", gi.Members[i], err)
			}
		} else {
			z.PrintfT(0, "%v (%v)", gi.Members[i], id.Fingerprint())
		}
	}
	z.PrintfT(0, "To accept type /gc join %v %v",
		gi.Name, gi.Token)

	return nil
}

func (z *ZKC) handleGroupJoin(msg rpc.Message, p rpc.Push,
	gj rpc.GroupJoin) error {

	// check we are admin is us
	z.Lock()
	defer z.Unlock()

	gc, found := z.groups[gj.Name]
	if !found {
		return fmt.Errorf("group chat not found: %v", gj.Name)
	}
	ogc := gc // save in case of unwind

	if len(gc.Members) == 0 {
		return fmt.Errorf("group chat invalid: %v", gj.Name)
	}

	// make sure we are list administrator
	if !bytes.Equal(gc.Members[0][:], z.id.Public.Identity[:]) {
		return fmt.Errorf("not group chat administrator")
	}

	// check if we had send this user an invite
	err := z.delInvite(p.From, gj)
	if err != nil {
		return fmt.Errorf("join failed: %v", err)
	}

	id, err := z.ab.FindIdentity(p.From)
	if err != nil {
		return fmt.Errorf("received join from unknown identity: %v",
			hex.EncodeToString(p.From[:]))
	}

	// add new member and increment Generation
	gc, err = z._addIdGroupchat(gj.Name, *id)
	if err != nil {
		return fmt.Errorf("could not add identity to group chat: %v",
			err)
	}

	// send everyone the new group list, skip [0], it is us
	gc.Generation++
	z.groups[gj.Name] = gc
	// save to disk
	err = z._gcSaveDisk(gj.Name)
	if err != nil {
		z.groups[gj.Name] = ogc // unwind
		return fmt.Errorf("could not save group chat %v: %v", gj.Name, err)
	}

	// send to everyone
	for i := 1; i < len(gc.Members); i++ {
		z.scheduleCRPC(true, &gc.Members[i], gc)
	}

	z.PrintfT(0, "%v joined group chat: %v",
		z.settings.PmColor+id.Nick+RESET,
		z.settings.GcColor+gj.Name+RESET)
	// echo on conversation window
	for k, v := range z.conversation {
		if v.id.Nick == gj.Name {
			z.PrintfTS(k, time.Unix(p.Received, 0),
				"%v joined group chat",
				id.Nick)
			break
		}
	}

	return nil
}

func (z *ZKC) handleGroupPart(msg rpc.Message, p rpc.Push,
	gp rpc.GroupPart) error {

	z.Lock()
	defer z.Unlock()

	gc, found := z.groups[gp.Name]
	if !found {
		return fmt.Errorf("group chat not found during part: %v",
			gp.Name)
	}

	if len(gc.Members) == 0 {
		return fmt.Errorf("handleGroupPart: group chat corrupt")
	}

	// make sure we got this from list administrator
	if !bytes.Equal(gc.Members[0][:], z.id.Public.Identity[:]) {
		return fmt.Errorf("part may only be sent to group chat " +
			"administrator")
	}

	var nick string
	for i := 1; i < len(gc.Members); i++ {
		if !bytes.Equal(gc.Members[i][:], p.From[:]) {
			continue
		}

		// remove from member list
		ngc := rpc.GroupList{
			Name:       gc.Name,
			Generation: gc.Generation + 1,
			Timestamp:  time.Now().Unix(),
			Members:    append(gc.Members[:i:i], gc.Members[i+1:]...),
		}

		// send new list to everyone including partee
		for j := 1; j < len(gc.Members); j++ {
			z.scheduleCRPC(true, &gc.Members[j], rpc.GroupKick{
				Member:       p.From,
				Reason:       gp.Reason,
				Parted:       true,
				NewGroupList: ngc,
			})
		}

		// set new group in memory
		z.groups[gp.Name] = ngc

		// save to disk
		err := z._gcSaveDisk(gp.Name)
		if err != nil {
			return fmt.Errorf("could not save group chat to disk %v: %v",
				gp.Name, err)
		}

		id, err := z.ab.FindIdentity(p.From)
		if err != nil {
			return fmt.Errorf("received join from unknown identity: %v",
				hex.EncodeToString(p.From[:]))
		}
		z.PrintfT(0, "%v left group chat %v: %v",
			z.settings.PmColor+id.Nick+RESET,
			z.settings.GcColor+gp.Name+RESET,
			gp.Reason)

		// echo on conversation window
		for k, v := range z.conversation {
			if v.id.Nick == gp.Name {
				z.PrintfT(k, "%v left group chat: %v",
					z.settings.PmColor+nick+RESET,
					gp.Reason)
				break
			}
		}

		return nil
	}

	return fmt.Errorf("not part of group chat: %v", nick)
}

func (z *ZKC) handleGroupKick(msg rpc.Message, p rpc.Push,
	gk rpc.GroupKick) error {
	z.Lock()
	defer z.Unlock()

	z.Dbg(idZKC, "handleGroupKick: %v", gk.NewGroupList.Name)

	group, found := z.groups[gk.NewGroupList.Name]
	if !found {
		return fmt.Errorf("group chat not found during kick/part: %v",
			gk.NewGroupList.Name)
	}

	// sanity
	if len(group.Members) == 0 {
		return fmt.Errorf("handleGroupKick: group chat corrupt")
	}

	// make sure we got this from list administrator
	if !bytes.Equal(group.Members[0][:], p.From[:]) {
		return fmt.Errorf("kick/part was not sent by group chat " +
			"administrator")
	}

	if bytes.Equal(gk.Member[:], z.id.Public.Identity[:]) {
		if gk.Parted {
			z.PrintfTS(0, time.Unix(p.Received, 0),
				"left group chat %v: %v",
				z.settings.GcColor+gk.NewGroupList.Name+RESET,
				gk.Reason)
		} else {
			z.PrintfTS(0, time.Unix(p.Received, 0),
				REDBOLD+"you were kicked of group chat %v: %v"+RESET,
				gk.NewGroupList.Name,
				gk.Reason)
		}

		// echo on conversation window
		for k, v := range z.conversation {
			if v.id.Nick == gk.NewGroupList.Name {
				if gk.Parted {
					z.PrintfTS(k, time.Unix(p.Received, 0),
						"left group chat: %v",
						gk.Reason)
				} else {
					z.PrintfTS(k, time.Unix(p.Received, 0),
						REDBOLD+"you were kicked of "+
							"group chat: %v"+RESET,
						gk.Reason)
				}
				break
			}
		}

		return z._deleteGroup(gk.NewGroupList.Name)
	}

	nick := hex.EncodeToString(gk.Member[:])
	id, err := z.ab.FindIdentity(gk.Member)
	if err == nil {
		nick = id.Nick
	}

	if gk.Parted {
		z.PrintfTS(0, time.Unix(p.Received, 0), "%v left group chat %v: %v",
			z.settings.PmColor+nick+RESET,
			z.settings.GcColor+gk.NewGroupList.Name+RESET,
			gk.Reason)
	} else {
		z.PrintfTS(0, time.Unix(p.Received, 0),
			"%v was kicked of group chat %v: %v",
			z.settings.PmColor+nick+RESET,
			z.settings.GcColor+gk.NewGroupList.Name+RESET,
			gk.Reason)
	}

	// echo on conversation window
	for k, v := range z.conversation {
		if v.id.Nick == gk.NewGroupList.Name {
			if gk.Parted {
				z.PrintfTS(k, time.Unix(p.Received, 0),
					"%v left group chat %v",
					z.settings.PmColor+nick+RESET,
					gk.Reason)
			} else {
				z.PrintfTS(k, time.Unix(p.Received, 0),
					"%v was kicked of group chat %v",
					z.settings.PmColor+nick+RESET,
					gk.Reason)
			}
			break
		}
	}

	return z._updateGroupList(p.From, gk.NewGroupList)
}

func (z *ZKC) handleGroupKill(msg rpc.Message, p rpc.Push,
	gk rpc.GroupKill) error {
	z.Lock()
	defer z.Unlock()

	group, found := z.groups[gk.Name]
	if !found {
		return fmt.Errorf("group chat not found: %v", gk.Name)
	}

	if !bytes.Equal(group.Members[0][:], p.From[:]) {
		return fmt.Errorf("spoofed group chat kill command")
	}

	err := z._deleteGroup(gk.Name)
	if err != nil {
		return fmt.Errorf("could not kill group chat %v: %v",
			gk.Name, err)
	}

	z.PrintfT(0, "group chat killed: %v", z.settings.GcColor+gk.Name+RESET)

	// echo on conversation window
	for k, v := range z.conversation {
		if v.id.Nick == gk.Name {
			z.PrintfTS(k, time.Unix(p.Received, 0),
				REDBOLD+"group chat killed"+RESET)
			break
		}
	}

	return nil
}

func (z *ZKC) diffGroupList(ng rpc.GroupList) ([][zkidentity.IdentitySize]byte,
	[][zkidentity.IdentitySize]byte, error) {

	z.RLock()
	defer z.RUnlock()

	og, found := z.groups[ng.Name]
	if !found {
		return nil, nil, fmt.Errorf("diff unknown group chat: %v",
			ng.Name)
	}

	// minus
	min := make([][zkidentity.IdentitySize]byte, 0, len(og.Members))
	for _, ov := range og.Members {
		for _, nv := range ng.Members {
			if bytes.Equal(ov[:], nv[:]) {
				goto skipmin
			}
		}
		min = append(min, ov)
	skipmin:
	}

	// plus
	plus := make([][zkidentity.IdentitySize]byte, 0, len(ng.Members))
	for _, nv := range ng.Members {
		for _, ov := range og.Members {
			if bytes.Equal(nv[:], ov[:]) {
				goto skipplus
			}
		}
		plus = append(plus, nv)
	skipplus:
	}

	return min, plus, nil
}

func (z *ZKC) diffGroupListPrint(ng rpc.GroupList) {
	min, plus, err := z.diffGroupList(ng)
	if err != nil {
		return
	}

	for _, v := range min {
		if bytes.Equal(v[:], z.id.Public.Identity[:]) {
			// self
			z.PrintfT(0, "- %v %v (self)",
				z.id.Public.Fingerprint(),
				z.settings.PmColor+z.id.Public.Nick+RESET)
			continue
		}
		id, err := z.ab.FindIdentity(v)
		if err != nil {
			z.PrintfT(0, "- UNKNOWN %x", v)
			continue
		}
		z.PrintfT(0, "- %v %v",
			id.Fingerprint(),
			z.settings.PmColor+id.Nick+RESET)
	}

	for _, v := range plus {
		if bytes.Equal(v[:], z.id.Public.Identity[:]) {
			// self
			z.PrintfT(0, "+ %v %v (self)",
				z.id.Public.Fingerprint(),
				z.settings.PmColor+z.id.Public.Nick+RESET)
			continue
		}
		id, err := z.ab.FindIdentity(v)
		if err != nil {
			z.PrintfT(0, "+ UNKNOWN %x", v)
			continue
		}
		z.PrintfT(0, "+ %v %v",
			id.Fingerprint(),
			z.settings.PmColor+id.Nick+RESET)
	}
}

func (z *ZKC) warnGroupListMissingKeys(print bool, gl rpc.GroupList) error {
	var err error
	first := true

	for _, v := range gl.Members {
		if bytes.Equal(v[:], z.id.Public.Identity[:]) {
			continue
		}
		_, err = z.ab.FindIdentity(v)
		if err == nil {
			continue
		}
		err = fmt.Errorf("unknown identity")
		if print {
			if first {
				z.PrintfT(0, "Unknown identities in group "+
					"chat: %v", z.settings.GcColor+gl.Name+RESET)
				first = false
			}
			z.PrintfT(0, "    %v %x", zkidentity.Fingerprint(v), v)
		}
	}

	return err
}

func (z *ZKC) handleGroupList(msg rpc.Message, p rpc.Push,
	gl rpc.GroupList) error {

	z.PrintfT(0, "Received new group chat list (%v): %v",
		gl.Generation,
		z.settings.GcColor+gl.Name+RESET)
	// print diff
	z.diffGroupListPrint(gl)

	// warn about missing keys
	err := z.warnGroupListMissingKeys(true, gl)
	if err != nil {
		z.PrintfT(0, "could not warn about missing keys: %v", err)
	}

	// update grouplist
	err = z.updateGroupList(p.From, gl)
	if err != nil {
		z.PrintfT(0, "could not update group chat list: %v %v"+
			z.settings.GcColor+gl.Name+RESET,
			err)
	}

	return nil
}

func (z *ZKC) handleGroupMessage(msg rpc.Message, p rpc.Push,
	gm rpc.GroupMessage) error {

	z.Lock()

	// generation check here to see if message was sent with the correct
	// generation of the groupchat list
	gc, found := z.groups[gm.Name]
	if !found {
		z.Unlock()
		return fmt.Errorf("handleGroupMessage: group chat not found: %v",
			gm.Name)
	}
	if gc.Generation != gm.Generation {
		z.Unlock()
		return fmt.Errorf("invalid generation (%v != %v) group chat %v",
			gc.Generation, gm.Generation, gm.Name)
	}
	z.Unlock()

	// now create chat window
	c, win, err := z.groupConversation(gm.Name)
	if err != nil {
		return fmt.Errorf("handleGroupMessage: %v", err)
	}

	// calculate nick
	nick := hex.EncodeToString(p.From[:])
	id, err := z.ab.FindIdentity(p.From)
	if err == nil {
		nick = id.Nick
	}

	// see if we were mentioned
	s := gm.Message
	if x := strings.Index(strings.ToUpper(gm.Message),
		strings.ToUpper(z.id.Public.Nick)); x != -1 &&
		gm.Mode == rpc.MessageModeNormal {

		z.Lock()
		if z.active != win {
			c.mentioned = true
		}
		z.Unlock()

		// color me brah
		s = gm.Message[:x] + MAGENTABOLD +
			gm.Message[x:x+len(z.id.Public.Nick)] + RESET +
			gm.Message[x+len(z.id.Public.Nick):]

	}

	var n string
	if gm.Mode == rpc.MessageModeMe {
		n = fmt.Sprintf("* %v", z.settings.GcColor+nick+RESET)
	} else {
		n = fmt.Sprintf("<%v>", z.settings.GcColor+nick+RESET)
	}
	z.PrintfTS(win, time.Unix(p.Received, 0), "%v %v", n, s)

	// annoy people
	if z.settings.Beep {
		fmt.Printf("\a")
	}

	// reply to tag
	return nil
}
