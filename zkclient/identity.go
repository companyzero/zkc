// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/companyzero/zkc/ratchet"
	"github.com/companyzero/zkc/ratchet/disk"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-xdr/xdr2"
)

const (
	ratchetFilename     = "ratchet.xdr"
	halfRatchetFilename = "halfratchet.xdr"
	identityFilename    = "publicidentity.xdr"
)

// identityExists checks to see if identityFilename exists in the id directory.
// Any ratchet file must exist as well for this to return true.
func (z *ZKC) identityExists(id [zkidentity.IdentitySize]byte) bool {
	_, err := os.Stat(path.Join(z.settings.Root, inboundDir,
		hex.EncodeToString(id[:]), identityFilename))
	if err == nil {
		ids := hex.EncodeToString(id[:])
		fullPath := path.Join(z.settings.Root, inboundDir, ids)
		_, err1 := os.Stat(path.Join(fullPath, ratchetFilename))
		_, err2 := os.Stat(path.Join(fullPath, halfRatchetFilename))
		if err1 == nil || err2 == nil {
			return true
		}

		// this happens during reset condiftion
		z.Dbg(idZKC, "identityExists: reset condition")
		return false
	}

	return false
}

// ratchetExists checks to see if ratchetFilename exists in the id directory.
func (z *ZKC) ratchetExists(id [zkidentity.IdentitySize]byte) bool {
	_, err := os.Stat(path.Join(z.settings.Root, inboundDir,
		hex.EncodeToString(id[:]), ratchetFilename))
	return err == nil
}

func (z *ZKC) removeRatchet(id [zkidentity.IdentitySize]byte, half bool) error {
	var rf string
	if half {
		rf = halfRatchetFilename
	} else {
		rf = ratchetFilename
	}

	ids := hex.EncodeToString(id[:])
	fullPath := path.Join(z.settings.Root, inboundDir, ids)

	return os.Remove(path.Join(fullPath, rf))
}

func (z *ZKC) loadRatchet(id [zkidentity.IdentitySize]byte,
	half bool) (*ratchet.Ratchet, error) {

	//z.Dbg(idZKC, "loadRatchet: start")
	//defer z.Dbg(idZKC, "loadRatchet: end")

	var rf string
	if half {
		rf = halfRatchetFilename
	} else {
		rf = ratchetFilename
	}

	ids := hex.EncodeToString(id[:])
	fullPath := path.Join(z.settings.Root, inboundDir, ids)

	// read ratchet from disk
	ratchetXDR, err := ioutil.ReadFile(path.Join(fullPath, rf))
	if err != nil {
		return nil, fmt.Errorf("ReadFile ratchet: %v", err)
	}

	var rs disk.RatchetState
	br := bytes.NewReader(ratchetXDR)
	_, err = xdr.Unmarshal(br, &rs)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal RatchetState")
	}

	// recreate ratchet
	r := ratchet.New(rand.Reader)
	err = r.Unmarshal(&rs)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal Ratchet")
	}

	// read identity from disk
	idXDR, err := ioutil.ReadFile(path.Join(fullPath, identityFilename))
	if err != nil {
		return nil, fmt.Errorf("ReadFile identity: %v", err)
	}
	var idDisk zkidentity.PublicIdentity
	br = bytes.NewReader(idXDR)
	_, err = xdr.Unmarshal(br, &idDisk)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal public identity %v",
			ids)
	}

	// XXX verify this
	r.MyPrivateKey = &z.id.PrivateKey
	r.MySigningPublic = &z.id.Public.SigKey
	r.TheirIdentityPublic = &idDisk.Identity
	r.TheirSigningPublic = &idDisk.SigKey
	r.TheirPublicKey = &idDisk.Key

	return r, nil
}

func (z *ZKC) updateRatchet(r *ratchet.Ratchet, half bool) error {
	state := r.Marshal(time.Now(), 31*24*time.Hour)

	z.Dbg(idZKC, "updateRatchet: start")
	defer z.Dbg(idZKC, "updateRatchet: end")

	var rf string
	if half {
		rf = halfRatchetFilename
	} else {
		rf = ratchetFilename
	}
	z.Dbg(idZKC, "updateRatchet: %v", rf)

	// save to tempfile
	ids := hex.EncodeToString(r.TheirIdentityPublic[:])
	fullPath := path.Join(z.settings.Root, inboundDir, ids)
	f, err := ioutil.TempFile(fullPath, rf)
	if err != nil {
		return fmt.Errorf("could not create ratchet file: %v", err)
	}
	// we can't defer f.Close() here because of windows

	_, err = xdr.Marshal(f, state)
	if err != nil {
		f.Close()
		return fmt.Errorf("could not marshal ratchet")
	}
	f.Sync()
	f.Close()

	// rename tempfile to actual file
	filename := path.Join(fullPath, rf)
	err = os.Rename(f.Name(), filename)
	if err != nil {
		return fmt.Errorf("could not rename ratchet file: %v", err)
	}

	return nil
}

func (z *ZKC) loadIdentity(id [zkidentity.IdentitySize]byte) (*zkidentity.PublicIdentity,
	error) {
	ids := hex.EncodeToString(id[:])

	fullPath := path.Join(z.settings.Root, inboundDir, ids)
	filename := path.Join(fullPath, identityFilename)

	blob, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	idr, err := zkidentity.UnmarshalPublicIdentity(blob)
	if err != nil {
		return nil, err
	}

	return idr, nil
}

func (z *ZKC) saveIdentity(id zkidentity.PublicIdentity) error {
	// see if identity exists
	if z.identityExists(id.Identity) {
		return fmt.Errorf("identity already exists")
	}

	// make identity dirs
	ids := hex.EncodeToString(id.Identity[:])
	fullPath := path.Join(z.settings.Root, inboundDir, ids)
	err := os.MkdirAll(fullPath, 0700)
	if err != nil {
		return err
	}

	// save identity
	pidXDR, err := id.Marshal()
	if err != nil {
		return fmt.Errorf("marshal public identity")
	}
	filename := path.Join(fullPath, identityFilename)
	err = ioutil.WriteFile(filename, pidXDR, 0600)
	if err != nil {
		return fmt.Errorf("write to %v: %v", filename, err)
	}

	return nil
}
