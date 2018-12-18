// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path"

	"github.com/companyzero/zkc/rpc"
	"github.com/davecgh/go-xdr/xdr2"
	"github.com/marcopeereboom/goutil"
)

const descriptor = "descriptor.xdr"

func (z *ZKC) handleChunkNew(msg rpc.Message, p rpc.Push,
	cn rpc.ChunkNew) error {

	err := z.doHandleChunkNew(msg, p, cn)
	if err != nil {
		z.PrintfT(0, REDBOLD+"doHandleChunkNew: %v"+RESET, err)
	}

	return nil
}

func (z *ZKC) doHandleChunkNew(msg rpc.Message, p rpc.Push,
	cn rpc.ChunkNew) error {

	// create landing zone
	dir := path.Join(z.settings.Root, spoolDir,
		hex.EncodeToString(p.From[:]))
	spool := path.Join(dir, hex.EncodeToString(cn.Digest[:]))
	desc := path.Join(dir, descriptor)
	os.MkdirAll(dir, 0700)

	// write out encoded chunk information
	f, err := os.Create(desc)
	if err != nil {
		return err
	}
	defer f.Close()
	e := xdr.NewEncoder(f)
	if err != nil {
		return err
	}
	_, err = e.Encode(cn)
	if err != nil {
		return err
	}

	// create empty spool
	fs, err := os.Create(spool)
	if err != nil {
		return err
	}
	defer fs.Close()

	// nick
	pid, err := z.ab.FindIdentity(p.From)
	if err != nil {
		return err
	}
	// notify user a file transfer is in flight
	z.FloodfT(pid.Nick, "File transfer initiated by: %v filename: %v "+
		"size: %v description: %v",
		pid.Nick, cn.Filename, cn.Size, cn.Description)

	return nil
}

func (z *ZKC) handleChunk(msg rpc.Message, p rpc.Push,
	c rpc.Chunk) error {

	err := z.doHandleChunk(msg, p, c)
	if err != nil {
		z.PrintfT(0, REDBOLD+"doHandleChunk: %v"+RESET, err)
	}

	return nil
}

func (z *ZKC) doHandleChunk(msg rpc.Message, p rpc.Push,
	c rpc.Chunk) error {

	dir := path.Join(z.settings.Root, spoolDir,
		hex.EncodeToString(p.From[:]))
	spool := path.Join(dir, hex.EncodeToString(c.Digest[:]))
	desc := path.Join(dir, descriptor)

	// open spool
	fs, err := os.OpenFile(spool, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}

	// validate offset
	fi, err := fs.Stat()
	if err != nil {
		fs.Close()
		return err
	}
	if fi.Size() != int64(c.Offset) {
		fs.Close()
		return fmt.Errorf("unexpected offset got %v wanted %v",
			fi.Size(), c.Offset)
	}

	// write payload
	_, err = fs.Write(c.Payload)
	if err != nil {
		return err
	}

	// update fi
	fi, err = fs.Stat()
	if err != nil {
		fs.Close()
		return err
	}
	fs.Close() // windows

	// determine if this is the last chunk
	f, err := os.Open(desc)
	if err != nil {
		return err
	}
	defer f.Close()

	d := xdr.NewDecoder(f)
	var cn rpc.ChunkNew
	_, err = d.Decode(&cn)
	if err != nil {
		return err
	}

	// check sizes
	if fi.Size() == int64(cn.Size) {
		// nick
		pid, err := z.ab.FindIdentity(p.From)
		if err != nil {
			return err
		}

		// assembly complete, check digest and move into place
		fd, err := goutil.FileSHA256(spool)
		if err != nil {
			return fmt.Errorf("could not digest %v: %v",
				spool, err)
		}
		if !bytes.Equal(fd[:], cn.Digest[:]) {
			return fmt.Errorf("Incoming file from %v corrupt: %v",
				pid.Nick, cn.Filename)
		}

		var fullpath, filename string
		filename = cn.Filename
		for {
			fullpath = path.Join(z.settings.Root, spoolDir,
				filename)
			_, err = os.Stat(fullpath)
			if err != nil {
				break
			}
			filename = "1" + filename
		}

		err = os.Rename(spool, fullpath)
		if err != nil {
			return err
		}

		z.FloodfT(pid.Nick, "File transfer complete from: %v type: %v "+
			"saved to: %v",
			pid.Nick,
			cn.MIME,
			fullpath)

		// annoy people
		if z.settings.Beep {
			fmt.Printf("\a")
		}

		// cleanup
		os.Remove(desc)
	}

	return nil
}
