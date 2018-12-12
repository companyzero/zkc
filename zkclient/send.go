// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"

	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/mitchellh/go-homedir"
)

// FileMIME returns a file's MIME type.
func FileMIME(f *os.File) (string, error) {
	// store location
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", err
	}

	// determine mime
	b := make([]byte, 512) // all that's needed for mime per doco
	_, err = f.Read(b)
	if err != nil {
		return "", err
	}

	// reset file pointer
	_, err = f.Seek(pos, io.SeekStart)
	if err != nil {
		return "", err
	}

	return http.DetectContentType(b), nil
}

func (z *ZKC) send(id [zkidentity.IdentitySize]byte, nick, filename,
	desc string) error {

	// verify file is there
	var err error
	filename, err = homedir.Expand(filename)
	if err != nil {
		return err
	}

	f, err := os.Open(filename)
	if err != nil {
		return err
	}

	// check upload size
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("could not stat %v: %v", filename, err)
	}
	if uint64(fi.Size()) > z.attachmentSize {
		return fmt.Errorf("file too large %v: %v, max allowed %v",
			filename, fi.Size(), z.attachmentSize)
	}

	// obtain mime
	mime, err := FileMIME(f)
	if err != nil {
		f.Close()
		return fmt.Errorf("could not obtain mime type %v: %v",
			filename, err)
	}

	// create new transfer so that we can resume
	// XXX

	// start assembling rpc
	cn := rpc.ChunkNew{
		Size:        uint64(fi.Size()),
		ChunkSize:   z.chunkSize,
		Filename:    path.Base(filename),
		Description: desc,
		MIME:        mime,
	}

	// finish in the background
	go z.completeSend(nick, f, id, &cn)

	return nil
}

// XXX should echo errors to conversation window as well
func (z *ZKC) completeSend(nick string, f *os.File,
	id [zkidentity.IdentitySize]byte, cn *rpc.ChunkNew) {

	defer f.Close()

	// get digest
	h := sha256.New()
	_, err := io.Copy(h, f)
	if err != nil {
		z.PrintfT(0, "send failed (%v->%v): digest %v",
			cn.Filename,
			nick,
			err)
		return
	}
	copy(cn.Digest[:], h.Sum(nil))

	// rewind
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		z.PrintfT(0, "send failed (%v->%v): seek %v",
			cn.Filename,
			nick,
			err)
		return
	}

	// reason to believe we are going to be successful so send chunk rpc
	z.scheduleCRPC(true, &id, *cn)

	// start chunking file
	for offset := 0; ; {
		chunk := make([]byte, z.chunkSize)
		count, err := f.Read(chunk)
		if err != nil {
			if err == io.EOF {
				break
			}
			z.PrintfT(0, "send failed (%v->%v): chunk read %v",
				cn.Filename,
				nick,
				err)
			return
		}
		chunk = chunk[:count]

		// setup chunk rpc
		c := rpc.Chunk{
			Offset:  uint64(offset),
			Payload: chunk,
		}
		copy(c.Digest[:], h.Sum(nil))

		// and send it
		z.scheduleCRPC(false, &id, c) // should block

		offset += count
	}

	z.FloodfT(nick, "Send completed: %v->%v", cn.Filename, nick)
}
