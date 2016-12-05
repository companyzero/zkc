// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"io"

	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-xdr/xdr2"
)

func tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		InsecureSkipVerify: true,
	}
}

// kx echanges keys with zkserver
func (mw *mainWindow) kx(conn io.ReadWriteCloser) error {
	// tell remote we want kx
	_, err := xdr.Marshal(conn, rpc.InitialCmdIdentify)
	if err != nil {
		return err
	}

	// write local public identity
	_, err = xdr.Marshal(conn, mw.zkc.id.Public)
	if err != nil {
		return err
	}

	// read remote public identity
	var remoteId zkidentity.PublicIdentity
	_, err = xdr.Unmarshal(conn, &remoteId)
	if err != nil {
		return err
	}

	// handle trust
	//err = handleTrust(remoteId)
	//if err != nil {
	//	// printing has happened
	//	return err
	//}

	return nil
}

// dial zkserver.
func (mw *mainWindow) dial(host, fingerprint string) error {
	var (
		tr  zkidentity.PublicIdentity
		err error
	)

	// see if fingerprint exists before dialing
	if fingerprint != "" {
		_ = tr
		//tr, err = mw.trustDB.Get(fingerprint)
		//if err != nil {
		//	return fmt.Errorf("fingerprint not found: %v", fingerprint)
		//}
	}

	// dial remote
	conn, err := tls.Dial("tcp", host, tlsConfig())
	if err != nil {
		return err
	}

	// check if we were instructed to exchange keys
	if fingerprint == "" {
		defer conn.Close() // always close after kx
		return mw.kx(conn)
	}

	// go full session
	_, err = xdr.Marshal(conn, rpc.InitialCmdSession)
	if err != nil {
		conn.Close()
		return err
	}

	return nil
}
