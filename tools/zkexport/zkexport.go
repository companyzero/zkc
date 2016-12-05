// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC license that can be
// found in the LICENSE file.
//
// zkexport writes the base64-encoded public identity of a zkc server
// (zkserver) or client (zkclient) on stdout.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/companyzero/zkc/inidb"
	"github.com/companyzero/zkc/tools"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/companyzero/zkc/zkserver/settings"
	"github.com/companyzero/zkc/zkutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/davecgh/go-xdr/xdr2"
)

var (
	errNotFound = errors.New("not found")
)

// fetchServerFullIdentity() fetches a server's signed identity data.
func fetchServerFullIdentity(root string) (*zkidentity.FullIdentity, error) {
	id, err := ioutil.ReadFile(path.Join(root, tools.ZKSIdentityFilename))
	if err != nil {
		return nil, fmt.Errorf("could not read identity: %v", err)
	}
	return zkidentity.UnmarshalFullIdentity(id)
}

// fetchServerCert() fetches a server's key and corresponding
// certificate.
func fetchServerCert(root string) (tls.Certificate, error) {
	certPath := path.Join(root, tools.ZKSCertFilename)
	keyPath := path.Join(root, tools.ZKSKeyFilename)
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func fetchServerIPandPort(root string) string {
	var err error
	if root == "" {
		root, err = zkutil.DefaultServerRootPath()
		if err != nil {
			return ""
		}
	}
	serverConf := path.Join(root, "zkserver.conf")
	s := settings.New()
	s.Listen = ""
	err = s.Load(serverConf)
	if err != nil {
		return ""
	}
	return s.Listen
}

// fetchServerRecord() fetches a server record residing in 'root', if
// specified, or from zkserver's default root directory.
func fetchServerRecord(root, ipAndPort string) (*tools.ServerRecord, error) {
	cert, err := fetchServerCert(root)
	if err != nil {
		return nil, err
	}
	fi, err := fetchServerFullIdentity(root)
	if err != nil {
		return nil, err
	}
	if ipAndPort == "" {
		ipAndPort = fetchServerIPandPort(root)
		if ipAndPort == "" {
			return nil, fmt.Errorf("could not obtain server ip. " +
			    "please add it to the config file or provide it " +
			    "on the command line (option -i)")
		}
	}
	pr := tools.ServerRecord{
		PublicIdentity: fi.Public,
		Certificate:    cert.Certificate[0],
		IPandPort:	[]byte(ipAndPort),
	}
	return &pr, nil
}

// zkserver() retrieves the public identity of a server.
func zkserver(root string, ipAndport string, fingerprint, verbose bool) error {
	var err error
	if root == "" {
		root, err = zkutil.DefaultServerRootPath()
		if err != nil {
			return err
		}
	}
	pr, err := fetchServerRecord(root, ipAndport)
	if err != nil {
		return err
	}
	if fingerprint {
		cert, err := fetchServerCert(root)
		if err != nil {
			return err
		}
		fmt.Printf("outer: %s\n", tools.FingerprintDER(cert))
		fmt.Printf("inner: %s\n", pr.PublicIdentity.Fingerprint())
		return nil
	}
	var blob bytes.Buffer
	_, err = xdr.Marshal(&blob, pr)
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", base64.StdEncoding.EncodeToString(blob.Bytes()))
	if verbose {
		spew.Config.ContinueOnMethod = true
		spew.Dump(pr)
	}
	return nil
}

// fetchClientIdentity() is an auxiliary function invoked by
// fetchClientFullIdentity().
func fetchClientIdentity(root string) ([]byte, error) {
	file := path.Join(root, tools.ZKCServerFilename)
	server, err := inidb.New(file, false, 10)
	if err != nil {
		return nil, err
	}
	b64, err := server.Get("", "myidentity")
	if err != nil {
		return nil, fmt.Errorf("could not obtain myidentity record")
	}
	return base64.StdEncoding.DecodeString(b64)
}

// fetchClientFullIdentity() fetches a server's signed identity data.
func fetchClientFullIdentity(root string) (*zkidentity.FullIdentity, error) {
	id, err := fetchClientIdentity(root)
	if err != nil {
		return nil, err
	}
	var fi *zkidentity.FullIdentity
	r := bytes.NewReader(id)
	_, err = xdr.Unmarshal(r, &fi)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal identity")
	}
	return fi, nil
}

// fetchClientRecord() fetches a client record residing in 'root',
// if specified, or from zkclient's default root directory.
func fetchClientRecord(root string) (*tools.ClientRecord, error) {
	var err error
	if root == "" {
		root, err = zkutil.DefaultClientRootPath()
		if err != nil {
			return nil, err
		}
	}
	fi, err := fetchClientFullIdentity(root)
	if err != nil {
		return nil, err
	}
	cr := tools.ClientRecord{
		PublicIdentity: fi.Public,
	}
	return &cr, nil
}

// zkclient() retrieves the public identity of a client.
func zkclient(root string, fingerprint, verbose bool) error {
	cr, err := fetchClientRecord(root)
	if err != nil {
		return err
	}
	if fingerprint {
		fmt.Printf("%s\n", cr.PublicIdentity.Fingerprint())
		return nil
	}
	var blob bytes.Buffer
	_, err = xdr.Marshal(&blob, cr)
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", base64.StdEncoding.EncodeToString(blob.Bytes()))
	if verbose {
		spew.Config.ContinueOnMethod = true
		spew.Dump(cr)
	}
	return nil
}

func _main() error {
	root := flag.String("root", "", "path to zkclient/zkserver's root directory")
	verbose := flag.Bool("v", false, "verbose flag")
	server := flag.Bool("s", false, "export a server's (zkserver) identity")
	ipAndPort := flag.String("i", "", "specify a zkserver's IP and port")
	fingerprint := flag.Bool("f", false, "export a zkclient/zkserver's " +
	    "fingerprint in a human-readable format")
	flag.Parse()

	if *server {
		return zkserver(*root, *ipAndPort, *fingerprint, *verbose)
	} else {
		return zkclient(*root, *fingerprint, *verbose)
	}
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
