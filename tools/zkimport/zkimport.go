// Copyright (c) 2016,2017 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path"
	"runtime"
	"strings"

	"github.com/companyzero/zkc/inidb"
	"github.com/companyzero/zkc/tools"
	"github.com/companyzero/zkc/zkserver/account"
	"github.com/davecgh/go-spew/spew"
	"github.com/davecgh/go-xdr/xdr2"
	"github.com/vaughan0/go-ini"
)

func readBlob(filename string) (interface{}, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// try server record first
	var pr tools.ServerRecord
	d := base64.NewDecoder(base64.StdEncoding, f)
	_, err = xdr.Unmarshal(d, &pr)
	if err != nil {
		// reset file handle and decoder
		_, err = f.Seek(0, 0)
		if err != nil {
			return nil, err
		}
		d = base64.NewDecoder(base64.StdEncoding, f)

		// try client record
		var cr tools.ClientRecord
		_, err = xdr.Unmarshal(d, &cr)
		if err != nil {
			return nil, fmt.Errorf("not a zkserver/zkclient " +
				"key blob")
		}
		return cr, nil
	}

	return pr, nil
}

func importClientRecord(root string, force bool, cr tools.ClientRecord) error {
	// make sure we have a valid zkserver directory
	var dir string
	// make sure config exists
	if root != "" {
		dir = root
		_, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("Stat %v: %v", dir, err)
		}
	} else {
		// guess
		usr, err := user.Current()
		if err != nil {
			return fmt.Errorf("user.Current: %v", err)
		}
		dir = path.Join(usr.HomeDir, ".zkserver")
	}

	// stat important bits, just in case
	cert := path.Join(dir, tools.ZKSCertFilename)
	key := path.Join(dir, tools.ZKSKeyFilename)
	id := path.Join(dir, tools.ZKSIdentityFilename)
	home := path.Join(dir, tools.ZKSHome)
	_, err := os.Stat(cert)
	if err != nil {
		return fmt.Errorf("invalid zkserver directory")
	}
	_, err = os.Stat(key)
	if err != nil {
		return fmt.Errorf("invalid zkserver directory")
	}
	_, err = os.Stat(id)
	if err != nil {
		return fmt.Errorf("invalid zkserver directory")
	}
	_, err = os.Stat(home)
	if err != nil {
		return fmt.Errorf("invalid zkserver directory")
	}

	// see if user already exists
	i := hex.EncodeToString(cr.PublicIdentity.Identity[:])
	user := path.Join(dir, tools.ZKSHome, i)
	_, err = os.Stat(user)

	a, err := account.New(home)
	if err != nil {
		return err
	}
	err = a.Create(cr.PublicIdentity, force)
	if err != nil {
		return err
	}

	fmt.Printf("Imported %v: %v\n", cr.PublicIdentity.Name, cr.PublicIdentity.Fingerprint())

	return nil
}

func promptUser(cr tools.ServerRecord) error {
	fmt.Fprintf(os.Stderr, "The authenticity of server '%s' can't be established.\n", cr.IPandPort)
	fmt.Fprintf(os.Stderr, "Inner fingerprint = %s.\n", cr.PublicIdentity.Fingerprint())
	fmt.Fprintf(os.Stderr, "Outer fingerprint = %s.\n", tools.Fingerprint(cr.Certificate))
	fmt.Fprintf(os.Stderr, "Are you sure you want to import this server (yes/no)? ")

	reader := bufio.NewReader(os.Stdin)
	reply, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("could not prompt user: %v", err)
	}
	if reply != "yes\n" && reply != "y\n" {
		return fmt.Errorf("refusing to import server")
	}

	return nil
}

func importServerRecord(root string, force bool, cr tools.ServerRecord) error {
	// make sure we have a valid zkclient directory
	var dir string
	// make sure config exists
	if root != "" {
		dir = root
		_, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("Stat %v: %v", dir, err)
		}
	} else {
		// guess
		usr, err := user.Current()
		if err != nil {
			return fmt.Errorf("user.Current: %v", err)
		}
		dir = path.Join(usr.HomeDir, ".zkclient")
	}

	// see if server already exists
	serverFile := path.Join(dir, tools.ZKCServerFilename)
	_, err := os.Stat(serverFile)
	if err == nil && force == false {
		return fmt.Errorf("server already configured")
	}

	// ask the user to verify the server's coordinates
	if force == false {
		err = promptUser(cr)
		if err != nil {
			return err
		}
	}
	// save server as our very own
	server, err := inidb.New(serverFile, true, 10)
	if err != nil && err != inidb.ErrCreated {
		return fmt.Errorf("could not open server file: %v", err)
	}
	err = server.Set("", "server", string(cr.IPandPort))
	if err != nil {
		return fmt.Errorf("could not insert record server")
	}
	srvId, err := cr.PublicIdentity.Marshal()
	if err != nil {
		return fmt.Errorf("could not marshall record serveridentity")
	}
	err = server.Set("", "serveridentity",
		base64.StdEncoding.EncodeToString(srvId))
	if err != nil {
		return fmt.Errorf("could not insert record serveridentity")
	}
	err = server.Set("", "servercert",
		base64.StdEncoding.EncodeToString(cr.Certificate))
	if err != nil {
		return fmt.Errorf("could not insert record servercert")
	}
	err = server.Save()
	if err != nil {
		return fmt.Errorf("could not save server: %v", err)
	}

	fmt.Printf("Imported %v\n", cr.PublicIdentity.Fingerprint())

	return nil
}

func _main() error {
	// setup default paths
	usr, err := user.Current()
	if err != nil {
		return fmt.Errorf("user.Current: %v", err)
	}

	filename := flag.String("cfg", "", "config file")
	force := flag.Bool("f", false, "overwrite identity if it already "+
		"exists; skip verification (DANGEROUS)")
	verbose := flag.Bool("v", false, "enable verbose")
	flag.Parse()

	// get import list
	if len(flag.Args()) < 1 {
		fmt.Fprintf(os.Stderr,
			"usage: zkimport [-cfg][-v] filename...\n")
		flag.PrintDefaults()
		return nil
	}

	var (
		root string
		ok   bool
	)
	if *filename != "" {
		cfg, err := ini.LoadFile(*filename)
		if err != nil && *filename != flag.Lookup("cfg").DefValue {
			return fmt.Errorf("could not read config file: %v", err)
		}

		// root directory
		root, ok = cfg.Get("", "root")
		if !ok {
			return fmt.Errorf("config file does not contain " +
				"entry: root")
		}
		root = strings.Replace(root, "~", usr.HomeDir, 1)
	}

	for _, v := range flag.Args() {
		// read blob
		record, err := readBlob(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %v: %v\n", v, err)
			continue
		}

		switch r := record.(type) {
		case tools.ClientRecord:
			if *verbose {
				spew.Config.ContinueOnMethod = true
				spew.Dump(r)
			}
			err = importClientRecord(root, *force, r)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Import failed %v: %v\n",
					v, err)
				os.Exit(1)
			}
		case tools.ServerRecord:
			if *verbose {
				spew.Config.ContinueOnMethod = true
				spew.Dump(r)
			}
			err = importServerRecord(root, *force, r)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Import failed %v: %v\n",
					v, err)
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "not reached")
		}
	}

	return nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
