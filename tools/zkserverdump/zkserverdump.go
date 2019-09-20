package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"

	"github.com/companyzero/zkc/inidb"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/companyzero/zkc/zkserver/account"
	"github.com/companyzero/zkc/zkserver/settings"
	"github.com/companyzero/zkc/zkutil"
	xdr "github.com/davecgh/go-xdr/xdr2"
)

func ObtainSettings() (*settings.Settings, error) {
	// defaults
	s := settings.New()

	// setup default paths
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	// config file
	filename := flag.String("cfg", path.Join(usr.HomeDir, ".zkserver", "zkserver.conf"),
		"config file")
	version := flag.Bool("version", false, "show version")
	flag.Parse()

	if *version {
		fmt.Fprintf(os.Stderr, "zkserverdump %s (%s) protocol version"+
			"%d\n", zkutil.Version(), runtime.Version(),
			rpc.ProtocolVersion)
		os.Exit(0)
	}

	// load file
	err = s.Load(*filename)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func _main() error {
	// flags and settings
	var err error
	settings, err := ObtainSettings()
	if err != nil {
		return err
	}

	fmt.Printf("zkserverdump directory: %v\n", settings.Root)

	fi, err := ioutil.ReadDir(path.Join(settings.Users))
	if err != nil {
		return err
	}

	for _, v := range fi {
		user, err := inidb.New(filepath.Join(settings.Users, v.Name(),
			account.UserIdentityFilename), false, 1)
		if err != nil {
			return err
		}
		b64, err := user.Get("", "identity")
		if err != nil {
			return fmt.Errorf("could not get user: %v", err)
		}
		blob, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return fmt.Errorf("could not decode user: %v", err)
		}
		id := new(zkidentity.PublicIdentity)
		br := bytes.NewReader(blob)
		_, err = xdr.Unmarshal(br, &id)
		if err != nil {
			return fmt.Errorf("could not unmarshal user: %v", err)
		}
		fmt.Printf("%v %v\n", v.Name(), id.Nick)
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
