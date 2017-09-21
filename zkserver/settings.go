package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"runtime"

	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkserver/settings"
	"github.com/companyzero/zkc/zkutil"
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
	filename := flag.String("cfg", usr.HomeDir+"/.zkserver/zkserver.conf",
		"config file")
	version := flag.Bool("version", false, "show version")
	flag.Parse()

	if *version {
		fmt.Fprintf(os.Stderr, "zkserver %s (%s) protocol version %d\n",
			zkutil.Version(), runtime.Version(), rpc.ProtocolVersion)
		os.Exit(0)
	}

	// load file
	err = s.Load(*filename)
	if err != nil {
		return nil, err
	}

	return s, nil
}
