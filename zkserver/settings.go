package main

import (
	"flag"
	"os/user"

	"github.com/companyzero/zkc/zkserver/settings"
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
	flag.Parse()

	// load file
	err = s.Load(*filename)
	if err != nil {
		return nil, err
	}

	return s, nil
}
