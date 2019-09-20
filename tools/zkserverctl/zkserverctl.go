package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/companyzero/zkc/zkserver/settings"
	"github.com/companyzero/zkc/zkserver/socketapi"
	"github.com/companyzero/zkc/zkutil"
)

var socket string

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
		fmt.Fprintf(os.Stderr, "zkserverctl %s (%s) socket protocol "+
			"version %d\n", zkutil.Version(), runtime.Version(),
			socketapi.SCVersion)
		os.Exit(0)
	}

	// load file
	err = s.Load(*filename)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func userDisable(a []string) error {
	if len(a) != 2 {
		return fmt.Errorf("userdisable <nick|identity>")
	}

	c, err := net.Dial("unix", socket)
	if err != nil {
		return err
	}
	defer c.Close()

	// send identifier
	je := json.NewEncoder(c)
	err = je.Encode(socketapi.SocketCommandID{
		Version: socketapi.SCVersion,
		Command: socketapi.SCUserDisable,
	})
	if err != nil {
		return err
	}
	err = je.Encode(socketapi.SocketCommandUserDisable{
		Identifier: strings.TrimSpace(a[1]),
	})
	if err != nil {
		return err
	}

	// read reply
	jd := json.NewDecoder(c)
	var udr socketapi.SocketCommandUserDisableReply
	err = jd.Decode(&udr)
	if err != nil {
		return err
	}

	if udr.Error != "" {
		return fmt.Errorf("%v", udr.Error)
	}

	return nil
}

func _main() error {
	// flags and settings
	var err error
	settings, err := ObtainSettings()
	if err != nil {
		return err
	}

	// open socket
	a := flag.Args()
	if len(a) == 0 {
		return fmt.Errorf("must provide command")
	}

	socket = filepath.Join(settings.Root, socketapi.SocketFilename)
	fmt.Printf("zkserverctl socket: %v\n", socket)

	switch a[0] {
	case "userdisable":
		return userDisable(a)
	default:
		return fmt.Errorf("invalid command: %v", a[0])
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
