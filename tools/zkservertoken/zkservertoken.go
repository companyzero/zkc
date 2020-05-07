// Copyright (c) 2016-2020 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/companyzero/zkc/inidb"
	"github.com/companyzero/zkc/tools"
	"github.com/vaughan0/go-ini"
)

const (
	pendingDir  = "pending"
	pendingFile = "pending.ini"
)

var (
	pendingPath = path.Join(pendingDir, pendingFile)
)

func _main() error {
	// setup default paths
	usr, err := user.Current()
	if err != nil {
		return fmt.Errorf("user.Current: %v", err)
	}

	// config file
	filename := flag.String("cfg", usr.HomeDir+"/.zkserver/zkserver.conf",
		"config file")
	hours := flag.Uint("hours", 24, "hours before expiration")
	flag.Parse()

	// parse file
	cfg, err := ini.LoadFile(*filename)
	if err != nil && *filename != flag.Lookup("cfg").DefValue {
		return fmt.Errorf("could not read config file: %v", err)
	}

	// root directory
	root, ok := cfg.Get("", "root")
	if !ok {
		return fmt.Errorf("config file does not contain entry: root")
	}
	root = strings.Replace(root, "~", usr.HomeDir, 1)

	// open db
	pending, err := inidb.New(path.Join(root, pendingPath), true, 10)
	if err != nil && !errors.Is(err, inidb.ErrCreated) {
		return fmt.Errorf("could not open inidb: %v", err)
	}

	for {
		x, err := tools.RandomUint64()
		if err != nil {
			return fmt.Errorf("not enough entropy")
		}
		if x < 10000000000000000 {
			continue
		}
		x %= 10000000000000000

		xs := strconv.FormatUint(x, 10)
		_, err = pending.Get("", xs)
		if err == nil {
			continue
		}

		xsPrint, err := tools.InFours(xs)
		if err != nil {
			continue
		}

		// deal with it
		expires := time.Now().Add(time.Duration(*hours) * time.Hour).Unix()
		err = pending.Set("", xs, strconv.FormatUint(uint64(expires), 10))
		if err != nil {
			return fmt.Errorf("could not insert record")
		}

		err = pending.Save()
		if err != nil {
			return fmt.Errorf("could not save pending database: %v",
				err)
		}

		fmt.Printf("%v\n", xsPrint)

		break
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
