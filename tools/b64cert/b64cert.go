// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"runtime"
)

func _main() error {
	cert := flag.String("c", "", "cert file")
	key := flag.String("k", "", "key file")
	flag.Parse()

	if *cert == "" {
		flag.PrintDefaults()
		return nil
	}
	if *key == "" {
		flag.PrintDefaults()
		return nil
	}

	c, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		return fmt.Errorf("could not load certificates: %v", err)
	}

	fmt.Printf("servercert = %v\n",
		base64.StdEncoding.EncodeToString(c.Certificate[0]))

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
