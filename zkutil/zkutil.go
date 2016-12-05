// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package zkutil

import (
	"fmt"
	"os/user"
	"path"
)

func DefaultClientRootPath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("user.Current: %v", err)
	}
	return path.Join(usr.HomeDir, ".zkclient"), nil
}

func DefaultServerRootPath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("user.Current: %v", err)
	}
	return path.Join(usr.HomeDir, ".zkserver"), nil
}
