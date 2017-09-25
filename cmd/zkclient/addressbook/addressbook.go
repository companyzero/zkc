// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addressbook

import (
	"bytes"
	"errors"
	"sync"

	"github.com/companyzero/zkc/zkidentity"
)

const (
	IdentityFilename = "publicidentity.xdr"
)

var (
	ErrNotFound      = errors.New("nick not found")
	ErrDuplicateNick = errors.New("duplicate nick")
)

// AddressBook context.
type AddressBook struct {
	sync.RWMutex

	identities map[string]zkidentity.PublicIdentity
}

// New creates a new AddressBook context.
func New() *AddressBook {
	return &AddressBook{
		identities: make(map[string]zkidentity.PublicIdentity),
	}
}

// Add adds an identity to an AddressBook.  The identity is always added and
// can not fail.  The returned error is used to indicate if the nick, which is
// used as the lookup key, was modified.  The caller is responsible for using
// the correct lookup nick.
func (a *AddressBook) Add(identity zkidentity.PublicIdentity) (string, error) {
	a.Lock()
	defer a.Unlock()

	var (
		found, warn bool
		i           zkidentity.PublicIdentity
	)

	for {
		i, found = a.identities[identity.Nick]
		if found {
			// if identity is identical do not alter nick
			if bytes.Equal(identity.Identity[:], i.Identity[:]) {
				break
			}
			identity.Nick += "_"
			warn = true
			continue
		}
		break
	}
	if warn {
		return identity.Nick, ErrDuplicateNick
	}
	a.identities[identity.Nick] = identity

	return identity.Nick, nil
}

// Del permanently removes user from the address book.
func (a *AddressBook) Del(id [zkidentity.IdentitySize]byte) error {
	a.Lock()
	defer a.Unlock()

	for k, v := range a.identities {
		if !bytes.Equal(v.Identity[:], id[:]) {
			continue
		}

		delete(a.identities, k)
		return nil
	}

	return ErrNotFound
}

// FindNick returns the identity associated with nick.
func (a *AddressBook) FindNick(nick string) (*zkidentity.PublicIdentity, error) {
	a.RLock()
	defer a.RUnlock()

	id, found := a.identities[nick]
	if !found {
		return nil, ErrNotFound
	}

	return &id, nil
}

// FindIdentity returns the identity associated with identity.
func (a *AddressBook) FindIdentity(id [zkidentity.IdentitySize]byte) (*zkidentity.PublicIdentity, error) {
	a.RLock()
	defer a.RUnlock()

	for _, v := range a.identities {
		if bytes.Equal(v.Identity[:], id[:]) {
			return &v, nil
		}
	}

	return nil, ErrNotFound
}

// All returns an unsorted array of zkidentity.PublicIdentity.
func (a *AddressBook) All() []zkidentity.PublicIdentity {
	a.RLock()
	defer a.RUnlock()

	pids := make([]zkidentity.PublicIdentity, 0, len(a.identities))
	for _, v := range a.identities {
		pids = append(pids, v)
	}

	return pids
}
