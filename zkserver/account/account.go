// Copyright (c) 2016-2020 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package account

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"time"

	"github.com/companyzero/zkc/inidb"
	"github.com/companyzero/zkc/zkidentity"
	xdr "github.com/davecgh/go-xdr/xdr2"
)

const (
	CacheDir             = "cache"
	UserIdentityFilename = "user.ini"
)

type ErrAlreadyOnline struct {
	err error
}

func (e ErrAlreadyOnline) Error() string {
	return e.err.Error()
}

// Account opaque type that handles account related services.
type Account struct {
	root string // root location of all accounts

	// mutexed memebers
	sync.Mutex
	online map[[32]byte]diskNotification
}

type diskNotification struct {
	ntfn      chan *Notification
	work      chan struct{}
	quit      chan struct{}
	processed map[string]struct{}
}

// diskMessage is the on disk structure of a message. To is identified by the
// delivery directory name and from is stored in the structure.  That fully
// identifies from where the message came and where it shall be delivered.
type diskMessage struct {
	From     [zkidentity.IdentitySize]byte
	Received int64
	Payload  []byte
	// Cleartext was added after the fact and is therefore at the end of
	// the struct for compatibility reasons. Default is 0 which means
	// content is encrypted as it always was prior to this change.
	Cleartext bool // Content is cleartext when set
}

// Notification contains the necessary information to notify the caller that a
// delivery has been made.  Notifications are written opportunistically and non
// blocking.  It is the receivers responsibility to read the channel queue
// quickly enough.  This usually means that the channel should be created with
// some sane queue depth!
type Notification struct {
	To         [zkidentity.IdentitySize]byte
	From       [zkidentity.IdentitySize]byte
	Received   int64 // received time
	Payload    []byte
	Cleartext  bool // Set when payload is clear text
	Identifier string
	Error      error
}

// New initializes an Account context.  It creates the containing directory and
// launches the push channel handling.
// Note that New walks the root directory and removes stale locks.  The
// directory walk is slow and this call may take a while to complete.
func New(root string) (*Account, error) {
	if root == "" {
		return nil, fmt.Errorf("must provide root directory")
	}

	a := Account{
		root:   root,
		online: make(map[[zkidentity.IdentitySize]byte]diskNotification),
	}

	// make directory
	err := os.MkdirAll(root, 0700)
	if err != nil {
		return nil, err
	}

	return &a, nil
}

// AccountDirDisabled return the account directory for a given disabled identity.
func (a *Account) accountDirDisabled(id [zkidentity.IdentitySize]byte) string {
	return path.Join(a.root, "."+hex.EncodeToString(id[:]))
}

// AccountDir return the account directory for a given identity.
func (a *Account) accountDir(id [zkidentity.IdentitySize]byte) string {
	return path.Join(a.root, hex.EncodeToString(id[:]))
}

// AccountFile return the account filename for a given identity.
func (a *Account) accountFile(id [zkidentity.IdentitySize]byte,
	file string) string {
	return path.Join(a.root, hex.EncodeToString(id[:]), file)
}

// createAccount creates all directories and files associated with an account.
// It returns a logable and a sanitized error.
func (a *Account) Create(pid zkidentity.PublicIdentity, force bool) error {
	_, err := a.Find(pid.Nick)
	if err == nil {
		return fmt.Errorf("nickname already in use")
	}
	// make sure account doesn't exist
	accountName := a.accountDir(pid.Identity)
	_, err = os.Stat(accountName)
	if err == nil {
		if !force {
			return fmt.Errorf("account already exists: %v",
				accountName)
		}
	}

	// open user db
	user, err := inidb.New(a.accountFile(pid.Identity,
		UserIdentityFilename), true, 10)
	if err != nil && !errors.Is(err, inidb.ErrCreated) {
		return fmt.Errorf("could not open userdb: %v", err)
	}

	// save public identity
	var b bytes.Buffer
	_, err = xdr.Marshal(&b, pid)
	if err != nil {
		return fmt.Errorf("create account Marshal PublicIdentity failed")
	}
	err = user.Set("", "identity",
		base64.StdEncoding.EncodeToString(b.Bytes()))
	if err != nil {
		return fmt.Errorf("could not insert record identity: %v", err)
	}
	err = user.Save()
	if err != nil {
		return fmt.Errorf("could not save user: %v", err)
	}

	// make additional directories
	err = os.Mkdir(a.accountFile(pid.Identity, CacheDir), 0700)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("could not create cache directory: %v", err)
	}

	return nil
}

func (a *Account) Push(id [zkidentity.IdentitySize]byte) error {
	accountName := a.accountDir(id)
	_, err := os.Stat(accountName)
	if err != nil {
		return fmt.Errorf("account not found")
	}
	user, err := inidb.New(a.accountFile(id, UserIdentityFilename), false, 10)
	if err != nil {
		return fmt.Errorf("could not open userdb: %v", err)
	}

	err = user.Set("", "listed", "1")
	if err != nil {
		return fmt.Errorf("could not list user: %v", err)
	}
	err = user.Save()
	if err != nil {
		return fmt.Errorf("could not save user: %v", err)
	}

	return nil
}

func (a *Account) Find(nick string) (*zkidentity.PublicIdentity, error) {
	a.Lock()
	fi, err := ioutil.ReadDir(a.root)
	if err != nil {
		a.Unlock()
		return nil, fmt.Errorf("could not find user: %v", err)
	}
	for _, v := range fi {
		dirname := path.Join(a.root, v.Name())
		user, err := inidb.New(path.Join(dirname, UserIdentityFilename), false, 10)
		if err != nil {
			a.Unlock()
			return nil, fmt.Errorf("could not find user: %v", err)
		}
		a.Unlock()

		listed, err := user.Get("", "listed")
		if err == nil && listed == "1" {
			b64, err := user.Get("", "identity")
			if err != nil {
				return nil, fmt.Errorf("could not get user: %v", err)
			}
			blob, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return nil, fmt.Errorf("could not decode user: %v", err)
			}
			id := new(zkidentity.PublicIdentity)
			br := bytes.NewReader(blob)
			_, err = xdr.Unmarshal(br, &id)
			if err != nil {
				return nil, fmt.Errorf("could not unmarshal user: %v", err)
			}
			if id.Nick == nick {
				return id, nil
			}
		}
		a.Lock()
	}
	a.Unlock()

	return nil, fmt.Errorf("user not found")
}

func (a *Account) Disabled(pid [zkidentity.IdentitySize]byte) bool {
	_, err := os.Stat(a.accountDirDisabled(pid))
	return err == nil
}

func (a *Account) Enabled(pid [zkidentity.IdentitySize]byte) bool {
	_, err := os.Stat(a.accountDir(pid))
	return err == nil
}

func (a *Account) Disable(pid [zkidentity.IdentitySize]byte) error {
	a.Lock()
	defer a.Unlock()

	accountNameDisabled := a.accountDirDisabled(pid)
	_, err := os.Stat(accountNameDisabled)
	if err == nil {
		return fmt.Errorf("account already disabled: %v",
			accountNameDisabled)
	}

	accountName := a.accountDir(pid)
	_, err = os.Stat(accountName)
	if err != nil {
		return fmt.Errorf("account doesn't exist: %v",
			accountName)
	}

	return os.Rename(accountName, accountNameDisabled)
}

func (a *Account) Enable(pid [zkidentity.IdentitySize]byte) error {
	a.Lock()
	defer a.Unlock()

	accountNameDisabled := a.accountDirDisabled(pid)
	_, err := os.Stat(accountNameDisabled)
	if err != nil {
		return fmt.Errorf("account not disable: %v",
			accountNameDisabled)
	}

	accountName := a.accountDir(pid)
	_, err = os.Stat(accountName)
	if err == nil {
		return fmt.Errorf("account already enabled: %v",
			accountName)
	}

	return os.Rename(accountNameDisabled, accountName)
}

func (a *Account) Pull(id [zkidentity.IdentitySize]byte) error {
	accountName := a.accountDir(id)
	_, err := os.Stat(accountName)
	if err != nil {
		return fmt.Errorf("account not found")
	}
	user, err := inidb.New(a.accountFile(id, UserIdentityFilename), false, 10)
	if err != nil {
		return fmt.Errorf("could not open userdb: %v", err)
	}

	err = user.Del("", "listed")
	if err != nil {
		return fmt.Errorf("could not unlist user: %v", err)
	}
	err = user.Save()
	if err != nil {
		return fmt.Errorf("could not save user: %v", err)
	}

	return nil
}

// Deliver physically drops a message on disk.  It returns the fullpath so that
// callers can pretty log deliveries.
func (a *Account) Deliver(to [zkidentity.IdentitySize]byte, from [zkidentity.IdentitySize]byte, payload []byte, cleartext bool) (string, error) {
	// get directory
	cache := a.accountFile(to, CacheDir)

	// calculate next filename
	filename := time.Now().Format("20060102150405.000000000")

	// convert to on disk format
	dm := diskMessage{
		From:      from,
		Received:  time.Now().Unix(),
		Payload:   payload,
		Cleartext: cleartext,
	}
	var b bytes.Buffer
	_, err := xdr.Marshal(&b, dm)
	if err != nil {
		return "", fmt.Errorf("could not marshal diskMessage")
	}

	// sanity
	fullPath := path.Join(cache, filename)
	_, err = os.Stat(fullPath)
	if err == nil {
		return "", fmt.Errorf("duplicate filename %v", filename)
	}

	a.Lock()
	defer a.Unlock()

	// and dump it
	err = ioutil.WriteFile(fullPath, b.Bytes(), 0600)
	if err != nil {
		return "", fmt.Errorf("could not write to %v: %v", cache, err)
	}

	// notify
	dn, found := a.online[to]
	if !found {
		return fullPath, nil
	}

	// notify producer that there is work
	select {
	case dn.work <- struct{}{}:
	default:
	}

	return fullPath, nil
}

func (a *Account) Delete(from [zkidentity.IdentitySize]byte, identifier string) error {

	a.Lock()
	defer a.Unlock()

	cache := a.accountFile(from, CacheDir)
	err := os.Remove(path.Join(cache, identifier))
	if err != nil {
		return err
	}

	dn, found := a.online[from]
	if found {
		delete(dn.processed, identifier)
	}

	return nil
}

// offline closes open quit channels and deletes an account from the online
// map. This function must be called WITH the mutex held.
func (a *Account) offline(who [zkidentity.IdentitySize]byte) {
	dn, found := a.online[who]
	if found {
		close(dn.quit)
	}
	delete(a.online, who)
}

// Offline knocks a user offline. This function must be called WITHOUT the
// mutex held.
func (a *Account) Offline(who [zkidentity.IdentitySize]byte) {
	a.Lock()
	defer a.Unlock()
	a.offline(who)
}

// Online notifies Account that a user has become available.  It reads all
// undelivered messages of disk and uses the Notification channel to propagate
// them.
func (a *Account) Online(who [zkidentity.IdentitySize]byte, ntfn chan *Notification) error {

	cache := a.accountFile(who, CacheDir)

	a.Lock()
	_, found := a.online[who]
	if found {
		a.Unlock()
		return ErrAlreadyOnline{
			err: fmt.Errorf("already online: %v ",
				hex.EncodeToString(who[:])),
		}
	}

	dn := diskNotification{
		ntfn:      ntfn,
		work:      make(chan struct{}, 1),
		quit:      make(chan struct{}),
		processed: make(map[string]struct{}),
	}
	a.online[who] = dn
	a.Unlock()

	go func() {
		// first time around start delivering
		dn.work <- struct{}{}

		for {
			select {
			case <-dn.quit:
				return

			case <-dn.work:
			}

			a.Lock()
			fi, err := ioutil.ReadDir(cache)
			if err != nil {
				a.Unlock()
				dn.send(&Notification{Error: err})
				continue
			}
			a.Unlock()

			for _, v := range fi {
				a.Lock()
				_, found := dn.processed[v.Name()]
				if found {
					a.Unlock()
					continue
				}
				dn.processed[v.Name()] = struct{}{}
				a.Unlock()

				filename := path.Join(cache, v.Name())
				f, err := os.Open(filename)
				if err != nil {
					dn.send(&Notification{
						Error: fmt.Errorf("%v: %v",
							filename, err)})
					continue
				}

				var dm diskMessage
				_, err = xdr.Unmarshal(f, &dm)
				// Special error handling because of prior
				// upgrade where we added Cleartext to the
				// diskMessage. A short read is therefore
				// an error we must ignore.
				if err != nil {
					var uerr *xdr.UnmarshalError
					if !errors.As(err, &uerr) ||
						uerr.ErrorCode != xdr.ErrIO ||
						!errors.Is(uerr.Err, io.EOF) {

						f.Close()
						dn.send(&Notification{
							Error: fmt.Errorf("%v: unmarshal %v",
								filename, err),
						})
						continue
					}
				}
				f.Close()

				// notify and block
				dn.send(&Notification{
					To:         who,
					From:       dm.From,
					Received:   dm.Received,
					Payload:    dm.Payload,
					Cleartext:  dm.Cleartext,
					Identifier: v.Name(),
				})
			}
		}
	}()

	return nil
}

func (dn *diskNotification) send(n *Notification) {
	// notify and block
	select {
	case <-dn.quit:
	case dn.ntfn <- n:
	}
}
