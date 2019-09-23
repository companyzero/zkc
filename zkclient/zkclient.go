// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/companyzero/sntrup4591761"
	"github.com/companyzero/ttk"
	"github.com/companyzero/zkc/blobshare"
	"github.com/companyzero/zkc/debug"
	"github.com/companyzero/zkc/inidb"
	"github.com/companyzero/zkc/ratchet"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/session"
	"github.com/companyzero/zkc/tagstack"
	"github.com/companyzero/zkc/tools"
	"github.com/companyzero/zkc/zkclient/addressbook"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/davecgh/go-spew/spew"
	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/nsf/termbox-go"
)

var (
	errCert      = errors.New("server certificate changed")
	errPendingKX = errors.New("key exchange kicked off")
)

// updateStatus updates the status bar, lock must be held
func (z *ZKC) calculateStatus() string {
	var active string
	comma := false
	for k, v := range z.conversation {
		if v.dirty {
			if comma {
				active += ","
			}
			color := STATUSWHITEBOLD
			if v.mentioned {
				color = STATUSMAGENTABOLD
			}
			active += color +
				strconv.FormatInt(int64(k), 10) +
				STATUSRESET
			comma = true
		}
	}

	var paging string
	if z.conversation[z.active].console.IsPaging() {
		paging = STATUSWHITEBOLD +
			" -- More --" +
			STATUSRESET
	}

	return fmt.Sprintf(STATUSCYAN+" ["+STATUSRESET+"%v"+STATUSCYAN+"] ["+
		STATUSRESET+"%v"+STATUSCYAN+"] ["+STATUSRESET+"%v:%v"+
		STATUSCYAN+"] ["+STATUSRESET+"%v"+STATUSCYAN+"]%v",
		time.Now().Format("15:04"),
		z.id.Public.Nick,
		z.active,
		z.conversation[z.active].nick,
		active,
		paging)
}

func differentDay(x, y time.Time) bool {
	return x.Day() != y.Day() ||
		x.Month() != y.Month() ||
		x.Year() != y.Year()
}

// updateTS updates the timestamp of a conversation. Lock must be held.
func (z *ZKC) updateTS(id int, ts time.Time) {
	var msg string
	var c *conversation = z.conversation[id]

	if c.lastMsg.IsZero() {
		msg = fmt.Sprintf("first message received on %v %s %v",
			ts.Day(), ts.Month(), ts.Year())
	} else if differentDay(ts, c.lastMsg) {
		msg = fmt.Sprintf("day changed to %v %s %v", ts.Day(),
			ts.Month(), ts.Year())
	}
	if msg != "" {
		c.console.Append("%v %s", ts.Format(z.settings.TimeFormat), msg)
		z.log(id, "%v %s", ts.Format(z.settings.LongTimeFormat), msg)
	}

	c.lastMsg = ts
}

func (z *ZKC) PrintfT(id int, format string, args ...interface{}) {
	z.printf(id, time.Now(), true, format, args...)
}

func (z *ZKC) PrintfTS(id int, ts time.Time, format string, args ...interface{}) {
	z.printf(id, ts, false, format, args...)
}

// FloodfT prints to the console and the current window unless an active
// conversation with the person is in progress. If nick is empty it always
// prints in the current window.
func (z *ZKC) FloodfT(nick, format string, args ...interface{}) {
	// Print to console
	z.printf(0, time.Now(), true, format, args...)

	// Try to find the proper conversation window
	z.RLock()
	//search for active nick
	for k, v := range z.conversation {
		if v == nil || k == 0 {
			continue
		}
		if v.nick != nick {
			continue
		}
		z.RUnlock()
		z.printf(k, time.Now(), true, format, args...)
		return
	}
	active := z.active
	z.RUnlock()

	// Not found, print in current window if it isn't 0
	if active != 0 {
		z.printf(active, time.Now(), true, format, args...)
	}
}

func (z *ZKC) printf(id int, ts time.Time, localTs bool, format string, args ...interface{}) {
	output := fmt.Sprintf(format, args...)
	ttk.Queue(func() {
		z.Lock()
		if id < 0 {
			id = z.active
		}
		if id < len(z.conversation) && z.conversation[id] != nil {
			// We do these gymnastics in order to print a
			// separator line where conversation left off.
			if z.active != id && z.settings.Separator &&
				z.conversation[id].console.Len() != 0 &&
				id != 0 && !z.conversation[id].separator {
				t := fmt.Sprintf("%v ",
					ts.Format(z.settings.TimeFormat))
				r := z.conversation[id].console.Width() - len(t)
				if r <= 0 {
					// assume normal terminal width
					r = 80 - len(t)
				}
				z.conversation[id].console.Append("%v%v",
					t, strings.Repeat("-", r))
				z.conversation[id].separator = true
			}

			if !localTs {
				z.updateTS(id, ts)
			}
			z.conversation[id].console.Append("%v %v",
				ts.Format(z.settings.TimeFormat),
				output)
			z.conversation[id].console.Render()
			if z.active != id {
				z.conversation[id].dirty = true
			}
		}

		s := z.calculateStatus()
		z.mw.status.SetText(s)
		z.mw.status.Render()

		z.log(id, "%v %v", ts.Format(z.settings.LongTimeFormat),
			output)

		z.Unlock()
		ttk.Flush()
	})
}

func (z *ZKC) log(id int, format string, args ...interface{}) {
	output := fmt.Sprintf(format, args...)
	if id < 0 || !(id < len(z.conversation) && z.conversation[id] != nil) {
		return
	}

	server, _, err := net.SplitHostPort(z.serverAddress)
	if err != nil {
		// this can't happen
		go z.PrintfT(0, "invalid server address: %v", err)
		return
	}
	var filename string
	switch {
	case id == 0:
		// console
		z.Log(id, format, args...)
		return
	case z.conversation[id].group:
		filename = path.Join(z.settings.Root,
			logsDir, "groupchat."+z.conversation[id].nick+"."+
				server+".log")
	default:
		filename = path.Join(z.settings.Root,
			logsDir,
			z.conversation[id].nick+"."+server+"."+
				z.conversation[id].id.String()+".log")
	}
	f, err := os.OpenFile(filename,
		os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		nick := z.conversation[id].id.Nick
		go z.PrintfT(0, "can't log for %v: %v",
			nick, err)
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "%v\n", ttk.Unescape(output))
}

func (z *ZKC) focus(id int) {
	ttk.Queue(func() {
		z.Lock()
		defer z.Unlock()

		// console overrides a.active, allows rendering at SOD
		if id != 0 && id == z.active {
			return
		}

		if id < 0 || id > len(z.conversation)-1 {
			z.PrintfT(0, "invalid window: %v", id)
			return
		}

		// hide old window, show new window
		if z.active < len(z.conversation) {
			// this prevents a removed window from running array
			// out of bounds
			z.conversation[z.active].console.Visibility(ttk.VisibilityHide)
		}
		z.active = id
		z.conversation[id].dirty = false
		z.conversation[id].separator = false
		z.conversation[id].mentioned = false
		z.conversation[id].console.Visibility(ttk.VisibilityShow)

		// update status
		s := z.calculateStatus()
		z.mw.status.SetText(s)
		z.mw.status.Render()

		// update title
		title := fmt.Sprintf(" %v@%v",
			z.conversation[id].nick,
			z.serverAddress)
		z.mw.title.SetText(title)
		z.mw.title.Render()

		ttk.Flush()
	})
}

type conversation struct {
	console   *ttk.List // console list
	id        *zkidentity.PublicIdentity
	nick      string
	dirty     bool
	separator bool
	group     bool      // when set it is a group chat
	mentioned bool      // set when user nick is mentioned in group chat
	lastMsg   time.Time // stamp of last received msg
}

func (z *ZKC) nextConversation() {
	z.RLock()
	defer z.RUnlock()

	if z.active+1 > len(z.conversation)-1 {
		// overflow
		z.focus(0)
		return
	}
	for x := z.active + 1; x < len(z.conversation); x++ {
		if z.conversation[x] == nil {
			continue
		}
		z.focus(x)
		return
	}
}

func (z *ZKC) prevConversation() {
	z.RLock()
	defer z.RUnlock()

	if z.active-1 < 0 {
		// underflow
		for x := len(z.conversation) - 1; x >= 0; x-- {
			if z.conversation[x] == nil {
				continue
			}
			z.focus(x)
			return
		}
		return
	}

	for x := z.active - 1; x >= 0; x-- {
		if z.conversation[x] == nil {
			continue
		}
		z.focus(x)
		return
	}

	// if we make it here we need to focus on console
	z.focus(0)
}

func (z *ZKC) groupConversation(group string) (*conversation, int, error) {

	// make sure group exists first
	z.Lock()
	_, found := z.groups[group]
	if !found {
		z.Unlock()
		return nil, -1, fmt.Errorf("group not found %v", group)
	}
	z.Unlock()

	c := &conversation{}
	fi := new(zkidentity.FullIdentity)
	fi.Public.Name = "group chat"
	fi.Public.Nick = group
	c.id = &fi.Public
	c.nick = c.id.Nick
	c.group = true
	done := make(chan struct{})
	ttk.Queue(func() {
		c.console = z.ttkMW.AddList(0, 1, 0, -2)
		c.console.Visibility(ttk.VisibilityHide)
		z.Lock()
		// XXX this should not be necessary and must be fixed in ttk
		// XXX hiding the new list clears screen
		z.conversation[z.active].console.Visibility(ttk.VisibilityShow)

		z.Unlock()
		done <- struct{}{}
	})
	<-done

	z.Lock()
	defer z.Unlock()
	x := -1
	for k, v := range z.conversation {
		if v.id.Nick == group {
			return v, k, nil
		}
		// next free slot
		if x == -1 && v == nil {
			x = k
		}
	}

	// add to array
	if x == -1 {
		x = len(z.conversation)
		z.conversation = append(z.conversation, nil)
	}
	z.conversation[x] = c

	z.PrintfT(0, "group conversation started [%v]: %v",
		x,
		z.settings.GcColor+c.nick+RESET)
	z.PrintfT(x, "group conversation started: %v",
		z.settings.GcColor+c.nick+RESET)

	return c, x, nil
}

func (z *ZKC) getConversation(id [zkidentity.IdentitySize]byte) (*conversation, int, error) {
	// get identity and calculate nick
	var err error
	c := &conversation{}
	c.id, err = z.loadIdentity(id)
	if err != nil {
		return nil, -1, err
	}
	if c.id.Nick == "" {
		c.nick = hex.EncodeToString(id[:])
	} else {
		c.nick = c.id.Nick
	}

	// create conversation console in queue
	done := make(chan struct{})
	ttk.Queue(func() {
		// add to array
		c.console = z.ttkMW.AddList(0, 1, 0, -2)
		c.console.Visibility(ttk.VisibilityHide)

		z.Lock()
		// XXX this should not be necessary and must be fixed in ttk
		// XXX hiding the new list clears screen
		z.conversation[z.active].console.Visibility(ttk.VisibilityShow)
		z.Unlock()
		done <- struct{}{}
	})
	<-done

	// add it to conversation list
	z.Lock()
	defer z.Unlock()

	x := -1
	for k, v := range z.conversation {
		if bytes.Equal(v.id.Identity[:], id[:]) {
			return v, k, nil
		}
		// next free slot
		if x == -1 && v == nil {
			x = k
		}
	}

	if x == -1 {
		x = len(z.conversation)
		z.conversation = append(z.conversation, nil)
	}
	z.conversation[x] = c

	z.PrintfT(0, "conversation started [%v]: %v %v",
		x,
		z.settings.PmColor+c.nick+RESET,
		c.id.Fingerprint())

	z.PrintfT(x, "conversation started: %v %v",
		z.settings.PmColor+c.nick+RESET,
		c.id.Fingerprint())

	return c, x, nil
}

func (z *ZKC) query(nick string) {
	z.RLock()
	//search for active nick
	for k, v := range z.conversation {
		if v == nil {
			continue
		}
		if v.nick != nick {
			continue
		}
		z.focus(k)
		z.RUnlock()
		return
	}
	z.RUnlock()

	// Try group conversation first
	_, win, err := z.groupConversation(nick)
	if err != nil {
		// See if it is a person
		_, win, err = z.addressBookConversation(nick)
		if err != nil {
			z.PrintfT(-1, "%v", err)
			if err == errPendingKX {
				z.PrintfT(-1, "If key exchange succeeds you "+
					"must reissue the query command")
			}
			return
		}
	}
	z.focus(win)
}

func (z *ZKC) listConversations() {
	z.RLock()
	defer z.RUnlock()

	for k, v := range z.conversation {
		if k == 0 {
			// skip console
			continue
		}
		if v == nil {
			continue
		}
		z.PrintfT(-1, "[%v] %v %v %v",
			k,
			v.nick,
			v.id.Name,
			v.id.Fingerprint())
	}
}

func (z *ZKC) listAddressBook() {
	a := z.ab.All()
	for _, v := range a {
		z.PrintfT(-1, "%v %v %v", v.Nick, v.Name, v.Fingerprint())
	}
}

func (z *ZKC) listGroupchat(args []string) {
	z.RLock()
	defer z.RUnlock()

	switch len(args) {
	case 2:
		z.PrintfT(-1, "Group chats:")
		// show all groups
		for k, v := range z.groups {
			z.PrintfT(-1, "%v created %v",
				z.settings.GcColor+k+RESET,
				time.Unix(v.Timestamp, 0).Format(time.RFC850))
		}
	case 3:
		// show one group
		g, found := z.groups[args[2]]
		if !found {
			z.PrintfT(-1, "invalid groupchat %v",
				z.settings.GcColor+args[2]+RESET)
			return
		}
		z.PrintfT(-1, "Group chat %v:",
			z.settings.GcColor+args[2]+RESET)
		for k, v := range g.Members {
			post := ""
			if k == 0 {
				post = " (admin)"
			}
			nick := hex.EncodeToString(v[:])
			fp := "UNKNOWN"
			pid, err := z.addressBookFind(v)
			if err == nil {
				nick = pid.Nick
				fp = pid.Fingerprint()
			}
			z.PrintfT(-1, "    %v %v %v",
				fp,
				z.settings.PmColor+nick+RESET,
				post)
		}
	default:
		z.PrintfT(-1, "invalid /list gc command")
		return
	}
}

func (z *ZKC) list(args []string) {
	if len(args) < 2 {
		// should not be reached
		return
	}
	switch strings.ToLower(args[1]) {
	case "c", "conversations":
		z.PrintfT(-1, "Conversations:")
		z.listConversations()
	case "a", "addressbook":
		z.PrintfT(-1, "Address book:")
		z.listAddressBook()
	case "gc", "groupchat":
		z.listGroupchat(args)
	case "invites":
		z.listInvites(args)
	case "joins":
		z.listJoins(args)
	default:
		z.PrintfT(-1, "invalid list command: %v", args[1])
	}
}

type ZKC struct {
	*debug.Debug
	settings *Settings

	mw    *mainWindow // main window
	ttkMW *ttk.Window // main window

	ttkWW *ttk.Window // welcome window

	ttkAW *ttk.Window // accept server fingerprint window

	ttkACFPW *ttk.Window // accept client fingerprint window

	kw    *kxWindow   // kx window
	ttkKW *ttk.Window // kx window

	kaw    *kxAcceptWindow // kx accept window
	ttkKAW *ttk.Window     // kx accept window

	cctx *completion // completion context

	serverAddress  string
	serverIdentity *zkidentity.PublicIdentity
	id             *zkidentity.FullIdentity

	// kx provides encrypted transport
	write           sync.Mutex    // connection write mutex
	lastTick        time.Time     // keepalive ticker
	lastDuration    time.Duration // how many seconds before next ping
	pingInProgress  bool          // waiting on pong?
	kx              *session.KX
	cert            []byte // remote cert for outer fingerprint
	provisionalCert []byte // used when cert changed
	tagStack        *tagstack.TagStack
	tagCallback     []func() // what to do when tag is acknowledged
	chunkSize       uint64   // max chunk size, provided by server
	msgSize         uint     // max message size, provided by server
	attachmentSize  uint64   // max attachment size, provided by server
	directory       bool     // whether the server is in directory mode

	// new rpc writer
	done   chan struct{}    // shut it down
	lo     chan wireMsg     // low priority data channel
	hi     chan wireMsg     // high priority message channel
	depth  chan struct{}    // return queue depth
	queueW chan *queueDepth // return queue depth

	// online is a hint to indicate if we are in session phase
	online  bool // currently online
	offline bool // forced offline

	// fields that require locking
	sync.RWMutex
	active       int // index to visible conversation
	conversation []*conversation
	groups       map[string]rpc.GroupList

	// locks itself
	ab *addressbook.AddressBook

	ratchetMtx             sync.Mutex
	pendingIdentitiesMutex sync.Mutex
	pendingIdentities      map[string]*time.Time
}

const (
	idZKC = iota
	idRPC
	idSnd

	tagDepth = 32

	historyFilename = "history"
	inboundDir      = "inbound"
	logsDir         = "logs"
	spoolDir        = "spool"
	groupchatDir    = "groupchat"
)

func (z *ZKC) saveServerRecord(pid *zkidentity.PublicIdentity,
	cert []byte) error {

	// prepare identity to be pushed into ini file
	var b, myid bytes.Buffer
	_, err := xdr.Marshal(&b, pid)
	if err != nil {
		return fmt.Errorf("Could not marshal server identity")
	}
	_, err = xdr.Marshal(&myid, z.id)
	if err != nil {
		return fmt.Errorf("Could not marshal identity")
	}

	// save server as our very own
	server, err := inidb.New(path.Join(z.settings.Root,
		tools.ZKCServerFilename), true, 10)
	if err != nil && err != inidb.ErrCreated {
		return fmt.Errorf("could not open server file: %v", err)
	}
	err = server.Set("", "server", z.serverAddress)
	if err != nil {
		return fmt.Errorf("could not insert record server")
	}
	err = server.Set("", "serveridentity",
		base64.StdEncoding.EncodeToString(b.Bytes()))
	if err != nil {
		return fmt.Errorf("could not insert record serveridentity")
	}
	err = server.Set("", "servercert",
		base64.StdEncoding.EncodeToString(cert))
	if err != nil {
		return fmt.Errorf("could not insert record servercert")
	}
	err = server.Set("", "myidentity",
		base64.StdEncoding.EncodeToString(myid.Bytes()))
	if err != nil {
		return fmt.Errorf("could not insert record myidentity")
	}
	err = server.Save()
	if err != nil {
		return fmt.Errorf("could not save server: %v", err)
	}

	return nil
}

func (z *ZKC) preSessionPhase() (net.Conn, *tls.ConnectionState, error) {
	if z.serverAddress == "" {
		return nil, nil, fmt.Errorf("invalid server address")
	}

	conn, err := tls.DialWithDialer(&net.Dialer{
		Deadline:  time.Now().Add(5 * time.Second),
		KeepAlive: time.Second,
	}, "tcp", z.serverAddress, tlsConfig())
	if err != nil {
		z.Dbg(idZKC, "tls.Dial: %v", err)
		return nil, nil, fmt.Errorf("could not dial: %v", err)
	}

	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) != 1 {
		return nil, nil, fmt.Errorf("unexpected certificate chain")
	}

	return conn, &cs, nil
}

func (z *ZKC) sessionPhase(conn net.Conn) (*session.KX, error) {
	if z.id == nil || z.serverIdentity == nil {
		return nil, fmt.Errorf("can not go full session prior to dial")
	}

	// tell remote we want to go full session
	_, err := xdr.Marshal(conn, rpc.InitialCmdSession)
	if err != nil {
		return nil, fmt.Errorf("could not marshal session command")
	}

	// session with server and use a default msgSize
	kx := new(session.KX)
	kx.Conn = conn
	kx.MaxMessageSize = z.msgSize
	kx.OurPublicKey = &z.id.Public.Key
	kx.OurPrivateKey = &z.id.PrivateKey
	kx.TheirPublicKey = &z.serverIdentity.Key
	err = kx.Initiate()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("could not complete key exchange: %v", err)
	}

	return kx, nil
}

// lock must be held
func (z *ZKC) welcomePhase(kx *session.KX) (*rpc.Welcome, error) {
	// obtain Welcome/
	var (
		command rpc.Message
		wmsg    rpc.Welcome
	)

	// read command
	cmd, err := kx.Read()
	if err != nil {
		if xdr.IsIO(err) {
			return nil, fmt.Errorf("connection closed")
		}
		return nil, fmt.Errorf("invalid Welcome header")
	}

	// unmarshal header
	br := bytes.NewReader(cmd)
	_, err = xdr.Unmarshal(br, &command)
	if err != nil {
		return nil, fmt.Errorf("unmarshal Welcome header failed")
	}

	switch command.Command {
	case rpc.SessionCmdUnwelcome:
		// unmarshal payload
		var umsg rpc.Unwelcome
		_, err = xdr.Unmarshal(br, &umsg)
		if err != nil {
			return nil, fmt.Errorf("unmarshal Unwelcome payload " +
				"failed")
		}
		return nil, fmt.Errorf("unwelcome reason %v",
			umsg.Reason)
	case rpc.SessionCmdWelcome:
	default:
		return nil, fmt.Errorf("expected (un)welcome command")
	}

	// unmarshal payload
	_, err = xdr.Unmarshal(br, &wmsg)
	if err != nil {
		return nil, fmt.Errorf("unmarshal Welcome payload failed")
	}

	if wmsg.Version != rpc.ProtocolVersion {
		return nil, fmt.Errorf("protocol version mismatch: "+
			"got %v wanted %v",
			wmsg.Version,
			rpc.ProtocolVersion)
	}

	// deal with server properties
	var (
		td  int64  = -1
		pt  int64  = -1
		cs  uint64 = 0
		ms  uint64 = 0
		as  uint64 = 0
		dir bool   = false
	)
	if z.settings.Debug {
		z.Dbg(idRPC, "remote properties:")
		for _, v := range wmsg.Properties {
			z.Dbg(idRPC, "%v = %v %v", v.Key, v.Value, v.Required)
		}
	}
	for _, v := range wmsg.Properties {
		switch v.Key {
		case rpc.PropTagDepth:
			td, err = strconv.ParseInt(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid tag depth: %v",
					err)
			}

		case rpc.PropServerTime:
			pt, err = strconv.ParseInt(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid server time: %v",
					err)
			}

		case rpc.PropMaxChunkSize:
			cs, err = strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid max chunk "+
					"size: %v", err)
			}

		case rpc.PropMaxMsgSize:
			ms, err = strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid max chunk "+
					"size: %v", err)
			}

		case rpc.PropMaxAttachmentSize:
			as, err = strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid attachment "+
					"chunk size: %v", err)
			}

		case rpc.PropMOTD:
			// ignore here, handled later

		case rpc.PropDirectory:
			dir, err = strconv.ParseBool(v.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid directory "+
					"setting: %v", err)
			}

		default:
			return nil, fmt.Errorf("unhandled property: %v", v.Key)
		}
	}

	// tag depth
	if td == -1 {
		return nil, fmt.Errorf("server did not provide tag depth")
	}
	if td > tagDepth {
		return nil, fmt.Errorf("invalid tag depth: %v", td)
	}

	// server time
	if pt == -1 {
		return nil, fmt.Errorf("server did not provide time")
	}
	z.PrintfT(idZKC, "NOTE: server provided time %v",
		time.Unix(pt, 0).Format(z.settings.TimeFormat))

	// attachment size
	if as == 0 {
		return nil, fmt.Errorf("server did not provide attachment size")
	}

	// chunk size
	if cs == 0 {
		return nil, fmt.Errorf("server did not provide chunk size")
	}

	// message size
	if ms == 0 {
		return nil, fmt.Errorf("server did not provide chunk size")
	}
	if ms < cs {
		return nil, fmt.Errorf("message size < chunk size")
	}

	// directory mode
	if dir {
		z.PrintfT(idZKC, "NOTE: by policy the server allows "+
			"automatic identity exchanges")
	}

	// at this point we are going to use tags
	z.tagStack = tagstack.New(int(td))
	z.tagCallback = make([]func(), int(td))
	z.kx = kx
	z.online = true
	z.chunkSize = cs
	z.msgSize = uint(ms)
	z.attachmentSize = as
	z.directory = dir

	return &wmsg, nil
}

// goOnline goes through all phases of a connection with a server.
// If successful z.kx can be used to send commands back and forth.
func (z *ZKC) goOnline() (*rpc.Welcome, error) {
	z.Lock()
	defer z.Unlock()

	if z.online {
		return nil, fmt.Errorf("already online")
	}

	conn, cs, err := z.preSessionPhase()
	if err != nil {
		return nil, err
	}

	// XXX check cert here
	if !bytes.Equal(cs.PeerCertificates[0].Raw, z.cert) {
		z.provisionalCert = cs.PeerCertificates[0].Raw
		return nil, errCert
	}

	kx, err := z.sessionPhase(conn)
	if err != nil {
		return nil, err
	}

	welcome, err := z.welcomePhase(kx)
	if err != nil {
		return nil, err
	}

	go z.handleRPC()

	return welcome, nil
}

//
func (z *ZKC) goOnlineAndPrint() error {
	welcome, err := z.goOnline()
	switch {
	case err == errCert:
		z.PrintfT(0, REDBOLD+"Server connection disallowed: "+
			"certificate changed"+RESET)
		z.PrintfT(0, REDBOLD+"New fingerprint: %v"+RESET,
			tools.Fingerprint(z.provisionalCert))
		z.PrintfT(0, REDBOLD+"To accept new certificate type "+
			"/acceptnewcert followed by /online"+RESET)
	case err != nil:
		z.PrintfT(0, "Could not connect to server: %v", err)
	default:
		err = z.welcomeUser(welcome)
	}

	return err
}

func (z *ZKC) goOnlineRetry() {
	d := 30 * time.Second
	timer := time.NewTimer(d)
	for {
		z.RLock()
		if z.offline {
			z.RUnlock()
			return
		}
		z.RUnlock()

		<-timer.C
		z.RLock()
		if z.online {
			z.RUnlock()
			continue
		}
		z.RUnlock()

		z.PrintfT(0, "Trying to reconnect to: %v",
			z.serverAddress)
		err := z.goOnlineAndPrint()
		if err == errCert {
			// give up
			return
		}
		timer.Reset(d)
	}
}

// nickFromId looks up an ID and returns a nick. If ID is not found it returns
// an empty string.
func (z *ZKC) nickFromId(id [zkidentity.IdentitySize]byte) string {
	i, err := z.ab.FindIdentity(id)
	if err != nil || i == nil {
		return ""
	}
	return i.Nick
}

func (z *ZKC) PrintIdentity(id zkidentity.PublicIdentity) {
	z.PrintfT(0, "found %s (%s), fingerprint %s", id.Nick, id.Name,
		base64.StdEncoding.EncodeToString(id.Identity[:]))
}

func (z *ZKC) step1IDKX(id zkidentity.PublicIdentity) error {
	nc, nk, err := sntrup4591761.Encapsulate(rand.Reader, &id.Key)
	if err != nil {
		return fmt.Errorf("could not encapsulate key: %v", err)
	}

	r := ratchet.New(rand.Reader)
	r.MyPrivateKey = &z.id.PrivateKey
	r.MySigningPublic = &z.id.Public.SigKey
	r.TheirIdentityPublic = &id.Identity
	r.TheirPublicKey = &id.Key

	kxRatchet := new(ratchet.KeyExchange)
	err = r.FillKeyExchange(kxRatchet)
	if err != nil {
		return fmt.Errorf("could not setup ratchet key: %v", err)
	}

	idkx := rpc.IdentityKX{
		Identity: z.id.Public,
		KX:       *kxRatchet,
	}
	idkxXDR := &bytes.Buffer{}
	_, err = xdr.Marshal(idkxXDR, idkx)
	if err != nil {
		return fmt.Errorf("could not marshal identityKX: %v", err)
	}

	encrypted, nonce, err := blobshare.Encrypt(idkxXDR.Bytes(), nk)
	if err != nil {
		return fmt.Errorf("could not encrypt IdentityKX: %v", err)
	}

	packed := blobshare.PackNonce(nonce, encrypted)
	payload := append(nc[:], packed...)

	z.Dbg(0, "[InitiateKX]: nk = %v", nk)
	z.Dbg(0, "[InitiateKX]: nc = %v", nc)

	err = z.cache(id.Identity, payload)
	if err != nil {
		return fmt.Errorf("could not send IdentityKX: %v", err)
	}

	err = z.saveIdentity(id)
	if err != nil {
		return fmt.Errorf("could not save identity: %v", err)
	}

	err = z.saveKey(nk)
	if err != nil {
		return fmt.Errorf("could not save key: %v", err)
	}

	z.ratchetMtx.Lock()
	defer z.ratchetMtx.Unlock()
	err = z.updateRatchet(r, true)
	if err != nil {
		return fmt.Errorf("could not save half ratchet: %v", err)
	}

	return nil
}

// handleRPC deals with all incoming RPC commands.  It shall be called as a go
// routine.
func (z *ZKC) handleRPC() {
	var exitError error

	var wg sync.WaitGroup
	quit := make(chan struct{})

	// go offline
	defer func() {
		close(quit)
		wg.Wait()

		z.Lock()
		z.online = false
		z.kx.Close()
		z.kx = nil
		z.Unlock()

		if exitError != nil {
			z.Dbg(idRPC, "connection error: %v", exitError)
			z.PrintfT(0, "connection error: %v", exitError)
		} else {
			z.Dbg(idRPC, "server connection closed: %v",
				z.serverAddress)
			z.PrintfT(0, "server connection closed: %v",
				z.serverAddress)
		}

		go z.goOnlineRetry() // try to reconnect
	}()

	// heartbeat, needed because OpenBSD does not do TCP KEEPALIVE
	//
	// This should be removed ASAP!
	wg.Add(1)
	go func() {
		defer func() {
			z.write.Lock()
			z.pingInProgress = false
			z.write.Unlock()

			wg.Done()
		}()

		// we tick more often to see if we have expired keepalive
		timer := time.NewTicker(1 * time.Second)
		retry := 2
		for {
			select {
			case <-quit:
				return

			case <-timer.C:
				z.write.Lock()
				if z.pingInProgress {
					if time.Now().After(z.lastTick) {
						// should have gotten a ping
						//z.PrintfT(0, "pong timeout")
						z.kx.Close()
					}
					z.write.Unlock()
					continue
				}
				if !time.Now().After(z.lastTick) {
					z.write.Unlock()
					continue
				}
				z.write.Unlock()

				tag, err := z.tagStack.Pop()
				if err != nil {
					retry--
					if retry == 0 {
						// XXX this is bad, think about
						// it some more
						z.PrintfT(0, "could not obtain"+
							" tag or heartbeat: %v",
							err)
						z.kx.Close()
						return
					}
				}
				//z.PrintfT(0, "ping %v", tag)
				z.write.Lock()
				z.pingInProgress = true
				z.lastTick = time.Now().Add(z.lastDuration)
				z.write.Unlock()
				z.schedulePRPC(true,
					rpc.Message{
						Command: rpc.TaggedCmdPing,
						Tag:     tag,
					},
					rpc.Ping{})
				retry = 2
			}
		}
	}()

	for {
		var message rpc.Message

		// read message
		cmd, err := z.kx.Read()
		if err != nil {
			if xdr.IsIO(err) {
				z.Dbg(idZKC, "connection closed")
				return
			}
			if err == session.ErrDecrypt {
				exitError = fmt.Errorf("invalid header: %v", err)
			} else {
				exitError = fmt.Errorf("kx.Read: invalid header")
			}
			return
		}

		// unmarshal header
		br := bytes.NewReader(cmd)
		_, err = xdr.Unmarshal(br, &message)
		if err != nil {
			exitError = fmt.Errorf("unmarshal header failed")
			return
		}

		if z.settings.Debug && message.Command != rpc.TaggedCmdPong {
			z.Dbg(idZKC, "received command %v tag %v",
				message.Command,
				message.Tag)
		}

		// unmarshal payload
		switch message.Command {
		case rpc.TaggedCmdPong:
			var p rpc.Pong
			_, err = xdr.Unmarshal(br, &p)
			if err != nil {
				exitError = fmt.Errorf("unmarshal Pong")
				return
			}

			// free tag
			err = z.tagStack.Push(message.Tag)
			if err != nil {
				exitError = fmt.Errorf("Pong invalid tag: %v",
					message.Tag)
				return
			}

			//z.PrintfT(0, "pong %v", message.Tag)

			// reset timer
			z.write.Lock()
			z.lastTick = time.Now().Add(z.lastDuration)
			z.pingInProgress = false
			z.write.Unlock()

		case rpc.TaggedCmdRendezvousReply:
			var r rpc.RendezvousReply
			_, err = xdr.Unmarshal(br, &r)
			if err != nil {
				exitError = fmt.Errorf("unmarshal RendezvousReply")
				return
			}
			if r.Error != "" {
				z.PrintfT(0, "key exchange failed: %v", r.Error)
			} else {
				z.PrintfT(0, "key exchange PIN: %v", r.Token)
			}
			err = z.tagStack.Push(message.Tag)
			if err != nil {
				exitError = fmt.Errorf("RendezvousReply "+
					"invalid tag: %v", message.Tag)
				return
			}

		case rpc.TaggedCmdRendezvousPullReply:
			var r rpc.RendezvousPullReply
			_, err = xdr.Unmarshal(br, &r)
			if err != nil {
				exitError = fmt.Errorf("unmarshal " +
					"RendezvousPullReply")
				return
			}
			if r.Error != "" {
				z.PrintfT(0, "fetch failed: %v", r.Error)
			} else {
				z.kaw.rendezvousPullReply = &r
				ttk.Focus(z.ttkKAW)
			}
			err = z.tagStack.Push(message.Tag)
			if err != nil {
				exitError = fmt.Errorf("RendezvousPullReply "+
					"invalid tag: %v", message.Tag)
				return
			}

		case rpc.TaggedCmdPush:
			var p rpc.Push
			_, err = xdr.Unmarshal(br, &p)
			if err != nil {
				exitError = fmt.Errorf("unmarshal Push")
				return
			}

			z.Dbg(idZKC, "handle CRPC %v tag %v from %v",
				message.Command,
				message.Tag,
				hex.EncodeToString(p.From[:]))

			err = z.handlePush(message, p)
			if err != nil {
				// Try to find nick
				from := hex.EncodeToString(p.From[:])
				rid, err2 := z.addressBookFind(p.From)
				if err2 == nil {
					from = rid.Nick
				}

				var ms string
				switch err.(type) {
				case *ratchetError:
					ms = fmt.Sprintf("push ratchet error "+
						"from %v: %v", from, err)
				default:
					ms = fmt.Sprintf("could not handle "+
						"push command from %v: %v",
						from, err)
				}

				// don't return because even though this is
				// fatal, we are trying to ack so that the
				// server deletes the command and maybe we can
				// recover
				z.Error(idZKC, ms)
				z.PrintfT(0, REDBOLD+ms+RESET)
				z.PrintfT(0, "deleting remote message")
			}

			// send ack
			z.schedulePRPC(true,
				rpc.Message{
					Command: rpc.TaggedCmdAcknowledge,
					Tag:     message.Tag,
				},
				rpc.Acknowledge{})

		case rpc.TaggedCmdAcknowledge:
			var a rpc.Acknowledge
			_, err = xdr.Unmarshal(br, &a)
			if err != nil {
				exitError = fmt.Errorf("unmarshal " +
					"Acknowledge")
				return
			}

			z.Lock()
			if message.Tag > uint32(len(z.tagCallback)) {
				exitError = fmt.Errorf("Acknowledge "+
					"invalid tag: %v", message.Tag)
				z.Unlock()
				return
			}
			f := z.tagCallback[message.Tag]
			z.tagCallback[message.Tag] = nil
			z.Unlock()

			// push tag
			err = z.tagStack.Push(message.Tag)
			if err != nil {
				exitError = fmt.Errorf("Push "+
					"invalid tag: %v", message.Tag)
				return
			}

			if a.Error != "" {
				z.PrintfT(-1, REDBOLD+"cache error: %v"+RESET,
					a.Error)
			}

			// handle callback
			if f != nil {
				z.Dbg(idZKC, "ack tag %v callback", message.Tag)
				go f()
			}

		case rpc.TaggedCmdIdentityFindReply:
			var r rpc.IdentityFindReply
			_, err = xdr.Unmarshal(br, &r)
			if err != nil {
				exitError = fmt.Errorf("unmarshal " +
					"IdentityFindReply")
				return
			}

			if r.Nick == "" {
				z.PrintfT(0, "Server did not return nick")
			} else {
				z.pendingIdentitiesMutex.Lock()
				delete(z.pendingIdentities, r.Nick)
				z.pendingIdentitiesMutex.Unlock()
			}

			err = z.tagStack.Push(message.Tag)
			if err != nil {
				exitError = fmt.Errorf("IdentityFindReply "+
					"invalid tag: %v", message.Tag)
				return
			}

			if r.Error != "" {
				// Server error is verbose so just print it
				z.PrintfT(0, "%v", r.Error)
			} else {
				err = z.step1IDKX(r.Identity)
				if err != nil {
					z.PrintfT(0, "%v", err)
				}
			}

		case rpc.TaggedCmdProxyReply:
			var p rpc.ProxyReply
			_, err = xdr.Unmarshal(br, &p)
			if err != nil {
				exitError = fmt.Errorf("unmarshal " +
					"ProxyReply")
				return
			}

			err = z.tagStack.Push(message.Tag)
			if err != nil {
				exitError = fmt.Errorf("ProxyReply "+
					"invalid tag: %v", message.Tag)
				return
			}

			// Best effort nick
			nick := z.nickFromId(p.To)
			n := nick
			if n != "" {
				n += " "
			}

			if p.Error != "" {
				// Server error is verbose so just print it
				z.FloodfT(nick, "%v", p.Error)
			} else {
				z.FloodfT(nick, REDBOLD+"Awaiting kx %v%x"+RESET,
					n, p.To)
			}

		default:
			exitError = fmt.Errorf("unhandled message %v tag %v",
				message.Command, message.Tag)
			return
		}
	}
}

func (z *ZKC) cache(to [32]byte, blob []byte) error {
	if !z.isOnline() {
		return fmt.Errorf("not online")
	}

	tag, err := z.tagStack.Pop()
	if err != nil {
		return fmt.Errorf("could not obtain tag: %v", err)
	}

	z.schedulePRPC(true,
		rpc.Message{
			Command: rpc.TaggedCmdCache,
			Tag:     tag,
		},
		rpc.Cache{
			To:      to,
			Payload: blob,
		})

	return nil
}

func (z *ZKC) rendezvous(blob []byte) error {
	if !z.isOnline() {
		return fmt.Errorf("not online")
	}

	tag, err := z.tagStack.Pop()
	if err != nil {
		return fmt.Errorf("could not obtain tag: %v", err)
	}

	z.schedulePRPC(true,
		rpc.Message{
			Command: rpc.TaggedCmdRendezvous,
			Tag:     tag,
		},
		rpc.Rendezvous{
			Blob:       blob,
			Expiration: strconv.Itoa(int(24)),
		})

	return nil
}

func (z *ZKC) parseMyServer(server *inidb.INIDB) error {
	var err error

	// server
	z.serverAddress, err = server.Get("", "server")
	if err != nil {
		return fmt.Errorf("could not obtain server record")
	}

	// serveridentity
	pib64, err := server.Get("", "serveridentity")
	if err != nil {
		return fmt.Errorf("could not obtain serveridentity record")
	}
	piXDR, err := base64.StdEncoding.DecodeString(pib64)
	if err != nil {
		return fmt.Errorf("could not decode serveridentity")
	}
	br := bytes.NewReader(piXDR)
	_, err = xdr.Unmarshal(br, &z.serverIdentity)
	if err != nil {
		return fmt.Errorf("could not unmarshal serveridentity")
	}
	pc64, err := server.Get("", "servercert")
	if err != nil {
		return fmt.Errorf("could not obtain servercert record")
	}
	z.cert, err = base64.StdEncoding.DecodeString(pc64)
	if err != nil {
		return fmt.Errorf("could not decode servercert")
	}

	return nil
}

func (z *ZKC) parseMyIdentity(server *inidb.INIDB) error {
	// myidentity
	myidb64, err := server.Get("", "myidentity")
	if err != nil {
		return fmt.Errorf("could not obtain myidentity record")
	}
	myidXDR, err := base64.StdEncoding.DecodeString(myidb64)
	if err != nil {
		return fmt.Errorf("could not decode myidentity")
	}
	br := bytes.NewReader(myidXDR)
	_, err = xdr.Unmarshal(br, &z.id)
	if err != nil {
		return fmt.Errorf("could not unmarshal myidentity")
	}

	return nil
}

func (z *ZKC) welcomeUser(welcome *rpc.Welcome) error {
	remoteId, ok := z.kx.TheirIdentity().([32]byte)
	if !ok {
		return fmt.Errorf("invalid KX identity type %T", remoteId)
	}
	rid := hex.EncodeToString(remoteId[:])
	z.Dbg(idZKC, "connected to server identity: %v", rid)

	z.PrintfT(0, "Connected to server: %v", z.serverAddress)
	if z.settings.TLSVerbose {
		// PeerCertificates have been checked to exist before we get here
		z.PrintfT(0, "Outer server fingerprint: %v",
			tools.Fingerprint(z.cert))
		z.PrintfT(0, "Inner server fingerprint: %v",
			z.serverIdentity.Fingerprint())
	} else {
		z.PrintfT(0, "Server fingerprint: %v",
			z.serverIdentity.Fingerprint())
	}

	// see if we have MOTD
	for _, v := range welcome.Properties {
		if v.Key != rpc.PropMOTD {
			continue
		}

		// split out MOTD
		motd := strings.Split(v.Value, "\n")
		for _, v := range motd {
			z.PrintfT(0, "%v", v)
		}
		break
	}

	if len(z.conversation) == 1 {
		_ = restoreConversations(z)
	}

	return nil
}

// fetch tries to obtain a Rendezvous blob using provided pin.
func (z *ZKC) fetch(pin string) error {
	if !z.isOnline() {
		return fmt.Errorf("not online")
	}

	tag, err := z.tagStack.Pop()
	if err != nil {
		return fmt.Errorf("could not obtain tag: %v", err)
	}
	z.schedulePRPC(true,
		rpc.Message{
			Command: rpc.TaggedCmdRendezvousPull,
			Tag:     tag,
		},
		rpc.RendezvousPull{
			Token: pin,
		})

	return nil
}

// find looks up a nickname on the server's identity directory.
func (z *ZKC) find(nick string) error {
	if !z.isOnline() {
		return fmt.Errorf("not online")
	}
	if !z.directory {
		return fmt.Errorf("directory not supported")
	}
	if nick == "" {
		return fmt.Errorf("must provide nick")
	}
	if nick == z.id.Public.Nick {
		return fmt.Errorf("can't find self")
	}
	_, err := z.ab.FindNick(nick)
	if err == nil {
		return fmt.Errorf("nick already known: %v", nick)
	}

	z.pendingIdentitiesMutex.Lock()
	defer z.pendingIdentitiesMutex.Unlock()

	if z.pendingIdentities == nil {
		z.pendingIdentities = make(map[string]*time.Time)
	}

	if z.pendingIdentities[nick] != nil {
		return fmt.Errorf("lookup already in progress")
	}

	tag, err := z.tagStack.Pop()
	if err != nil {
		return fmt.Errorf("could not obtain tag: %v", err)
	}

	z.schedulePRPC(true,
		rpc.Message{
			Command: rpc.TaggedCmdIdentityFind,
			Tag:     tag,
		},
		rpc.IdentityFind{
			Nick: nick,
		})

	t := time.Now()
	z.pendingIdentities[nick] = &t

	return nil
}

// reset sends an unencrypted proxy message to the server which will be
// forwarded to the correct user in order to initiate a ratchet reset.
func (z *ZKC) reset(nick string) error {
	if !z.isOnline() {
		return fmt.Errorf("not online")
	}

	id, err := z.ab.FindNick(nick)
	if err != nil {
		return err
	}

	pr := rpc.ProxyCmd{
		Command: rpc.ProxyCmdResetRatchet,
		Message: "reset ratchet initiated by: " +
			hex.EncodeToString(z.id.Public.Identity[:]),
	}
	var bb bytes.Buffer
	_, err = xdr.Marshal(&bb, pr)
	if err != nil {
		return fmt.Errorf("could not marshal ProxyResetRatchet: %v",
			err)
	}

	// Pop tag early because we are going to de deleting important files.
	// If something goes wrong we must push the tab back onto the stack.
	returnTag := true // assume failure
	tag, err := z.tagStack.Pop()
	if err != nil {
		return fmt.Errorf("could not obtain tag: %v", err)
	}
	defer func() {
		if returnTag {
			z.tagStack.Push(tag)
		}
	}()

	ids := hex.EncodeToString(id.Identity[:])
	fullPath := path.Join(z.settings.Root, inboundDir, ids)

	// always remove half ratchet
	os.Remove(path.Join(fullPath, halfRatchetFilename))

	// assert any ratchet file exists for sanity
	ratchet := path.Join(fullPath, ratchetFilename)
	_, err = os.Stat(ratchet)
	if err != nil {
		return fmt.Errorf("ratchet file does not exists for %v", nick)
	}

	z.FloodfT(nick, REDBOLD+"Ratchet reset initiated with: %v %v"+RESET,
		nick, ids)

	// delete ratchets from disk
	err = os.Remove(ratchet)
	if err != nil {
		z.FloodfT(nick, "could not remove ratchet for %v: %v",
			nick, err)
	}

	returnTag = false // we no longer need to return the tag

	// try to tell the other side the bad news
	z.schedulePRPC(true,
		rpc.Message{
			Command: rpc.TaggedCmdProxy,
			Tag:     tag,
		},
		rpc.Proxy{
			To:      id.Identity,
			Payload: bb.Bytes(),
		})

	return nil
}

// writeMessage marshals and sends encrypted message to server.
func (z *ZKC) writeMessage(msg *rpc.Message, payload interface{}) error {
	if !z.isOnline() {
		return fmt.Errorf("not online")
	}

	// we lock the ticker, rename write mutex
	defer func() {
		z.write.Lock()
		z.lastTick = time.Now().Add(z.lastDuration)
		z.write.Unlock()
	}()

	msg.TimeStamp = time.Now().Unix() // set timestamp
	var bb bytes.Buffer
	_, err := xdr.Marshal(&bb, msg)
	if err != nil {
		return fmt.Errorf("could not marshal message %v", msg.Command)
	}
	_, err = xdr.Marshal(&bb, payload)
	if err != nil {
		return fmt.Errorf("could not marshal payload %v", msg.Command)
	}

	err = z.kx.Write(bb.Bytes())
	if err != nil {
		return fmt.Errorf("could not write %v: %v",
			msg.Command, err)
	}

	if z.settings.Debug && msg.Command != rpc.TaggedCmdPing {
		z.Dbg(idRPC, "writeMessage: %v tag %v", msg.Command, msg.Tag)
	}

	return nil
}

var (
	errNotAdmin = errors.New("not group administrator")
)

func (z *ZKC) updateGroupList(id [zkidentity.IdentitySize]byte,
	gl rpc.GroupList) error {
	z.Lock()
	defer z.Unlock()

	return z._updateGroupList(id, gl)
}

func (z *ZKC) _updateGroupList(id [zkidentity.IdentitySize]byte,
	gl rpc.GroupList) error {

	group, found := z.groups[gl.Name]
	if !found {
		return fmt.Errorf("group not found: %v", gl.Name)
	}

	if len(group.Members) == 0 {
		return fmt.Errorf("partial group")
	}
	if !bytes.Equal(group.Members[0][:], id[:]) {
		return errNotAdmin
	}

	// Warn if generation is no moving forward
	if gl.Generation <= group.Generation {
		z.Warn(idRPC, "received illegal grouplist generation: %v %v %v",
			gl.Name,
			group.Generation,
			gl.Generation)
	}

	z.groups[gl.Name] = gl
	return z._gcSaveDisk(gl.Name)
}

func (z *ZKC) _addIdGroupchat(gcName string,
	id zkidentity.PublicIdentity) (rpc.GroupList, error) {

	group, found := z.groups[gcName]
	if !found {
		return rpc.GroupList{},
			fmt.Errorf("group not found: %v", gcName)
	}

	for i := 1; i < len(group.Members); i++ {
		if group.Members[i] == id.Identity {
			return rpc.GroupList{},
				fmt.Errorf("identity already in group")
		}
	}

	group.Members = append(group.Members, id.Identity)
	group.Generation++
	z.groups[gcName] = group

	return group, nil
}

func (z *ZKC) loadGroupchat() error {
	fi, err := ioutil.ReadDir(path.Join(z.settings.Root, groupchatDir))
	if err != nil {
		return err
	}

	for _, v := range fi {
		if v.IsDir() {
			continue
		}

		// read
		filename := path.Join(z.settings.Root, groupchatDir, v.Name())
		gcXDR, err := ioutil.ReadFile(filename)
		if err != nil {
			z.PrintfT(0, "read groupchat: %v %v", filename, err)
			continue
		}
		var gc rpc.GroupList
		br := bytes.NewReader(gcXDR)
		_, err = xdr.Unmarshal(br, &gc)
		if err != nil {
			z.PrintfT(0, "unmarshal groupchat: %v", filename)
			continue
		}

		z.Lock()
		// sanity
		_, found := z.groups[gc.Name]
		if found {
			// really shouldn't happen
			z.Unlock()
			z.PrintfT(0, "groupchat already exists: %v", filename)
			continue
		}
		z.groups[gc.Name] = gc
		z.Unlock()
	}

	return nil
}

func (z *ZKC) finalizeAccountCreation(conn net.Conn, cs *tls.ConnectionState,
	pid *zkidentity.PublicIdentity, token string) error {
	// tell server we want to create an account
	_, err := xdr.Marshal(conn, rpc.InitialCmdCreateAccount)
	if err != nil {
		return fmt.Errorf("Connection closed during create account")
	}

	// set fields
	err = z.id.RecalculateDigest()
	if err != nil {
		return fmt.Errorf("Could not recalculate digest: %v", err)
	}

	// send create account rpc
	ca := rpc.CreateAccount{
		PublicIdentity: z.id.Public,
		Token:          token,
	}
	_, err = xdr.Marshal(conn, ca)
	if err != nil {
		return fmt.Errorf("Connection closed while sending create " +
			"account")
	}

	// obtain answer
	var car rpc.CreateAccountReply
	_, err = xdr.Unmarshal(conn, &car)
	if err != nil {
		return fmt.Errorf("Could not obtain create account reply")
	}
	if car.Error != "" {
		return fmt.Errorf("Could not create account: %v", car.Error)
	}

	// save of server identity
	z.serverIdentity = pid
	z.cert = cs.PeerCertificates[0].Raw

	// tell remote we want to go full session
	kx, err := z.sessionPhase(conn)
	if err != nil {
		return err
	}

	// go through welcome phase
	welcome, err := z.welcomePhase(kx)
	if err != nil {
		return err
	}

	err = z.saveServerRecord(pid, cs.PeerCertificates[0].Raw)
	if err != nil {
		return err
	}

	go z.handleRPC()

	z.mw.welcomeMessage()
	err = z.welcomeUser(welcome)
	if err != nil {
		return err
	}
	ttk.Focus(z.ttkMW)
	z.focus(0)

	return nil
}

func _main() error {
	z := &ZKC{
		conversation: make([]*conversation, 1, 16), // 1 is for console
		ab:           addressbook.New(),
		groups:       make(map[string]rpc.GroupList),
		lastDuration: 5 * time.Second,
		msgSize:      uint(rpc.PropMaxMsgSizeDefault),
	}

	// flags and settings
	var err error
	z.settings, err = ObtainSettings()
	if err != nil {
		return err
	}

	// create paths
	err = os.MkdirAll(path.Join(z.settings.Root, inboundDir), 0700)
	if err != nil {
		return err
	}
	err = os.MkdirAll(path.Join(z.settings.Root, logsDir), 0700)
	if err != nil {
		return err
	}
	err = os.MkdirAll(path.Join(z.settings.Root, spoolDir), 0700)
	if err != nil {
		return err
	}
	err = os.MkdirAll(path.Join(z.settings.Root, groupchatDir), 0700)
	if err != nil {
		return err
	}

	// handle logging
	z.Debug, err = debug.New(z.settings.LogFile, z.settings.TimeFormat)
	if err != nil {
		return err
	}
	z.Register(idZKC, "")
	z.Register(idRPC, "[RPC]")
	z.Register(idSnd, "[SND]")

	z.Info(idZKC, "Start of day")
	z.Info(idZKC, "Settings %v", spew.Sdump(z.settings))
	defer z.Info(idZKC, "End of times")

	// debugging
	if z.settings.Debug {
		z.Info(idZKC, "Debug enabled")
		z.EnableDebug()
		if z.settings.Profiler != "" {
			z.Info(idZKC, "Profiler enabled on http://%v/debug/pprof",
				z.settings.Profiler)
			go http.ListenAndServe(z.settings.Profiler, nil)
		}
	}

	// we need to pre create the directory
	err = os.MkdirAll(path.Dir(path.Join(z.settings.Root,
		tools.ZKCServerFilename)), 0700)
	if err != nil {
		return err
	}

	// see if we have a myserver.ini
	var server *inidb.INIDB
	var foundServerIdentity bool
	var foundClientIdentity bool

	filename := path.Join(z.settings.Root, tools.ZKCServerFilename)
	server, err = inidb.New(filename, false, 10)
	if err == nil {
		foundServerIdentity = true
		// obtain all entries from ini
		err = z.parseMyServer(server)
		if err != nil {
			return fmt.Errorf("could not parse myserver: %v",
				err)
		}
	}

	// Parse server identity
	if foundServerIdentity {
		err = z.parseMyIdentity(server)
		if err == nil {
			foundClientIdentity = true
		}
	}

	// Create new user if it doesn't exist
	if !foundClientIdentity {
		z.id, err = zkidentity.New("", "")
		if err != nil {
			// really can't happen
			return fmt.Errorf("could not create new identity")
		}
	}

	// initialize terminal
	err = ttk.Init()
	if err != nil {
		return err
	}
	defer ttk.Deinit()

	// create main window
	z.mw = &mainWindow{
		quitC: make(chan struct{}),
		zkc:   z,
	}
	z.ttkMW = ttk.NewWindow(z.mw)

	// create kx window
	z.kw = &kxWindow{
		zkc: z,
	}
	z.ttkKW = ttk.NewWindow(z.kw)

	// create kx accept window
	z.kaw = &kxAcceptWindow{
		zkc: z,
	}
	z.ttkKAW = ttk.NewWindow(z.kaw)

	// bootstrap all known
	err = z.loadIdentities()
	if err != nil {
		z.PrintfT(0, "loadIdentities: %v", err)
	}

	// read all groupchats from disk
	err = z.loadGroupchat()
	if err != nil {
		z.PrintfT(0, "loadGroupchat: %v", err)
	}

	// setup high and low prio message channels
	z.scheduler()

	if !foundClientIdentity {
		// create and focus on welcome window
		ww := &welcomeWindow{
			zkc: z,
		}
		z.ttkWW = ttk.NewWindow(ww)
		ttk.Focus(z.ttkWW)
	} else {
		// focus on main window
		z.mw.welcomeMessage()
		ttk.Focus(z.ttkMW)
		z.focus(0)

		// go online
		go func() {
			z.goOnlineAndPrint()
		}()
	}

	// update status
	go func() {
		timer := time.NewTicker(1 * time.Second)
		for {
			<-timer.C
			ttk.Queue(func() {
				z.RLock()
				s := z.calculateStatus()
				z.mw.status.SetText(s)
				z.mw.status.Render()
				z.RUnlock()
				ttk.Flush()
			})
		}
	}()

	// populate history
	err = z.mw.readHistory()
	if err != nil {
		return err
	}

	for {
		select {
		case k := <-ttk.KeyChannel():
			switch k.Key {
			// global keys
			case termbox.KeyCtrlQ:
				return nil

			case termbox.KeyCtrlP:
				// previous conversation
				z.prevConversation()

			case termbox.KeyCtrlN:
				// next conversation
				z.nextConversation()

			default:
				if k.Mod == 0 {
					ttk.ForwardKey(k)
					continue
				}

				// special
				switch k.Ch {
				case rune('1'):
					z.focus(1)
				case rune('2'):
					z.focus(2)
				case rune('3'):
					z.focus(3)
				case rune('4'):
					z.focus(4)
				case rune('5'):
					z.focus(5)
				case rune('6'):
					z.focus(6)
				case rune('7'):
					z.focus(7)
				case rune('8'):
					z.focus(8)
				case rune('9'):
					z.focus(9)
				case rune('0'):
					z.focus(0)
				}
			}
		case <-z.mw.quitC:
			return nil
		}
	}

	// not reached
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
