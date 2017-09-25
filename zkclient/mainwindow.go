// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/companyzero/ttk"
	"github.com/companyzero/zkc/inidb"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/companyzero/zkc/zkutil"
	"github.com/davecgh/go-xdr/xdr2"
	"github.com/nsf/termbox-go"
)

const (
	consoleText           = "console"
	conversationsFilename = "conversations/conversations.ini"
)

var (
	statusFG = ttk.ColorWhite // default status foreground
	statusBG = ttk.ColorBlue  // default status background

	RESET, REDBOLD, CYANBOLD, GREENBOLD, WHITEBOLD string // colors
	MAGENTABOLD, YELLOWBOLD                        string

	STATUSWHITEBOLD, STATUSCYAN, STATUSRESET string // status colors
	STATUSMAGENTABOLD                        string
)

func init() {
	RESET, _ = ttk.Color(ttk.AttrReset, ttk.AttrNA, ttk.AttrNA)
	REDBOLD, _ = ttk.Color(ttk.AttrBold, ttk.ColorRed, ttk.AttrNA)
	CYANBOLD, _ = ttk.Color(ttk.AttrBold, ttk.ColorCyan, ttk.AttrNA)
	GREENBOLD, _ = ttk.Color(ttk.AttrBold, ttk.ColorGreen, ttk.AttrNA)
	WHITEBOLD, _ = ttk.Color(ttk.AttrBold, ttk.ColorWhite, ttk.AttrNA)
	MAGENTABOLD, _ = ttk.Color(ttk.AttrBold, ttk.ColorMagenta, ttk.AttrNA)
	YELLOWBOLD, _ = ttk.Color(ttk.AttrBold, ttk.ColorYellow, ttk.AttrNA)

	STATUSWHITEBOLD, _ = ttk.Color(ttk.AttrBold, ttk.ColorWhite, statusBG)
	STATUSCYAN, _ = ttk.Color(ttk.AttrNA, ttk.ColorCyan, statusBG)
	STATUSMAGENTABOLD, _ = ttk.Color(ttk.AttrBold, ttk.ColorMagenta, statusBG)
	STATUSRESET, _ = ttk.Color(ttk.AttrNA, statusFG, statusBG)
}

type mainWindow struct {
	quitC     chan struct{} // quit channel
	zkc       *ZKC          // pointer to client context
	w         *ttk.Window   // underlying window
	cmd       string        // cmdEdit backing buffer
	cmdEdit   *ttk.Edit     // edit widget at the bottom
	title     *ttk.Label    // top title bar
	status    *ttk.Label    // status bar near bottom
	history   []string      // history of all commands
	historyAt int           // current history location
}

func (mw *mainWindow) doUsage(args []string) error {
	for _, v := range helpArray {
		if args[0] != v.command {
			continue
		}
		return fmt.Errorf("invalid command, usage: %v", v.usage)
	}

	return fmt.Errorf("usage not found: %v", args[0])
}

func (mw *mainWindow) doHelp(args []string) error {
	z := mw.zkc

	switch len(args) {
	case 1:
		for _, v := range helpArray {
			z.PrintfT(-1, "%-12v: %v", v.command, v.description)
		}
	case 2:
		for _, v := range helpArray {
			if !(args[1] == v.command || args[1] == v.command[1:]) {
				continue
			}

			z.PrintfT(-1, "description: %v", v.description)
			z.PrintfT(-1, "usage      : %v", v.usage)
			for _, vv := range v.long {
				z.PrintfT(-1, "%v", vv)
			}

			return nil
		}
		return fmt.Errorf("help not found: %v", args[1])

	default:
		return fmt.Errorf("invalid help command")
	}

	return nil
}

// Init shall be called in queue context.
func (mw *mainWindow) Init(w *ttk.Window) {
	mw.w = w

	statusReset, _, _ := ttk.DecodeColor(STATUSRESET)
	// top line
	mw.w = w
	mw.title = w.AddStatus(0, ttk.JustifyLeft, consoleText)
	mw.title.SetAttributes(*statusReset)

	// status bar
	mw.status = w.AddStatus(-2, ttk.JustifyLeft, "")
	mw.status.SetAttributes(*statusReset)

	// bottom edit
	mw.cmdEdit = w.AddEdit(0, -2, 0, &mw.cmd)
	a := ttk.Attributes{
		Fg: termbox.ColorDefault,
		Bg: termbox.ColorDefault,
	}
	mw.cmdEdit.SetAttributes(a)

	// 0 is used for main console
	mw.zkc.Lock()
	mw.zkc.conversation[0] = &conversation{
		console: w.AddList(0, 1, 0, -2),
		nick:    consoleText,
	}
	mw.zkc.Unlock()

	ttk.Flush()
}

// Render shall be called in queue context.
func (mw *mainWindow) Render(w *ttk.Window) {
	// do nothing for now
}

// KeyHandler handles incoming keys on the window.
// This is called from queue context.
func (mw *mainWindow) KeyHandler(w *ttk.Window, k ttk.Key) {
	switch k.Key {
	case termbox.KeyEnter:
		if mw.cmdEdit != k.Widget {
			return
		}

		if len(mw.cmd) == 0 {
			return
		}

		cmd := mw.cmd
		// reset command edit
		// XXX this is racing when pasting
		// we need a blocking setCmd that does not fuck with ttk
		// keyhandler, there is a time.Sleep in ttk to work around
		// this issue
		mw.setCmd("") // XXX not called from queue context!

		// clear completion as well
		mw.zkc.cctx = nil

		// append to history
		mw.appendHistory(cmd)

		err := mw.action(cmd)
		if err != nil {
			mw.zkc.PrintfT(-1, REDBOLD+"%v"+RESET, err)
			mw.zkc.Dbg(idZKC, "mw.action: %v", err)
		}

	case termbox.KeyTab:
		if mw.cmdEdit != k.Widget {
			return
		}

		cmd := mw.cmdEdit.GetText()
		if len(cmd) == 0 {
			return
		}

		// split args
		args := strings.Split(cmd, " ")
		if len(args) == 0 {
			return
		}

		// determine mode
		switch args[0] {
		case cmdMsg, cmdM, cmdInfo, cmdReset, cmdQ, cmdQuery:
			mw.zkc.completeNickCommandLine(args)
		case cmdSend:
			if len(args) == 1 || len(args) == 2 {
				mw.zkc.completeNickCommandLine(args)
			} else if len(args) == 3 {
				// complete path
				mw.zkc.completeDirCommandLine(args)
				return
			}
		default:
			return
		}

	case termbox.KeyArrowUp:
		if mw.historyAt <= 0 {
			return
		}
		mw.historyAt--
		mw.cmd = mw.history[mw.historyAt]
		mw.setCmd(mw.cmd) // XXX not called from queue context!

	case termbox.KeyArrowDown:
		if mw.historyAt >= len(mw.history)-1 {
			mw.historyAt = len(mw.history)
			mw.setCmd("") // XXX not called from queue context!
			return
		}
		mw.historyAt++
		mw.cmd = mw.history[mw.historyAt]
		mw.setCmd(mw.cmd) // XXX not called from queue context!

	case termbox.KeyCtrlL:
		mw.page(ttk.Current)

	case termbox.KeyCtrlT:
		mw.page(ttk.Top)

	case termbox.KeyCtrlB:
		mw.page(ttk.Bottom)

	case termbox.KeyCtrlU, termbox.KeyPgup:
		mw.page(ttk.Up)

	case termbox.KeyCtrlD, termbox.KeyPgdn:
		mw.page(ttk.Down)
	}
}

func (mw *mainWindow) page(where ttk.Location) {
	ttk.Queue(func() {
		mw.zkc.RLock()
		conv := mw.zkc.conversation[mw.zkc.active].console
		conv.Display(where)

		// update status
		s := mw.zkc.calculateStatus()
		mw.status.SetText(s)
		mw.status.Render()

		ttk.Flush()
		mw.zkc.RUnlock()
	})
}

func (mw *mainWindow) welcomeMessage() {
	// bit of an odd spot to set the console identity but code always flows
	// through here
	mw.zkc.Lock()
	mw.zkc.conversation[0].id = &mw.zkc.id.Public
	mw.zkc.Unlock()

	mw.zkc.PrintfT(0, "Welcome to Zero Knowledge Communications!")
	mw.zkc.PrintfT(0, "")
	mw.zkc.PrintfT(0, "Your fingerprint is: %v",
		mw.zkc.id.Public.Fingerprint())
}

// setCmd sets the value of the command line editor and displays it right away.
// This must be called from queue context.
func (mw *mainWindow) setCmd(s string) {
	mw.cmd = s
	mw.cmdEdit.SetText(&mw.cmd, true)
	mw.cmdEdit.Render()
	ttk.Flush()
}

// readHistory recreates command history from the history file.
func (mw *mainWindow) readHistory() error {
	// determine if we have to read it in first
	if !mw.zkc.settings.SaveHistory {
		return nil
	}

	f, err := os.OpenFile(path.Join(mw.zkc.settings.Root, historyFilename),
		os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {

				return nil
			}
			return err
		}
		mw.history = append(mw.history, strings.TrimRight(line, "\r\n"))
		mw.historyAt = len(mw.history)
	}

	// not reached
}

// appendHistory adds a command to the history file.
func (mw *mainWindow) appendHistory(cmd string) {
	if len(cmd) == 0 {
		return
	}

	// in memory
	mw.history = append(mw.history, cmd)
	mw.historyAt = len(mw.history)

	// save off
	if !mw.zkc.settings.SaveHistory {
		return
	}

	f, err := os.OpenFile(path.Join(mw.zkc.settings.Root, historyFilename),
		os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		ttk.Exit("appendHistory: %v", err)
	}
	defer func() { _ = f.Close() }()
	fmt.Fprintf(f, "%v\n", cmd)
}

// action executes a user command.
func (mw *mainWindow) action(cmd string) error {
	if len(cmd) == 0 {
		return nil
	}

	// see if we got a command
	if !strings.HasPrefix(cmd, leader) {
		mw.zkc.RLock()
		if mw.zkc.active != 0 {
			var c string
			if mw.zkc.conversation[mw.zkc.active].group {
				c = cmdGc + " m "
			} else {
				c = cmdM + " "
			}
			cmd = c + mw.zkc.conversation[mw.zkc.active].nick +
				" " + cmd
		}
		mw.zkc.RUnlock()
	}
	//mw.zkc.Dbg(idZKC, "action: [%v]", cmd)

	// split args
	args := strings.Split(cmd, " ")
	if len(args) == 0 {
		return nil
	}
	// strip at least first three args
	for k, v := range args {
		if k > 2 {
			break
		}
		args[k] = strings.Trim(v, " ")
	}

	switch args[0] {
	case cmdAcceptnewcert:
		mw.zkc.Lock()
		if mw.zkc.online || mw.zkc.provisionalCert == nil {
			mw.zkc.Unlock()
			return fmt.Errorf("nothing to do")
		}

		err := mw.zkc.saveServerRecord(mw.zkc.serverIdentity,
			mw.zkc.provisionalCert)
		if err != nil {
			mw.zkc.Unlock()
			return fmt.Errorf("could not save server record: %v",
				err)
		}

		mw.zkc.cert = mw.zkc.provisionalCert
		mw.zkc.provisionalCert = nil
		mw.zkc.Unlock()

		mw.zkc.PrintfT(0, "Server certificate saved")

		return nil

	case cmdOnline:
		// error is handled in function
		mw.zkc.Lock()
		mw.zkc.offline = false
		mw.zkc.Unlock()
		return mw.zkc.goOnlineAndPrint()

	case cmdOffline:
		// error is handled in function
		mw.zkc.Lock()
		if mw.zkc.online {
			mw.zkc.offline = true
			mw.zkc.kx.Close()
		}
		mw.zkc.Unlock()
		return nil

	case cmdKx:
		mw.zkc.RLock()
		if !mw.zkc.online {
			mw.zkc.RUnlock()
			return fmt.Errorf("zkc not online")
		}
		mw.zkc.RUnlock()
		ttk.Focus(mw.zkc.ttkKW)
		return nil

	case cmdFetch:
		if len(args) != 2 {
			return mw.doUsage(args)
		}
		return mw.zkc.fetch(args[1])

	case cmdSend:
		if len(args) < 3 {
			return mw.doUsage(args)
		}

		// remove /send <nick> <filename>
		desc := strings.TrimSpace(strings.TrimPrefix(cmd, cmdSend))
		desc = strings.TrimSpace(strings.TrimPrefix(desc, args[1]))
		desc = strings.TrimRight(strings.TrimPrefix(desc, args[2]+" "),
			" ")
		if desc == args[2] {
			// this happens when desc is empty
			desc = ""
		}

		c, win, err := mw.zkc.addressBookConversation(args[1])
		if err != nil {
			return err
		}
		_ = c

		err = mw.zkc.send(c.id.Identity, args[1], args[2], desc)
		if err != nil {
			return err
		}

		// echo
		mw.zkc.PrintfT(win, "initiated file transfer to %v: %v",
			args[1], args[2])

		return nil

	case cmdMe:
		if len(args) < 2 {
			return mw.doUsage(args)
		}

		var (
			c *conversation
		)
		mw.zkc.RLock()
		if mw.zkc.active != 0 {
			c = mw.zkc.conversation[mw.zkc.active]
			if c == nil {
				mw.zkc.RUnlock()
				return fmt.Errorf("invalid conversation")
			}
		} else {
			mw.zkc.RUnlock()
			return fmt.Errorf(cmdMe + " invalid on console")
		}
		mw.zkc.RUnlock()

		msg := strings.TrimSpace(strings.TrimPrefix(cmd, args[0]))

		if c.group {
			// just fake it
			a := []string{"/gc", "me", c.nick, msg}
			return mw.zkc.gcMessage(a, msg, rpc.MessageModeMe)
		} else {
			err := mw.zkc.pm(c.id.Identity, msg, rpc.MessageModeMe)
			if err != nil {
				return err
			}
		}

		// echo
		mw.zkc.PrintfT(-1, "* %v %v",
			mw.zkc.settings.NickColor+mw.zkc.id.Public.Nick+RESET,
			msg)

		return nil

	case cmdMsg, cmdM:
		if len(args) < 3 {
			return mw.doUsage(args)
		}
		// remove /m|/msg <identity>
		msg := strings.TrimSpace(strings.TrimPrefix(cmd, args[0]))
		msg = strings.TrimRight(strings.TrimPrefix(msg, args[1]+" "), " ")

		// determine if to is a nick or an identity
		var (
			c   *conversation
			win int
			err error
		)
		mw.zkc.RLock()
		for k, v := range mw.zkc.conversation {
			if v == nil {
				continue
			}
			if args[1] == v.nick {
				c = v
				win = k
				break
			}
		}
		mw.zkc.RUnlock()

		if c == nil {
			c, win, err = mw.zkc.addressBookConversation(args[1])
			if err != nil {
				return err
			}
		}

		err = mw.zkc.pm(c.id.Identity, msg, rpc.MessageModeNormal)
		if err != nil {
			return err
		}
		// echo
		mw.zkc.PrintfT(win, "<%v> %v",
			mw.zkc.settings.NickColor+mw.zkc.id.Public.Nick+RESET,
			msg)

		return nil

	case cmdInfo:
		if len(args) == 1 {
			mw.zkc.printID(&mw.zkc.id.Public)
			return nil
		}
		if len(args) == 2 {
			pid, err := mw.zkc.ab.FindNick(args[1])
			if err != nil {
				if mw.zkc.id.Public.Nick == args[1] {
					// handle self too
					mw.zkc.printID(&mw.zkc.id.Public)
					return nil
				} else {
					return fmt.Errorf("nick not found: %v",
						args[1])
				}
			}
			mw.zkc.printID(pid)
			return nil
		}

		return mw.doUsage(args)

	case cmdGc:
		if len(args) < 2 {
			return mw.doUsage(args)
		}
		return mw.zkc.gc(cmd, args)

	case cmdList:
		if len(args) < 2 {
			return mw.doUsage(args)
		}
		mw.zkc.list(args)
		return nil

	case cmdW, cmdWin:
		if len(args) != 2 {
			return mw.doUsage(args)
		}
		x, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid window")
		}
		mw.zkc.focus(int(x))
		return nil

	case cmdWc:
		if len(args) != 1 {
			return mw.doUsage(args)
		}

		mw.zkc.Lock()
		defer mw.zkc.Unlock()
		if mw.zkc.active <= 0 ||
			mw.zkc.active > len(mw.zkc.conversation)-1 {
			return nil
		}

		// delete conversation from list
		i := mw.zkc.active
		mw.zkc.conversation[i].console.Visibility(ttk.VisibilityHide)
		mw.zkc.conversation = append(mw.zkc.conversation[:i:i],
			mw.zkc.conversation[i+1:]...)
		mw.zkc.focus(0)

		return nil

	case cmdRestore:
		restoreConversations(mw.zkc)
		return nil

	case cmdQ, cmdQuery:
		if len(args) != 2 {
			return mw.doUsage(args)
		}
		mw.zkc.query(args[1])
		return nil

	case cmdQuit:
		if len(args) == 2 {
			if args[1] == "force" {
				close(mw.quitC)
				return nil
			}
		}

		qd, err := mw.zkc.queueDepth()
		if err != nil {
			// just exit
		} else {
			if qd.hi != 0 || qd.lo != 0 {
				return fmt.Errorf("queue not empty, to " +
					"force quit type: /quit force")
			}
		}

		close(mw.quitC)
		return nil

	case cmdVersion:
		mw.zkc.PrintfT(-1, "Version: %v, RPC Protocol: %v",
			zkutil.Version(), rpc.ProtocolVersion)
		return nil

	case cmdHelp:
		return mw.doHelp(args)

	case cmdReset:
		if len(args) != 2 {
			return mw.doUsage(args)
		}
		err := mw.zkc.reset(args[1])
		if err != nil {
			mw.zkc.PrintfT(-1, "reset failed: %v", err)
		}
		return nil

	case cmdAddressBook, cmdAB:
		if len(args) != 3 {
			return mw.doUsage(args)
		}
		if args[1] != "del" {
			return fmt.Errorf("invalid addressbook command: %v",
				args[1])
		}
		return mw.zkc.addressBookDel(args[2])

	case cmdSave:
		err := saveConversations(mw.zkc)
		if err != nil {
			mw.zkc.PrintfT(-1, "save failed: %v", err)
		}
		return nil
	}

	return fmt.Errorf("invalid command: %v", cmd)
}

type savedConversation struct {
	Id    *zkidentity.PublicIdentity
	Nick  string
	Group bool
}

func saveConversations(z *ZKC) error {
	os.Remove(path.Join(z.settings.Root, conversationsFilename))
	cdb, err := inidb.New(path.Join(z.settings.Root, conversationsFilename), true, 10)
	if err != inidb.ErrCreated {
		if err != nil {
			return err
		} else {
			return fmt.Errorf("could not create conversations.ini")
		}
	}
	err = cdb.Lock()
	if err != nil {
		return err
	}
	defer cdb.Unlock()
	cdb.NewTable("conversations")
	var b bytes.Buffer
	var n int
	n = len(z.conversation)
	_, err = xdr.Marshal(&b, n)
	if err != nil {
		return err
	}
	err = cdb.Set("conversations", "n", base64.StdEncoding.EncodeToString(b.Bytes()))
	if err != nil {
		return err
	}
	for i, v := range z.conversation {
		var s savedConversation
		var b bytes.Buffer
		l := fmt.Sprintf("conversation%d", i)
		s.Id = v.id
		s.Nick = v.nick
		s.Group = v.group
		_, err = xdr.Marshal(&b, s)
		if err != nil {
			return err
		}
		err = cdb.Set("conversations", l, base64.StdEncoding.EncodeToString(b.Bytes()))
		if err != nil {
			return err
		}
	}
	err = cdb.Save()
	if err != nil {
		return err
	}
	return nil
}

func closeAll(z *ZKC) {
	z.Lock()
	defer z.Unlock()
	console := z.conversation[0]
	z.conversation = make([]*conversation, 1)
	z.conversation[0] = console
	z.focus(0)
}

func unmarshalConversation(b64 string) (*savedConversation, error) {
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("could not decode base64 conversation")
	}
	b := bytes.NewReader(blob)
	var c savedConversation
	_, err = xdr.Unmarshal(b, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func restoreConversations(z *ZKC) error {
	cdb, err := inidb.New(path.Join(z.settings.Root, conversationsFilename), false, 10)
	if err != nil {
		return err
	}
	err = cdb.Lock()
	if err != nil {
		return err
	}
	defer cdb.Unlock()
	b64, err := cdb.Get("conversations", "n")
	if err != nil {
		return err
	}
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	b := bytes.NewReader(blob)
	var n int
	_, err = xdr.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	closeAll(z)
	for i := 1; i < n; i++ {
		l := fmt.Sprintf("conversation%d", i)
		b64, err := cdb.Get("conversations", l)
		if err != nil {
			closeAll(z)
			return err
		}
		c, err := unmarshalConversation(b64)
		if err != nil {
			closeAll(z)
			return err
		}
		z.query(c.Nick)
	}
	z.focus(0)
	return nil
}
