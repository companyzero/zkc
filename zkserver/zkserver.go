// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/companyzero/zkc/debug"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/session"
	"github.com/companyzero/zkc/tagstack"
	"github.com/companyzero/zkc/tools"
	"github.com/companyzero/zkc/zkidentity"
	"github.com/companyzero/zkc/zkserver/account"
	"github.com/companyzero/zkc/zkserver/settings"
	"github.com/companyzero/zkc/zkutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/davecgh/go-xdr/xdr2"
)

const (
	idApp = 0
	idRPC = 1
	idS   = 2

	tagDepth = 32

	pendingDir     = "pending"
	pendingFile    = "pending.ini"
	rendezvousDir  = "rendezvous"
	rendezvousFile = "rendezvous.ini"
)

var (
	pendingPath    = path.Join(pendingDir, pendingFile)
	rendezvousPath = path.Join(rendezvousDir, rendezvousFile)
)

// RPCWrapper is a wrapped RPC Message for internal use.  This is required because RPC messages
// consist of 2 discrete pieces.
type RPCWrapper struct {
	Message    rpc.Message
	Payload    interface{}
	Identifier string
}

type ZKS struct {
	*debug.Debug
	account  *account.Account
	settings *settings.Settings
	id       *zkidentity.FullIdentity
}

// writeMessage marshals and sends encrypted message to client.
func (z *ZKS) writeMessage(kx *session.KX, msg *RPCWrapper) error {
	var bb bytes.Buffer
	_, err := xdr.Marshal(&bb, msg.Message)
	if err != nil {
		return fmt.Errorf("could not marshal message %v",
			msg.Message.Command)
	}
	_, err = xdr.Marshal(&bb, msg.Payload)
	if err != nil {
		return fmt.Errorf("could not marshal payload, %v",
			msg.Message.Command)
	}

	err = kx.Write(bb.Bytes())
	if err != nil {
		return fmt.Errorf("could not write %v: %v",
			msg.Message.Command, err)
	}

	if z.settings.Debug {
		rid := kx.TheirIdentity().([32]byte)
		rids := hex.EncodeToString(rid[:])
		z.T(idS, "writeMessage: %v %v tag %v",
			rids,
			msg.Message.Command,
			msg.Message.Tag)
	}
	return nil
}

func (z *ZKS) welcome(kx *session.KX) error {
	// obtain message of the day
	motd, err := ioutil.ReadFile(z.settings.MOTD)
	if err != nil {
		motd = []byte{}
	}

	properties := rpc.SupportedServerProperties
	for k, v := range properties {
		switch v.Key {
		case rpc.PropTagDepth:
			properties[k].Value = strconv.FormatUint(tagDepth, 10)
		case rpc.PropMaxAttachmentSize:
			properties[k].Value = strconv.FormatUint(z.settings.MaxAttachmentSize, 10)
		case rpc.PropMaxChunkSize:
			properties[k].Value = strconv.FormatUint(z.settings.MaxChunkSize, 10)
		case rpc.PropMaxMsgSize:
			properties[k].Value = strconv.FormatUint(z.settings.MaxMsgSize, 10)
		case rpc.PropServerTime:
			properties[k].Value = strconv.FormatInt(time.Now().Unix(), 10)
		case rpc.PropMOTD:
			properties[k].Value = string(motd)
		case rpc.PropDirectory:
			properties[k].Value = strconv.FormatBool(z.settings.Directory)
		}
	}

	// assemble command
	message := rpc.Message{
		Command: rpc.SessionCmdWelcome,
	}
	payload := rpc.Welcome{
		Version:    rpc.ProtocolVersion,
		Properties: properties,
	}

	// encode command
	var bb bytes.Buffer
	_, err = xdr.Marshal(&bb, message)
	if err != nil {
		return fmt.Errorf("could not marshal Welcome message")
	}
	_, err = xdr.Marshal(&bb, payload)
	if err != nil {
		return fmt.Errorf("could not marshal Welcome payload")
	}

	// write command over encrypted transport
	err = kx.Write(bb.Bytes())
	if err != nil {
		return fmt.Errorf("could not write Welcome message: %v", err)
	}

	return nil
}

func (z *ZKS) sessionWriter(sc *sessionContext) {
	defer func() {
		z.Dbg(idS, "sessionWriter exit: %v", sc.rids)

		// close underlying connection in order to fail read
		sc.kx.Close()
	}()

	for {
		var (
			msg *RPCWrapper
			ok  bool
		)

		select {
		case <-sc.quit:
			z.T(idS, "sessionWriter quit: %v", sc.rids)
			return

		case msg, ok = <-sc.writer:
			if !ok {
				z.T(idS, "sessionWriter sc.writer: %v",
					sc.rids)
				return
			}

			z.T(idS, "sessionWriter write %v: %v %v",
				sc.rids,
				msg.Message.Command,
				msg.Message.Tag)

			err := z.writeMessage(sc.kx, msg)
			if err != nil {
				z.Error(idS, "sessionWriter write failed %v: %v",
					sc.rids,
					err)
				return
			}
		}
	}
}

func (z *ZKS) sessionNtfn(sc *sessionContext) {
	defer func() {
		z.T(idS, "sessionNtfn exit: %v", sc.rids)

		// close underlying connection in order to fail read
		sc.kx.Close()
	}()

	for {
		var (
			n  *account.Notification
			ok bool
		)

		select {
		case <-sc.quit:
			z.T(idS, "sessionNtfn quit: %v", sc.rids)
			return

		case n, ok = <-sc.ntfn:
			if !ok {
				z.T(idS, "sessionNtfn: <-sc.ntfn !ok %v", sc.rids)
				return
			}

			if n.Error != nil {
				z.Error(idS, "notification error: %v", n.Error)
				return
			}

			// obtain tag
			tag, err := sc.tagStack.Pop()
			if err != nil {
				// this probably should be debug
				z.Error(idS, "could not obtain tag: %v %v",
					sc.rids,
					err)
				return
			}
			sc.Lock()
			if sc.tagMessage[tag] != nil {
				sc.Unlock()
				z.Error(idS, "write duplicate tag: %v %v",
					sc.rids,
					tag)
				return
			}

			// translate notification into msg
			r := RPCWrapper{
				Message: rpc.Message{
					Command:   rpc.TaggedCmdPush,
					Cleartext: n.Cleartext,
					Tag:       tag,
				},
				Payload: rpc.Push{
					From:     n.From,
					Received: n.Received,
					Payload:  n.Payload,
				},
				Identifier: n.Identifier,
			}
			sc.tagMessage[tag] = &r
			sc.Unlock()

			z.T(idS, "sessionNtfn ntfy: %v %v",
				sc.rids,
				r.Message.Command,
				r.Message.Tag)

			sc.writer <- &r
		}
	}
}

type sessionContext struct {
	ntfn   chan *account.Notification
	writer chan *RPCWrapper
	quit   chan struct{}
	//done     chan bool
	kx       *session.KX
	rids     string
	tagStack *tagstack.TagStack

	// protected
	sync.Mutex
	tagMessage []*RPCWrapper
}

// handleSession deals with incoming RPC calls.  For now treat all errors as
// critical and return which in turns shuts down the connection.
func (z *ZKS) handleSession(kx *session.KX) error {
	rid, ok := kx.TheirIdentity().([32]byte)
	if !ok {
		return fmt.Errorf("invalid KX identity type %T", rid)
	}
	rids := hex.EncodeToString(rid[:])

	// create session context
	sc := sessionContext{
		ntfn:       make(chan *account.Notification, tagDepth),
		writer:     make(chan *RPCWrapper, tagDepth),
		quit:       make(chan struct{}),
		kx:         kx,
		rids:       rids,
		tagStack:   tagstack.NewBlocking(tagDepth),
		tagMessage: make([]*RPCWrapper, tagDepth),
	}

	// register identity
	err := z.account.Online(rid, sc.ntfn)
	if err != nil {
		return fmt.Errorf("handleSession: %v %v", rids, err)
	}
	z.Dbg(idS, "handleSession account online: %v", rids)

	// populate identity in directory
	if z.settings.Directory {
		err := z.account.Push(rid)
		if err != nil {
			z.Dbg(idS, "handleSession: Push(%v) = %v", rids, err)
		}
	}

	tagBitmap := make([]bool, tagDepth) // see if there is a duplicate tag
	go z.sessionWriter(&sc)
	go z.sessionNtfn(&sc)

	// wait for sessionWriter to exit
	defer func() {
		// stop it all
		close(sc.quit)

		z.account.Offline(rid)

		z.Dbg(idS, "handleSession exit: %v", rids)
	}()

	for {
		var message rpc.Message

		// OpenBSD does not support per socket TCP KEEPALIVES So
		// for now we ping on the client every 10 seconds and we
		// try to read those aggresively.  We'll cope in the
		// client with agressive reconnects.  This really is
		// ugly as sin.
		//
		// Ideally this crap goes away and we use proper TCP for
		// this.
		kx.SetReadDeadline(time.Now().Add(15 * time.Second))

		// read message
		cmd, err := kx.Read()
		if err != nil {
			if xdr.IsIO(err) {
				return nil // connection closed
			}
			return fmt.Errorf("Read: %v", err)
		}

		// unmarshal header
		br := bytes.NewReader(cmd)
		_, err = xdr.Unmarshal(br, &message)
		if err != nil {
			return fmt.Errorf("unmarshal header failed")
		}

		if message.Tag > tagDepth {
			return fmt.Errorf("invalid tag received %v", message.Tag)
		}

		if tagBitmap[message.Tag] {
			return fmt.Errorf("read duplicate tag: %v", message.Tag)
		}
		tagBitmap[message.Tag] = true

		z.T(idS, "handleSession: %v %v %v",
			rids,
			message.Command,
			message.Tag)

		// unmarshal payload
		switch message.Command {
		case rpc.TaggedCmdPing:
			var p rpc.Ping
			_, err = xdr.Unmarshal(br, &p)
			if err != nil {
				return fmt.Errorf("unmarshal Ping failed")
			}
			sc.writer <- &RPCWrapper{
				Message: rpc.Message{
					Command: rpc.TaggedCmdPong,
					Tag:     message.Tag,
				},
				Payload: rpc.Pong{},
			}

		case rpc.TaggedCmdRendezvous:
			var r rpc.Rendezvous
			_, err = xdr.Unmarshal(br, &r)
			if err != nil {
				return fmt.Errorf("unmarshal Rendezvous failed")
			}
			err = z.handleRendezvous(sc.writer, message, r)
			if err != nil {
				return fmt.Errorf("handleRendezvous: %v", err)
			}

		case rpc.TaggedCmdRendezvousPull:
			var r rpc.RendezvousPull
			_, err = xdr.Unmarshal(br, &r)
			if err != nil {
				return fmt.Errorf("unmarshal RendezvousPull " +
					"failed")
			}
			err = z.handleRendezvousPull(sc.writer, message, r)
			if err != nil {
				return fmt.Errorf("handleRendezvousPull: %v",
					err)
			}

		case rpc.TaggedCmdCache:
			var r rpc.Cache
			_, err = xdr.Unmarshal(br, &r)
			if err != nil {
				return fmt.Errorf("unmarshal Cache failed")
			}
			err = z.handleCache(sc.writer, kx, message, r)
			if err != nil {
				return fmt.Errorf("handleCache: %v", err)
			}

		case rpc.TaggedCmdAcknowledge:
			sc.Lock()
			m := sc.tagMessage[message.Tag]
			sc.Unlock()

			z.T(idS, "handleSession: %v got ack tag %v",
				rids,
				message.Tag)

			// sanity
			if m != nil && m.Message.Tag != message.Tag {
				return fmt.Errorf("acknowledge tag doesn't "+
					"match: %v %v %v",
					m.Message.Tag,
					message.Tag,
					rids)
			}
			// see if we have work to do
			if m != nil && m.Message.Command == rpc.TaggedCmdPush {
				from := kx.TheirIdentity().([32]byte)
				// err is reporting only
				err = z.account.Delete(from, m.Identifier)
				if err != nil {
					z.Error(idS,
						"handleSession: %v delete "+
							"failed %v %v",
						rids,
						m.Identifier,
						err)
				}
			}

			// mark free
			sc.Lock()
			sc.tagMessage[message.Tag] = nil
			sc.Unlock()

			// just push tag for now
			err = sc.tagStack.Push(message.Tag)
			if err != nil {
				return fmt.Errorf("Acknowledge can't push tag: %v",
					message.Tag)
			}
			z.T(idS, "handleSession: %v ack tag %v",
				rids,
				message.Tag)

		case rpc.TaggedCmdIdentityFind:
			var i rpc.IdentityFind
			_, err = xdr.Unmarshal(br, &i)
			if err != nil {
				return fmt.Errorf("unmarshal IdentityFind failed")
			}
			err = z.handleIdentityFind(sc.writer, message, i.Nick)
			if err != nil {
				return fmt.Errorf("handleIdentityFind: %v", err)
			}

		case rpc.TaggedCmdProxy:
			var p rpc.Proxy
			_, err = xdr.Unmarshal(br, &p)
			if err != nil {
				return fmt.Errorf("unmarshal Proxy failed")
			}
			err = z.handleProxy(sc.writer, kx, message, p)
			if err != nil {
				return fmt.Errorf("handleProxy: %v", err)
			}

		default:
			return fmt.Errorf("invalid message: %v", message)

		}

		tagBitmap[message.Tag] = false
	}
}

func (z *ZKS) preSession(conn net.Conn) {
	z.Dbg(idApp, "incoming connection: %v", conn.RemoteAddr())

	defer func() {
		conn.Close()
		z.Info(idApp, "connection closed: %v", conn.RemoteAddr())
	}()

	// pre session state
	var mode string
	for {
		_, err := xdr.Unmarshal(conn, &mode)
		if err != nil {
			z.Dbg(idApp, "could not unmarshal mode: %v",
				conn.RemoteAddr())
			return
		}

		switch mode {
		case rpc.InitialCmdIdentify:
			z.T(idApp, "InitialCmdIdentify: %v", conn.RemoteAddr())
			if !z.settings.AllowIdentify {
				z.Warn(idApp, "disallowing identify to: %v",
					conn.RemoteAddr())
				return
			}
			_, err = xdr.Marshal(conn, z.id.Public)
			if err != nil {
				z.Error(idApp, "could not marshal "+
					"z.id.Public: %v",
					conn.RemoteAddr())
				return
			}

			z.Dbg(idApp, "identifying self to: %v",
				conn.RemoteAddr())

		case rpc.InitialCmdCreateAccount:
			z.T(idApp, "InitialCmdCreateAccount: %v", conn.RemoteAddr())
			var ca rpc.CreateAccount
			_, err := xdr.Unmarshal(conn, &ca)
			if err != nil {
				z.Error(idApp, "could not unmarshal "+
					"CreateAccount: %v",
					conn.RemoteAddr())
				return
			}

			err = z.handleAccountCreate(conn, ca)
			if err != nil {
				z.Error(idApp, "handleAccountCreate: %v %v",
					conn.RemoteAddr(),
					err)
				return // treat as fatal
			}

			continue

		case rpc.InitialCmdSession:
			z.T(idApp, "InitialCmdSession: %v", conn.RemoteAddr())
			// go full session
			kx := new(session.KX)
			kx.Conn = conn
			kx.MaxMessageSize = uint(z.settings.MaxMsgSize)
			kx.OurPublicKey = &z.id.Public.Key
			kx.OurPrivateKey = &z.id.PrivateKey
			err = kx.Respond()
			if err != nil {
				conn.Close()
				z.Error(idApp, "kx.Respond: %v %v",
					conn.RemoteAddr(),
					err)
				return
			}
			remoteID, ok := kx.TheirIdentity().([32]byte)
			if !ok {
				z.Error(idApp, "invalid KX identity type %T: %v",
					remoteID,
					conn.RemoteAddr())
				return
			}
			rid := hex.EncodeToString(remoteID[:])

			// validate user has an account
			fi, err := os.Stat(path.Join(z.settings.Users, rid))
			if err != nil || !fi.IsDir() {
				z.Warn(idApp, "unknown identity: %v %v",
					conn.RemoteAddr(),
					rid)
				return
			}

			z.Info(idApp, "connection from %v identity %v",
				conn.RemoteAddr(),
				rid)

			// send welcome
			err = z.welcome(kx)
			if err != nil {
				z.Error(idApp, "welcome failed: %v %v",
					conn.RemoteAddr(),
					err)
			}

			// at this point we are going to use tags
			err = z.handleSession(kx)
			if err != nil {
				z.Error(idApp, "handleSession failed: %v %v",
					conn.RemoteAddr(),
					err)
			}
			return

		default:
			z.Error(idApp, "invalid mode: %v: %v",
				conn.RemoteAddr(),
				mode)
			return
		}
	}
}

func (z *ZKS) listen() error {
	cert, err := tls.LoadX509KeyPair(path.Join(z.settings.Root,
		tools.ZKSCertFilename),
		path.Join(z.settings.Root, tools.ZKSKeyFilename))
	if err != nil {
		return fmt.Errorf("could not load certificates: %v", err)
	}
	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}
	l, err := net.Listen("tcp", z.settings.Listen)
	if err != nil {
		return fmt.Errorf("could not listen: %v", err)
	}
	z.Info(idApp, "Listening on %v", z.settings.Listen)

	session.Init()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				z.Error(idApp, "Accept: %v", err)
				continue
			}

			conn.(*net.TCPConn).SetKeepAlive(true)
			conn.(*net.TCPConn).SetKeepAlivePeriod(time.Second)
			conn = tls.Server(conn, &config)

			go z.preSession(conn)
		}
	}()

	return nil
}

func _main() error {
	z := &ZKS{}

	// flags and settings
	var err error
	z.settings, err = ObtainSettings()
	if err != nil {
		return err
	}

	// create paths
	err = os.MkdirAll(z.settings.Root, 0700)
	if err != nil {
		return err
	}

	// handle logging
	z.Debug, err = debug.New(z.settings.LogFile, z.settings.TimeFormat)
	if err != nil {
		return err
	}
	z.Register(idApp, "[APP]")

	// register remaining subsystems
	z.Register(idRPC, "[RPC]")
	z.Register(idS, "[SES]")

	// print version
	z.Info(idApp, "Version: %v, RPC Protocol: %v",
		zkutil.Version(), rpc.ProtocolVersion)

	// identity
	id, err := ioutil.ReadFile(path.Join(z.settings.Root,
		tools.ZKSIdentityFilename))
	if err != nil {
		z.Info(idApp, "Creating a new identity")
		fid, err := zkidentity.New("zkserver", "zkserver")
		if err != nil {
			return err
		}
		id, err = fid.Marshal()
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(path.Join(z.settings.Root,
			tools.ZKSIdentityFilename), id, 0600)
		if err != nil {
			return err
		}
	}
	z.id, err = zkidentity.UnmarshalFullIdentity(id)
	if err != nil {
		return err
	}

	// certs
	cert, err := tls.LoadX509KeyPair(path.Join(z.settings.Root,
		tools.ZKSCertFilename),
		path.Join(z.settings.Root, tools.ZKSKeyFilename))
	if err != nil {
		// create a new cert
		valid := time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)
		cp, kp, err := newTLSCertPair("", valid, []string{})
		if err != nil {
			return fmt.Errorf("could not create a new cert: %v",
				err)
		}

		// save on disk
		err = ioutil.WriteFile(path.Join(z.settings.Root,
			tools.ZKSCertFilename), cp, 0600)
		if err != nil {
			return fmt.Errorf("could not save cert: %v", err)
		}
		err = ioutil.WriteFile(path.Join(z.settings.Root,
			tools.ZKSKeyFilename), kp, 0600)
		if err != nil {
			return fmt.Errorf("could not save key: %v", err)
		}

		cert, err = tls.X509KeyPair(cp, kp)
		if err != nil {
			return fmt.Errorf("X509KeyPair: %v", err)
		}
	}

	z.Info(idApp, "Start of day")
	z.Info(idApp, "Settings %v", spew.Sdump(z.settings))
	defer z.Info(idApp, "End of times")
	z.Info(idApp, "Our outer fingerprint: %v", tools.FingerprintDER(cert))
	z.Info(idApp, "Our inner fingerprint: %v", z.id.Public.Fingerprint())

	// debugging
	if z.settings.Debug {
		z.Info(idApp, "Debug enabled")
		z.EnableDebug()
		if z.settings.Profiler != "" {
			z.Info(idApp, "Profiler enabled on http://%v/debug/pprof",
				z.settings.Profiler)
			go http.ListenAndServe(z.settings.Profiler, nil)
		}

		if z.settings.Trace {
			z.Info(idApp, "Trace enabled")
			z.EnableTrace()
		}
	}

	// launch account service
	z.Info(idApp, "Account subsystem bringup started")
	z.account, err = account.New(z.settings.Users)
	if err != nil {
		return err
	}
	z.Info(idApp, "Account subsystem bringup complete")

	// listen for incoming connections
	err = z.listen()
	if err != nil {
		return err
	}

	// wait for termination signals
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		done <- true
	}()

	<-done

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
