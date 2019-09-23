// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// rpc contains all structures required by the ZK protocol.
//
// A ZK session has two discrete phases:
//	1. pre session phase, used to create accounts and obtain zkserver key
//	2. session phase, used for all other RPC commands
//	3. once the key exchange is complete the server shall issue a Welcome
//         command.  The welcome command also transfer additional settings such
//         as tag depth etc.
//
// In order to exchange messages with a third party two pieces of information
// are required.  Each side must know the other's long lived public identity
// and the public DH ratchet keys.
// The process, using RPC, to obtains that information is as follows:
//	1. Alice sends Bob a Rendezvous command that contains her encrypted
//	   identity. She uses a third party communication method (phone, IRC
//	   etc)	to share the rendezvous PIN code and a shared password.
//	2. Bob obtains Alice's identity by sending a RendezvousPull command
//	   using the PIN code.  After decrypting Alice's identity blob using the
//	   share password he replies with a Cache command that contains his long
//	   lived public identity and his initial public DH ratchet keys.
//	3. Alice is notified, using the normal Push RPC mechanism, when Bob has
//	   replied.  She then replies to Bob with her public DH ratchet keys.
//
// The external identity and key exchange process is outside of the scope of
// this document.
package rpc

import (
	"crypto/sha256"
	"errors"
	"strconv"

	"github.com/companyzero/zkc/ratchet"
	"github.com/companyzero/zkc/zkidentity"
)

type MessageMode uint32

const (
	// pre session phase
	InitialCmdIdentify      = "identify"
	InitialCmdCreateAccount = "createaccount"
	InitialCmdSession       = "session"

	// session phase
	SessionCmdWelcome   = "welcome"
	SessionCmdUnwelcome = "unwelcome"

	// tagged server commands
	TaggedCmdRendezvous          = "rendezvous"
	TaggedCmdRendezvousReply     = "rendezvousreply"
	TaggedCmdRendezvousPull      = "rendezvouspull"
	TaggedCmdRendezvousPullReply = "rendezvouspullreply"
	TaggedCmdCache               = "cache"
	TaggedCmdPush                = "push"
	TaggedCmdAcknowledge         = "ack"
	TaggedCmdProxy               = "proxy"
	TaggedCmdProxyReply          = "proxyreply"
	TaggedCmdPing                = "ping"
	TaggedCmdPong                = "pong"
	TaggedCmdIdentityFind        = "identityfind"
	TaggedCmdIdentityFindReply   = "identityfindreply"

	// misc
	MessageModeNormal MessageMode = 0
	MessageModeMe     MessageMode = 1
)

// CreateAccount is a PRPC that is used to create a new account on the server.
// Policy dictates if this is allowed or not.
type CreateAccount struct {
	Token          string                    // auth token
	PublicIdentity zkidentity.PublicIdentity // long lived public identity
}

// sanitized errors for CreateAccountReply
var (
	ErrCreateDisallowed = errors.New("not allowed")
	ErrInternalError    = errors.New("internal error, contact administrator")
)

// Message is the generic command that flows between a server and client and
// vice versa.  Its purpose is to add a discriminator to simplify payload
// decoding.  Additionally it has a tag that the recipient shall return
// unmodified when replying.  The tag is originated by the sender and shall be
// unique provided an answer is expected.  The receiver shall not interpret or
// use the tag in any way.
// The Cleartext flag indicates that the payload is in clear text. This flag
// should only be used for proxy commands (e.g. ratchet reset).
type Message struct {
	Command   string // discriminator
	TimeStamp int64  // originator timestamp
	Cleartext bool   // If set Payload is in clear text, proxy use only
	Tag       uint32 // client generated tag, shall be unique
	//followed by Payload []byte
}

// Acknowledge is sent to acknowledge commands and Error is set if the command
// failed.
type Acknowledge struct {
	Error string
}

const (
	ProtocolVersion = 8
)

// Unwelcome is written immediately following a key exchange.  This command
// purpose is to detect if the key exchange completed on the client side.  If
// the key exchange failed the server will simply disconnect. If the user is
// Unwelcome this message will contain the reason.
type Unwelcome struct {
	Version int    // protocol version
	Reason  string // reason why unwelcome
}

// Welcome is written immediately following a key exchange.  This command
// purpose is to detect if the key exchange completed on the client side.  If
// the key exchange failed the server will simply disconnect.
type Welcome struct {
	Version    int   // protocol version
	ServerTime int64 // server timestamp

	// Client shall ensure it is compatible with the server requirements
	Properties []ServerProperty // server properties
}

type ServerProperty struct {
	Key      string // name of property
	Value    string // value of property
	Required bool   // if true client must handle this entry
}

const (
	// Tag Depth is a required property.  It defines maximum outstanding
	// commands.
	PropTagDepth        = "tagdepth"
	PropTagDepthDefault = "10"

	// MOTD (Message Of The Day) is an optional property.  It is a welcome
	// message that is sent from the server to the client upon first
	// contact.  The client may display this.
	PropMOTD = "motd"

	// Max Attachment Size is a required property.  It defines the maximum
	// attachment size.  Attachment size is defined as the largest size a
	// file transfer is allowed to be.
	PropMaxAttachmentSize        = "maxattachmentsize"
	PropMaxAttachmentSizeDefault = uint64(10 * 1024 * 1024)

	// Max Chunk Size is a required property.  It defines the maximum chunk
	// size.  Chunk size is defined as the largest size a CRPC is allowed
	// to be.
	PropMaxChunkSize        = "maxchunksize"
	PropMaxChunkSizeDefault = uint64(256 * 1024)

	// Max Message Size is a required property.  It defines the maximum
	// message size.  Message size is defined as the largest size a CRPC is
	// allowed to be.  This includes message overhead etc.
	PropMaxMsgSize        = "maxmsgsize"
	PropMaxMsgSizeDefault = PropMaxChunkSizeDefault + 1024

	// Server Time is a required property.  It contains the server time
	// stamp.  The client shall warn the user if the client is not time
	// synced.  Clients and proxies really shall run NTP.
	PropServerTime = "servertime"

	// Directory is a required property. It defines whether the server
	// keeps a directory of identities.
	PropDirectory        = "directory"
	PropDirectoryDefault = false
)

var (
	// required
	DefaultPropTagDepth = ServerProperty{
		Key:      PropTagDepth,
		Value:    PropTagDepthDefault,
		Required: true,
	}
	DefaultPropMaxAttachmentSize = ServerProperty{
		Key:      PropMaxAttachmentSize,
		Value:    strconv.FormatUint(PropMaxAttachmentSizeDefault, 10),
		Required: true,
	}
	DefaultPropMaxChunkSize = ServerProperty{
		Key:      PropMaxChunkSize,
		Value:    strconv.FormatUint(PropMaxChunkSizeDefault, 10),
		Required: true,
	}
	DefaultPropMaxMsgSize = ServerProperty{
		Key:      PropMaxMsgSize,
		Value:    strconv.FormatUint(PropMaxMsgSizeDefault, 10),
		Required: true,
	}
	DefaultServerTime = ServerProperty{
		Key:      PropServerTime,
		Value:    "", // int64 unix time
		Required: true,
	}
	DefaultPropDirectory = ServerProperty{
		Key:      PropDirectory,
		Value:    strconv.FormatBool(PropDirectoryDefault),
		Required: true,
	}

	// optional
	DefaultPropMOTD = ServerProperty{
		Key:      PropMOTD,
		Value:    "",
		Required: false,
	}

	// All properties must exist in this array.
	SupportedServerProperties = []ServerProperty{
		// required
		DefaultPropTagDepth,
		DefaultPropMaxAttachmentSize,
		DefaultPropMaxChunkSize,
		DefaultPropMaxMsgSize,
		DefaultServerTime,
		DefaultPropDirectory,

		// optional
		DefaultPropMOTD,
	}
)

// CreateAccountReply returns a sanitized error to the client indicating
// success or failure of the CreateAccountReply command.  Errors is set to ""
// on success.
type CreateAccountReply struct {
	Error string // if create account failed error contains the reason.
}

// Push is a PRPC that is used to push cached encrypted blobs to a user.  This
// command must be acknowledged by the remote side.
type Push struct {
	From     [32]byte // sender identity
	Received int64    // server received timestamp
	Payload  []byte   // encrypted payload
}

// Cache is a PRPC that is used to store message on server for later push
// delivery.  This command must be acknowledged by the remote side.
type Cache struct {
	To      [32]byte // recipient identity
	Payload []byte   // encrypted payload
}

// Proxy is a PRPC that is used to store message on server for later push
// delivery.  This command must be acknowledged by the remote side.
// THIS COMMAND IS NOT ENCRYPTED AND IS ONLY TO BE USED DURING EMERGENCIES
// (like a ratchet reset).
type Proxy struct {
	To      [32]byte // recipient identity
	Payload []byte   // unencrypted payload
}

// ProxyReply returns with an Error set if an error occurred during delivery.
type ProxyReply struct {
	To    [32]byte // recipient identity, returned by server
	Error string   // Set if an error occurred
}

// All proxy commands are a uint32 followed by a string. We do this to make
// decoding easier and since these are emergency commands nothing more should
// be sent anyway.
const (
	ProxyCmdInvalid      = uint32(0)
	ProxyCmdResetRatchet = uint32(1)
)

// ProxyCmd is sent in clear text from one client to another.
type ProxyCmd struct {
	Command uint32 // Command type
	Message string // message from other client
}

// Ping is a PRPC that is used to determine if the server is alive.
// This command must be acknowledged by the remote side.
type Ping struct{}
type Pong struct{}

// client to client commands

// Rendezvous sends a blob to the server. Blob shall be < 4096 and
// expiration shall be < 168 (7 * 24).
type Rendezvous struct {
	Blob       []byte // data being shared
	Expiration string // hours until Rendezvous expires
}

// RendezvousReply is a reply packet for a Rendezvous command.  Token contains
// an easy to remember PIN code to identify initial Rendezvous blob.
type RendezvousReply struct {
	Token string // Rendezvous token that identifies blob
	Error string // If an error occurred Error will be != ""
}

// RendezvousPull tries to download a previously uploaded blob.
type RendezvousPull struct {
	Token string // Rendezvous token that identifies blob
}

// RendezvousPullReply contains a data blob reply to a previous RendezvousPull
// command that is identified by token.
type RendezvousPullReply struct {
	Error string // set if an error occurred
	Token string // Rendezvous token that identifies blob
	Blob  []byte // data reply to previous Rendezvous
}

// IdentityFind asks the server's directory if the provided bick exists. The
// server will always return a failure if the nick is not found or if directory
// services are not enabled.
type IdentityFind struct {
	Nick string
}

// IdentityFindReply contains a public identity if found.
type IdentityFindReply struct {
	Nick     string                    // Nick that was originally sent in
	Error    string                    // Set if an error occurred
	Identity zkidentity.PublicIdentity // Public Identify if Error not set
}

// IdentityKX contains the long lived public identify and the DH ratchet keys.
// It is the second step during the IDKX exchange.
type IdentityKX struct {
	Identity zkidentity.PublicIdentity
	KX       ratchet.KeyExchange
}

// KX contains the DH ratchet keys.  It is the third step during the IDKX
// exchange.
type KX struct {
	KX ratchet.KeyExchange
}

const (
	// CRPC commands
	CRPCCmdPrivateMessage = "privmsg"
	CRPCCmdGroupInvite    = "groupinvite"
	CRPCCmdGroupJoin      = "groupjoin"
	CRPCCmdGroupPart      = "grouppart"
	CRPCCmdGroupKill      = "groupkill"
	CRPCCmdGroupKick      = "groupkick"
	CRPCCmdGroupUpdate    = "groupupdate"
	CRPCCmdGroupList      = "grouplist"
	CRPCCmdGroupMessage   = "groupmessage"
	CRPCCmdChunkNew       = "chunknew"
	CRPCCmdChunk          = "chunk"
	CRPCCmdJanitorMessage = "janitormessage"

	// compression
	CRPCCompNone = ""
	CRPCCompZLIB = "zlib"

	// janitor
	CRPCJanitorDeleted = "deleted"
)

// CRPC is a client RPC message.
type CRPC struct {
	Timestamp   int64  // client side timestamp
	Command     string // discriminator
	Compression string // compression used on Payload
	//followed by Payload []byte
}

// PrivateMessage is a CRPC that contains a text message.
type PrivateMessage struct {
	Text string
	Mode MessageMode // 0 regular mode, 1 /me
}

// JanitorMessage is a CRPC that tells the other party some sort of
// housekeeping occurred.
type JanitorMessage struct {
	Command string
	Reason  string
}

// GroupInvite, sender is implicit to CRPC.
// XXX Note that there is no explicit way to prohibit sender being admin.
// XXX This needs some more thought.
type GroupInvite struct {
	Name        string   // group name
	Members     []string // list of participants' nicknames
	Token       uint64   // invite token
	Description string   // group description
	Expires     int64    // unix time when this invite expires
}

// GroupJoin
type GroupJoin struct {
	Name  string // group name
	Token uint64 // invite token, implicitly identifies sender
	Error string // accept or deny Invite
}

// GroupPart, sender is implicit to CRPC
type GroupPart struct {
	Name   string // group name
	Reason string // reason to depart group
}

// GroupKill, sender is implicit to CRPC
type GroupKill struct {
	Name   string // group name
	Reason string // reason to disassemble group
}

// GroupKick, sender is implicit to CRPC
type GroupKick struct {
	Member       [zkidentity.IdentitySize]byte // kickee
	Reason       string                        // why member was kicked
	Parted       bool                          // kicked/parted
	NewGroupList GroupList                     // new GroupList
}

// GroupUpdate is a forced update from the admin. Thi can be used in case of
// gc' generation getting out of sync.
type GroupUpdate struct {
	Reason       string    // why member was kicked
	NewGroupList GroupList // new GroupList
}

// GroupList, currently we detect spoofing by ensuring the origin of the
// message.  This may not be sufficient and we may have to add a signature of
// sorts.  For now roll with this assumption.
type GroupList struct {
	Name       string // group name
	Generation uint64 // incremented every time list changes
	Timestamp  int64  // unix time last generation changed

	// all participants, [0] is administrator
	// receiver must check [0] == originator
	Members [][zkidentity.IdentitySize]byte
}

// GroupMessage is a message to a group.
type GroupMessage struct {
	Name       string      // group name
	Generation uint64      // Generation used
	Message    string      // Actual message
	Mode       MessageMode // 0 regular mode, 1 /me
}

// ChunkNew describes a chunked file transfer initiation.
type ChunkNew struct {
	Size        uint64            // total file size
	ChunkSize   uint64            // chunk size
	Filename    string            // original filename
	Description string            // user provided description
	MIME        string            // mime type
	Digest      [sha256.Size]byte // digest of file -> unique identifier
}

type Chunk struct {
	Offset  uint64            // offset in file
	Digest  [sha256.Size]byte // digest of file -> unique identifier
	Payload []byte            // chunk
}
