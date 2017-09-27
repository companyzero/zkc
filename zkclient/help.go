// Copyright (c) 2016 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

type help struct {
	command     string
	usage       string
	description string
	long        []string
}

var (
	leader = "/"

	cmdAcceptnewcert = leader + "acceptnewcert"
	cmdVersion       = leader + "version"
	cmdHelp          = leader + "help"
	cmdFetch         = leader + "fetch"
	cmdGc            = leader + "gc"
	cmdInfo          = leader + "info"
	cmdKx            = leader + "kx"
	cmdList          = leader + "list"
	cmdM             = leader + "m" // alias for message
	cmdMe            = leader + "me"
	cmdMsg           = leader + "msg"
	cmdOffline       = leader + "offline"
	cmdOnline        = leader + "online"
	cmdQ             = leader + "q" // alias for query
	cmdQuery         = leader + "query"
	cmdQuit          = leader + "quit"
	cmdSend          = leader + "send"
	cmdWc            = leader + "wc"
	cmdW             = leader + "w" // alias for win
	cmdWin           = leader + "win"
	cmdReset         = leader + "reset"
	cmdAddressBook   = leader + "addressbook"
	cmdAB            = leader + "ab" // alias for addressbook
	cmdSave          = leader + "save"
	cmdRestore       = leader + "restore"
	cmdFind          = leader + "find"

	helpArray = []help{
		{
			command:     cmdAcceptnewcert,
			usage:       cmdAcceptnewcert,
			description: "accept new TLS certificate if it changed",
			long: []string{
				"If a remote server changed its certificate a warning message can popup (if tlsverbose = yes in configuration file).  This command should be run to explicitely accept the new certificate as valid.  If tlsverbose is disabled then no message will ever popup and all certificate changes are ignored.",
				"",
				"Ignoring the TLS certificate is acceptable because of the additional session key exchange that runs inside the TLS tunnel.  TLS is only used as untrusted transport.  The option exists in order to catch unexpected certificate changes in a high security environment.",
			},
		},
		{
			command:     cmdVersion,
			usage:       cmdVersion,
			description: "print application version",
		},
		{
			command:     cmdHelp,
			usage:       cmdHelp + " [command]",
			description: "this help",
		},
		{
			command:     cmdFetch,
			usage:       cmdFetch + " <pin>",
			description: "download encrypted key exchange blob from server",
			long: []string{
				cmdFetch + " is used to download an encrypted key exchange blob from the server.  Once the blob id downloaded the user is prompted for the shared passphrase that was used to create the blob (see " + cmdKx + " for more information",
				"",
				"When this completes successfully the public identity of the other side is cached and one can commence exchanging messages.",
			},
		},
		{
			command:     cmdGc,
			usage:       cmdGc + " <invite> | <join> | <kick> | <kill> | <new> | <me> | <message> | <part>",
			description: "group chat command",
			long: []string{
				"invite invites a user to a group chat.  Usage " + cmdGc + " invite <groupchat> <nick>",
				"join joins a group chat.  Usage " + cmdGc + " join <groupchat> <token>.  The token is printed on the console after the initial invite or it can be obtained using the " + cmdList + " invites command",
				"kick removes a user from a group chat.  Usage " + cmdGc + " kick <groupchat> <nick>.  Only the group administrator can run this command.",
				"kill disbands a group chat.  All participants will be removed from groupchat.  Usage " + cmdGc + " kill <groupchat>.  Only the group administrator can run this command.",
				"new creates a group chat of which you are the administrator.  Usage " + cmdGc + " new <groupchat>",
				"m send a message to a group chat.  Usage " + cmdGc + " m <groupchat> <message>",
				"part leaves a group chat.  Usage " + cmdGc + " part <groupchat>.",
			},
		},
		{
			command:     cmdInfo,
			usage:       cmdInfo + "[nick]",
			description: "print user information",
			long: []string{
				"When used without a nick this commands prints your information instead of the provided user's information.  This can be used to display things such as real names and fingerprints.",
			},
		},
		{
			command:     cmdKx,
			usage:       cmdKx,
			description: "upload encrypted key exchange blob to server",
			long: []string{
				cmdKx + " is used to upload an encrypted key exchange blob to the server.  A new window prompts the user for a passphrase that can be shared with a third party to decrypt the key exchange blob.",
				"",
				"When the command completes it prints a PIN code that a third party can use to obtain the encrypted key exchange blob.  See " + cmdFetch + " for more information.",
			},
		},
		{
			command:     cmdList,
			usage:       cmdList + " <c|conversations> | <a|addressbook> | <gc|groupchat> | <invites> | <joins>",
			description: "list various cached information",
			long: []string{
				"conversations lists all current active conversation windows.",
				"addressbook lists all people in your address book (all people that completed a key exchange with you).",
				"groupchat lists all available group chats.  " + cmdList + " gc <groupchat> lists the group chat participants.",
				"invites lists all pending invitations you received to join a group chat.",
				"joins lists all pending join requests you sent to others to join a group chat.",
			},
		},
		{
			command:     cmdOffline,
			usage:       cmdOffline,
			description: "disconnect from server",
		},
		{
			command:     cmdOnline,
			usage:       cmdOnline,
			description: "attempt to connect to server",
		},
		{
			command:     cmdM,
			usage:       cmdM + " <nick> <message>",
			description: "alias for " + cmdMsg,
		},
		{
			command:     cmdMe,
			usage:       cmdMe + " <message>",
			description: "send a message that is prefixed by * nick",
		},
		{
			command:     cmdMsg,
			usage:       cmdMsg + " <nick> <message>",
			description: "send a private message",
		},
		{
			command:     cmdQ,
			usage:       cmdQ + " <nick>",
			description: "alias for " + cmdQuery,
		},
		{
			command:     cmdQuery,
			usage:       cmdQuery + " <nick>",
			description: "start private conversation",
			long: []string{
				"Query opens a new conversation window with " +
					"provided nick.",
			},
		},
		{
			command:     cmdQuit,
			usage:       cmdQuit + " [force]",
			description: "quit application",
		},
		{
			command:     cmdSend,
			usage:       cmdSend + " <nick> <filename> [description]",
			description: "send file to nick.",
			long: []string{
				"Send a file to a user.  This command is intended to share a file with a single user.",
			},
		},
		{
			command:     cmdWc,
			usage:       cmdWc,
			description: "close current conversation window",
		},
		{
			command:     cmdW,
			usage:       cmdW + " <window>",
			description: "alias for " + cmdWin,
		},
		{
			command:     cmdWin,
			usage:       cmdWin + " <window>",
			description: "switch to conversation window",
			long: []string{
				"Switch to provided window and mark " +
					"conversation as read.",
			},
		},
		{
			command:     cmdReset,
			usage:       cmdReset + " <nick>",
			description: "reset ratchet state",
			long: []string{
				"Reset ratchet state with another user.  " +
					"A key exchange must be completed before parties can exchange messages.",
			},
		},
		{
			command:     cmdAddressBook,
			usage:       cmdAddressBook + " <del> <nick>",
			description: "Manipulate address book.",
			long: []string{
				"Currently the only supported command is del." +
					"It is used to permanently remove a nick from the address book.",
			},
		},
		{
			command:     cmdAB,
			usage:       cmdAB + " <del> <nick>",
			description: "alias for " + cmdAddressBook,
		},
		{
			command:     cmdSave,
			usage:       cmdSave,
			description: "Save open conversations to disk",
		},
		{
			command:     cmdRestore,
			usage:       cmdRestore,
			description: "Restore conversations from disk",
		},
		{
			command:     cmdFind,
			usage:       cmdFind + " <nick>",
			description: "looks up an identity in server",
		},
	}
)
