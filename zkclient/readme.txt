ZKC command overview
/acceptnewcert	If the server cert has changed accept the new one
/fetch <PIN>	Try to download key exchange blob using provided PIN
/find <nick>	Find nick in addressbook and initiate ratchet KX
/help		Online help
/info [nick]	Print identity for nick, if omitted it prints own identity
/kx		Initiate a key exchange with a third party
/offline	Drop connection to server
/online		Try to establish a session with a server
/quit		Exit zkc
/query <nick|gc>Open chat window with nick or groupchat
/reset <nick>	Reset ratchet with nick, other side initiates a ratchet KX
/save		Save all open conversations to disk
/restore	Loads saved conversations from disk
/version	Display both software and RPC protocol versions
/wc		Close current window
/win <window>	Switch active chat window

/addressbook <del> <nick>		Permanently delete user nick
/send <nick> <filename> [description]	Send file

/list <c>|<a>|<gc>|<invites><joins> [group]	Print all active conversations, address
						book, invites, joins or group chat entries

Chat commands
/me			Send message prefixed by * nick in current window
/msg <nick> text	Send message to nick

Group chat commands
/gc new <group>	Create a new group chat
/gc invite <group> <nick>	Invite nick to group chat
/gc join <group> <nick> <token>	Join group as requested by nick
/gc m <group> text		Send group a message
/gc part <group> 		Part group chat
/gc kick <group> <nick>		Kick nick of group chat

Hotkeys
ctrl-q		Quit application
ctrl-u, PgUp	Page up
ctrl-d, PgDn	Page down
ctrl-t		Top
ctrl-b		Bottom
ctrl-p		Previous window
ctrl-n		Next window
Esc-<N>		Go to window N
UpArrow		Previous history item
DownArrow	Next history item
