ZKC command overview
/acceptnewcert	If the server cert has changed accept the new one.
/fetch <PIN>	Try to download key exchange blob using provided PIN.
/kx		Initiate a key exchange with a third party.
/online		Try to establish a session with a server.
/offline	Drop connection to server
/quit		Exit zkc.
/m <nick> text	Send nick a text message.
/q <nick>	Query nick.
/info [nick]	Print identity for nick, if omitted it prints own
		identity.
/list <c>|<a>|<gc>|
	<invites><joins> [group]	Print all active conversations, address
					book, invites, joins or group chat entries
/w <window>	Switch active chat window
/wc		Close current window.
/build		Display last git commit digest.
/send <nick> <filename> [description]	Send file.
/reset <nick>				reset ratchet with nick.
/addressbook <del> <nick>		Permanently delete user nick.

Group chat commands
/gc new <group>	Create a new group chat.
/gc invite <group> <nick>	Invite nick to group chat.
/gc join <group> <nick> <token>	Join group as requested by nick.
/gc m <group> text		Send group a message.
/gc part <group> 		Part group chat.
/gc kick <group> <nick>		Kick nick of group chat.

Hotkeys
ctrl-q		Quit application.
ctrl-u, PgUp	Page up.
ctrl-d, PgDn	Page down.
ctrl-t		Top.
ctrl-b		Bottom.
UpArrow		Previous history item.
DownArrow	Next history item.
