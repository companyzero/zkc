zkc
====

zkc, Zero Knowledge Communications, is a suite of programs to enable private
and secure communications between any number of parties.

**The zkc suite is a Proof-Of-Concept tool!  The code reflects this by being
somewhat intertwined instead of completely and properly separated.  While we
took great care to make sure that the important bits are correct there
certainly are bugs lurking.  We will happily take PRs that move zkc into a more
mature project.**

## Requirements

[Go](http://golang.org) 1.7 or newer.

## Installation

#### Windows/Linux/BSD/MacOSX/POSIX - Build from Source

- Install Go according to the installation instructions here:
  http://golang.org/doc/install

- Ensure Go was installed properly and is a supported version:

```bash
$ go version
```

- Run the following commands to obtain zkc, all dependencies, and install it:

```bash
$ mkdir -p $GOPATH/src/github.com/companyzero/
$ cd $GOPATH/src/github.com/companyzero/
$ git clone https://github.com/companyzero/zkc
$ cd zkc
```

To install zkclient, for example:
```
$ cd zkclient && env GO111MODULE=on go build
```

- zkc (and utilities) will now be installed in ```$GOPATH/bin```.  If you did
  not already add the bin directory to your system path during Go installation,
  we recommend you do so now.

## Getting Started

### zkserver

It is a good idea to create a zkserver user and login to finalize the
installation process.  Create a zkserver directory and copy the config file in
place and then edit the config file.
```bash
$ mkdir ~/.zkserver
$ cp $GOPATH/src/github.com/companyzero/zkc/zkserver/zkserver.conf ~/.zkserver/
$ vi ~/.zkserver/zkserver.conf
```

There are 2 items that must be looked at in the config file.
```bash
allowidentify = no
createpolicy = no
```

allowidentify is a setting that explicitly tells zkserver if it is allowed to
identify itself to external parties.  This knob exists to enable true closed
systems.  When this setting is set to no the only way to communicate with it is
to have a zkclient that has communicated with this zkserver before or the
zkclient used zkimport to insert the zkserver identity record into its
configuration.  If this knob is set to yes the zkserver will allow queries of
its identity during pre-session phase.

createpolicy has three settings: yes, no and token.  When createpolicy is set
to no an external party can not create an account.  If createpolicy is set to
yes any zkclient can create an account on this zkserver.  And finally if
createpolicy is set to token the zkclient must provide a token during account
creation.  This token can be obtained from the zkserver administration.
Creating a token can be done as the zkserver administrator by running the
zkservertoken command.  This will spit out a token that can be used once to
create an account.

Note: if you are not using the default ~/.zkserver directory that you need to
review all directory/filenames entries in the config file.

The remaining items in the config file are pretty self explanatory.

### zkclient

zkclient is an irssi look-alike communication client.  Users of irssi will find
it's interface familiar.

Create a zkclient directory and copy the config file in place and then edit the
config file.
```bash
$ mkdir ~/.zkclient
$ cp $GOPATH/src/github.com/companyzero/zkc/zkclient/zkclient.conf ~/.zkclient/
$ vi ~/.zkclient/zkclient.conf
```

There is 1 item that must be looked at in the config file.
```bash
savehistory = no
```

savehistory is by default set to no.  If you want to have persistent history
(after exiting zkclient) set this to yes.

Note: if you are not using the default ~/.zkclient directory that you need to
review all directory/filenames entries in the config file.

The remaining items in the config file are pretty self explanatory.

Upon first launch of zkclient it'll prompt the user for: user name, nick,
server and token.  The user name is your name (e.g. Alice McAlice), nick is
your preferred nick as it is displayed by your received (e.g. alice1337),
server is the address of your zkserver and lastly token is the zkserver
administrator provided token in order to create an account (if needed).  Once
this step is complete you can now communicate with zkserver.

At this point the zkclient TUI is fully up and once can type /help to get an
idea of what commands are available.

zkclient uses ratcheted encryption for communications and the server is unable
to snoop messages.  The only thing zkserver can see is that someone is
communicating with someone else.  This therefore requires users to setup
ratchets between themselves.  Let's illustrate the flow with an example.

Assume that Alice wants to communicate with Bob and both have an account on a
shared zkserver then the process is as follows:
```
1. Alice must upload her identity as an encrypted blob to the zkserver.  This
   can be accomplished by typing /kx and then filling out a password that is
   going to be shared with Bob.  The server will return a PIN code upon
   completion.
2. Using an out-of-band communication mechanism Alice must share the PIN and
   password with Bob.
3. Bob needs to fetch Alice's identity by typing the following /fetch PIN
   ("PIN" is replaced with the actual number provided by Alice).  If the PIN is
   correct Bob will be prompted for the password of the encrypted blob.  If the
   blob decrypts properly Bob will additionally be prompted to accept Alice's
   fingerprint.  If Bob accepts Alice's fingerprint then the rest of the key
   exchange will be finalized.
```

zkserver only passes encrypted blobs back and forth between users.  It has no
knowledge at all of what is being exchanged.  Therefore a key exchange can only
be finalized once all parties have been online long enough for all blobs to
travel back and forth.

At this point either Alice or Bob are going to be able to send messages back
and fort using the /m command (e.g. Alice would to the following /m bob hello
there!).

There are many more commands in zkclient and TUI keys but those are described
elsewhere.

### zkexport

zkexport export either the zkserver or zkclient public identity.  The zkserver
identity does include the host address as well.  The resulting base64 string
can be emailed or otherwise exchanged with your counterpart.

zkclient example:
```bash
$ zkexport -root /Users/marco/.zkclient1/   
AAAAEU1hcmNvIFBlZXJlYm9vbSAxAAAAAAAABm1hcmNvMQAAY3rsUd6bTpLI/n2EwmGKPkK3dA/V+wyz5HHLiQgzHNJ9KAZTOrGznd9Ulhe0Y0EVoW8OkuM/G51w6BdvIOm1CWaOAhw8SJi0/vbjZzETd8k397Vl3LPcDUFUbp+JQVKdtBWDhevh3MFN0DY7Oc5ZZrT+lIE+KVwQm/PaPpeIohoWAEBu3HEE6vuq4eQt7BQ6dbEV61ZKUHbMm/61ymhXCA==
```

zkserver example:
```bash
$ zkexport -s -root /Users/marco/.zkserver/   
AAAACHprc2VydmVyAAAACHprc2VydmVyr51dJzm8pxrjiQsxFF3Bez+6izPdWAcEWZFHka7OwoTAoamQ1hm5eU5HwgQdSS7Ek+nd2LkvjUcu55l3jUhKdBwpfrCn/N/mGWpJS6iMSFSxU/OcRvWe9pEySQZR4gyjjb4TKuaaaReGBI4d8rUfOwoDTs1y05YO4Fgtx9a0BOQsBHvxoPKeqGJ6gxf5QlF4Xu8RRashfRYcTVG44uMpBwAAAmUwggJhMIIBw6ADAgECAhBGHi9VXIHCoQ6W3uSSG9OLMAoGCCqGSM49BAMEMAsxCTAHBgNVBAoTADAeFw0xNjExMjgxNzQwNThaFw00OTEyMzEyMzU5NTlaMAsxCTAHBgNVBAoTADCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAPHlelHUjxH+4JR2+PP71imPZ5b0JjF4vq86UYdgzJXzYmVShJgd+f8qK4ZP+GjLDiZjfl8ov+HUF63uX3V23EZxAVTW0FDyshRiJ+Lt5YmWRMVAM4i+I979Gjq6ySf9bm4Z4vxx1lvUBizussP3KoEG7AdmvbP/HqWzjuQaFH3oeTxDo4HFMIHCMA4GA1UdDwEB/wQEAwICpDAPBgNVHRMBAf8EBTADAQH/MIGeBgNVHREEgZYwgZOCCWxvY2FsaG9zdIIUTWFyY29zLU1hYy1Qcm8ubG9jYWyHBMCojQGHBMCoHQGHEAAAAAAAAAAAAAAAAAAAAAGHEP6AAAAAAAAAuCSI2MJKFRGHEP0JBrb3SIrKuCSI2MJKFRGHBAqqAGmHBH8AAAGHEP6AAAAAAAAAAAAAAAAAAAGHEP6AAAAAAAAAAiUA//7ved0wCgYIKoZIzj0EAwQDgYsAMIGHAkIAstVERsGjpqib7xm1NaplfzmpvOD0H+Zr8lJfKkSCWcnzbPhqo+rl71QlTdqZNzvQHX/hfBNntcXE8f4J80oI+zYCQUl0d7BZYis1X3OTGvguHd01GoxTPFv3HAvu1YlTWFvoShWilKOzH1jDJM//qyagwe/sg67pBUzQ24GQdGDxn/qIAAAA
```

### zkimport

zkimport is intended to import zkexported base64 strings.

ADD EXAMPLES HERE.

### zkservertoken

As the zkserver user simply type zkservertoken and the tool will spit out a
single use token.  For example:
```bash
$  zkservertoken 
7000 8677 6548 2615
```

## Issue Tracker

The [integrated github issue tracker](https://github.com/companyzero/zkc/issues)
is used for this project.

## Documentation

The documentation is a work-in-progress.  Add link here.

## Disclaimer

**zkc has not been audited yet.  Use wisely.**

## Audits and Development

We are looking for contractors to audit and develop zkc and its crypto libs. Pay is offered in Decred.

## License

zkc is licensed under the [copyfree](http://copyfree.org) ISC License.
