package settings

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"

	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/tools"
	"github.com/vaughan0/go-ini"
)

// Settings is the collection of all zkserver settings.  This is separated out
// in order to be able to reuse in various tests.
type Settings struct {
	// default section
	Root              string // root directory for zkserver
	Users             string // user home directories
	Listen            string // listen address and port
	AllowIdentify     bool   // identify server policy
	CreatePolicy      string // create account server policy
	Directory         bool   // whether we keep a directory of identities
	MOTD              string // filename to message of the day
	MaxAttachmentSize uint64 // maximum attachment size
	MaxChunkSize      uint64 // maximum chunk size
	MaxMsgSize        uint64 // maximum message size

	// log section
	LogFile    string // log filename
	TimeFormat string // debug file time stamp format
	Debug      bool   // enable debug
	Trace      bool   // enable tracing
	Profiler   string // go profiler link
}

var (
	errIniNotFound = errors.New("not found")
)

// New returns a default settings structure.
func New() *Settings {
	return &Settings{
		// default
		Root:              "~/.zkserver",
		Users:             "~/.zkserver/" + tools.ZKSHome,
		Listen:            "127.0.0.1:12345",
		AllowIdentify:     false,
		CreatePolicy:      "no",
		Directory:         false,
		MOTD:              "~/.zkserver/motd.txt",
		MaxAttachmentSize: rpc.PropMaxAttachmentSizeDefault,
		MaxChunkSize:      rpc.PropMaxChunkSizeDefault,
		MaxMsgSize:        rpc.PropMaxMsgSizeDefault,

		// log
		LogFile:    "~/.zkserver/zkserver.log",
		TimeFormat: "2006-01-02 15:04:05",
		Debug:      false,
		Trace:      false,
		Profiler:   "localhost:6060",
	}
}

// Load retrieves settings from an ini file.  Additionally it expands all ~ to
// the current user home directory.
func (s *Settings) Load(filename string) error {
	// parse file
	cfg, err := ini.LoadFile(filename)
	if err != nil {
		return err
	}

	// obtain current user for directory expansion
	usr, err := user.Current()
	if err != nil {
		return err
	}

	// root directory
	root, ok := cfg.Get("", "root")
	if ok {
		s.Root = root
	}
	s.Root = strings.Replace(s.Root, "~", usr.HomeDir, 1)

	// users directory
	users, ok := cfg.Get("", "users")
	if ok {
		s.Users = users
	}
	s.Users = strings.Replace(s.Users, "~", usr.HomeDir, 1)

	// listen address
	listen, ok := cfg.Get("", "listen")
	if ok {
		s.Listen = listen
	}
	s.Listen = strings.Replace(s.Listen, "~", usr.HomeDir, 1)

	// identify policy
	err = iniBool(cfg, &s.AllowIdentify, "", "allowidentify")
	if err != nil && err != errIniNotFound {
		return err
	}

	// account create policy
	cp, ok := cfg.Get("", "createpolicy")
	if ok {
		switch cp {
		case "yes":
		case "no":
		case "token":
		default:
			return fmt.Errorf("invalid createpolicy value: %v", cp)
		}
		s.CreatePolicy = cp
	}

	// directory policy
	err = iniBool(cfg, &s.Directory, "", "directory")
	if err != nil && err != errIniNotFound {
		return err
	}

	// motd
	motd, ok := cfg.Get("", "motd")
	if ok {
		s.MOTD = motd
	}
	s.MOTD = strings.Replace(s.MOTD, "~", usr.HomeDir, 1)

	// maxattachmentsize
	asz, ok := cfg.Get("", "maxattachmentsize")
	if ok {
		s.MaxAttachmentSize, err = strconv.ParseUint(asz, 10, 64)
		if err != nil {
			return fmt.Errorf("maxattachmentsize invalid: %v", err)
		}
	}

	// maxchunksize
	csz, ok := cfg.Get("", "maxchunksize")
	if ok {
		s.MaxChunkSize, err = strconv.ParseUint(csz, 10, 64)
		if err != nil {
			return fmt.Errorf("maxchunksize invalid: %v", err)
		}
	}

	// logging and debug
	logFile, ok := cfg.Get("log", "logfile")
	if ok {
		s.LogFile = logFile
	}
	s.LogFile = strings.Replace(s.LogFile, "~", usr.HomeDir, 1)

	err = iniBool(cfg, &s.Debug, "log", "debug")
	if err != nil && err != errIniNotFound {
		return err
	}

	err = iniBool(cfg, &s.Trace, "log", "trace")
	if err != nil && err != errIniNotFound {
		return err
	}

	timeFormat, ok := cfg.Get("log", "timeformat")
	if ok {
		s.TimeFormat = timeFormat
	}

	profiler, ok := cfg.Get("log", "profiler")
	if ok {
		s.Profiler = profiler
	}

	return nil
}

func iniBool(cfg ini.File, p *bool, section, key string) error {

	v, ok := cfg.Get(section, key)
	if ok {
		switch strings.ToLower(v) {
		case "yes":
			*p = true
			return nil
		case "no":
			*p = false
			return nil
		default:
			return fmt.Errorf("[%v]%v must be yes or no",
				section, key)
		}
	}
	return errIniNotFound
}
