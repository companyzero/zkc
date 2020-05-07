// Copyright (c) 2016-2020 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/companyzero/ttk"
	"github.com/companyzero/zkc/rpc"
	"github.com/companyzero/zkc/zkutil"
	"github.com/mitchellh/go-homedir"
	"github.com/vaughan0/go-ini"
)

var (
	ErrIniNotFound = errors.New("not found")
)

type Settings struct {
	Home string // user home directory

	// default section
	Root       string // root directory for zkclient
	TLSVerbose bool   // display outer TLS information
	Beep       bool   // annoy people when message comes in
	Separator  bool   // add line where conversation left off

	// log section
	SaveHistory    bool
	LogFile        string // log filename
	TimeFormat     string // debug file time stamp format
	LongTimeFormat string // long time stamp format
	Debug          bool   // enable debug
	Profiler       string // go profiler link

	// ui section
	NickColor string
	GcColor   string
	PmColor   string
}

func textToColor(in string) (int, error) {
	var c int
	switch strings.ToLower(in) {
	case "na":
		c = ttk.AttrNA
	case "black":
		c = ttk.ColorBlack
	case "red":
		c = ttk.ColorRed
	case "green":
		c = ttk.ColorGreen
	case "yellow":
		c = ttk.ColorYellow
	case "blue":
		c = ttk.ColorBlue
	case "magenta":
		c = ttk.ColorMagenta
	case "cyan":
		c = ttk.ColorCyan
	case "white":
		c = ttk.ColorWhite
	default:
		return ttk.AttrNA, fmt.Errorf("invalid color: %v", in)
	}
	return c, nil
}

func colorToAnsi(in string) (string, error) {
	s := strings.Split(in, ":")
	if len(s) != 3 {
		return "", fmt.Errorf("invalid color format: " +
			"attribute:foreground:background")
	}

	a := 0
	aa := strings.Split(strings.ToLower(s[0]), ",")
	for _, k := range aa {
		switch strings.ToLower(k) {
		case "bold":
			a |= ttk.AttrBold
		case "underline":
			a |= ttk.AttrUnderline
		case "reverse":
			a |= ttk.AttrReverse
		default:
			return "", fmt.Errorf("invalid attribute: %v", k)
		}
	}

	fg, err := textToColor(s[1])
	if err != nil {
		return "", err
	}

	bg, err := textToColor(s[2])
	if err != nil {
		return "", err
	}

	return ttk.Color(a, fg, bg)
}

func ObtainSettings() (*Settings, error) {
	home, err := homedir.Dir()
	if err != nil {
		return nil, err
	}
	// defaults
	s := Settings{
		Home: home,

		// default
		Root:       filepath.Join("~", zkutil.DefaultZKClientDir),
		TLSVerbose: true,
		Beep:       false,
		Separator:  false,

		// log
		SaveHistory: false,
		LogFile: filepath.Join("~", zkutil.DefaultZKClientDir,
			zkutil.DefaultZKClientLog),
		TimeFormat:     "15:04:05",
		LongTimeFormat: "2006-01-02 15:04:05",
		Debug:          false,
		Profiler:       "localhost:6061",

		NickColor: WHITEBOLD,
		GcColor:   GREENBOLD,
		PmColor:   CYANBOLD,
	}

	// config file
	defaultConfFile := filepath.Join(s.Home, zkutil.DefaultZKClientDir,
		zkutil.DefaultZKClientConf)
	filename := flag.String("cfg", defaultConfFile, "config file")
	export := flag.String("export", "", "export config file")
	version := flag.Bool("version", false, "show version")
	flag.Parse()

	if *version {
		fmt.Fprintf(os.Stderr, "zkclient %s (%s) protocol version %d\n",
			zkutil.Version(), runtime.Version(), rpc.ProtocolVersion)
		os.Exit(0)
	}

	if *export != "" {
		fmt.Printf("exporting config file to: %v\n", *export)
		err = ioutil.WriteFile(*export,
			[]byte(defaultConfigFileContent), 0700)
		if err != nil {
			return nil, err
		}
		os.Exit(0)
	}

	// see if we are running for the first time with defaults

	fi, err := os.Stat(*filename)
	if err != nil {
		if os.IsNotExist(err) && *filename == defaultConfFile {
			fmt.Printf("Initial run, creating default config: %v\n",
				defaultConfFile)
			// We are running defaults so create dir and a conf file
			err = os.MkdirAll(filepath.Dir(defaultConfFile), 0700)
			if err != nil {
				return nil, err
			}
			err = ioutil.WriteFile(defaultConfFile,
				[]byte(defaultConfigFileContent), 0700)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	} else {
		// make sure conf isn't a dir
		if fi.IsDir() {
			return nil, fmt.Errorf("not a valid configuration file")
		}
	}

	// parse file
	cfg, err := ini.LoadFile(*filename)
	if err != nil && *filename != flag.Lookup("cfg").DefValue {
		return nil, err
	}

	// root directory
	root, ok := cfg.Get("", "root")
	if ok {
		s.Root = root
	}
	s.Root, err = homedir.Expand(s.Root)
	if err != nil {
		return nil, err
	}

	// TLS
	err = iniBool(cfg, &s.TLSVerbose, "", "tlsverbose")
	if err != nil && !errors.Is(err, ErrIniNotFound) {
		return nil, err
	}

	// Beep
	err = iniBool(cfg, &s.Beep, "", "beep")
	if err != nil && !errors.Is(err, ErrIniNotFound) {
		return nil, err
	}

	// Separator
	err = iniBool(cfg, &s.Separator, "", "separator")
	if err != nil && !errors.Is(err, ErrIniNotFound) {
		return nil, err
	}

	// logging and debug
	err = iniBool(cfg, &s.SaveHistory, "log", "savehistory")
	if err != nil && !errors.Is(err, ErrIniNotFound) {
		return nil, err
	}

	logFile, ok := cfg.Get("log", "logfile")
	if ok {
		s.LogFile = logFile
	}
	s.LogFile, err = homedir.Expand(s.LogFile)
	if err != nil {
		return nil, err
	}

	err = iniBool(cfg, &s.Debug, "log", "debug")
	if err != nil && !errors.Is(err, ErrIniNotFound) {
		return nil, err
	}

	timeFormat, ok := cfg.Get("log", "timeformat")
	if ok {
		s.TimeFormat = timeFormat
	}

	longTimeFormat, ok := cfg.Get("log", "longtimeformat")
	if ok {
		s.LongTimeFormat = longTimeFormat
	}

	profiler, ok := cfg.Get("log", "profiler")
	if ok {
		s.Profiler = profiler
	}

	// ui
	nickColor, ok := cfg.Get("ui", "nickcolor")
	if ok {
		color, err := colorToAnsi(nickColor)
		if err != nil {
			return nil, fmt.Errorf("nickcolor: %v", err)
		}
		s.NickColor = color
	}

	gcOtherColor, ok := cfg.Get("ui", "gcothercolor")
	if ok {
		color, err := colorToAnsi(gcOtherColor)
		if err != nil {
			return nil, fmt.Errorf("gcothercolor: %v", err)
		}
		s.GcColor = color
	}

	pmOtherColor, ok := cfg.Get("ui", "pmothercolor")
	if ok {
		color, err := colorToAnsi(pmOtherColor)
		if err != nil {
			return nil, fmt.Errorf("pmothercolor: %v", err)
		}
		s.PmColor = color
	}

	return &s, nil
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
	return ErrIniNotFound
}
