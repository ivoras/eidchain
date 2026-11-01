package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/config"
)

// stringList is a repeatable flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func defaultData() string {
	if d := os.Getenv("EIDCHAIN_DATA"); d != "" {
		return d
	}
	return "./data"
}

// parse parses flags that may come before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// visited returns the names of flags that were set explicitly.
func visited(fs *flag.FlagSet) map[string]bool {
	m := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { m[f.Name] = true })
	return m
}

// genesisHashArg resolves the expected genesis hash: flag, then env, then config.
func genesisHashArg(flagVal string, cfg config.File) (chain.Hash, error) {
	s := flagVal
	if s == "" {
		s = os.Getenv("EIDCHAIN_GENESIS_HASH")
	}
	if s == "" {
		s = cfg.GenesisHash
	}
	if s == "" {
		return chain.Hash{}, nil
	}
	return chain.ParseHash(s)
}

func parseDuration(name, v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("--%s: %w", name, err)
	}
	return d, nil
}

// serverArg picks the node to talk to: the flag, else the first configured peer,
// else this data directory's own node.
func serverArg(flagVal, dataDir string) string {
	if flagVal != "" {
		return flagVal
	}
	cfg, err := config.Load(dataDir)
	if err == nil && len(cfg.Peers) > 0 {
		return cfg.Peers[0]
	}
	if err == nil {
		if _, port, perr := net.SplitHostPort(cfg.Listen); perr == nil && port != "" {
			return "http://localhost:" + port
		}
	}
	return "http://localhost:8080"
}
