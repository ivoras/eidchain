package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"path/filepath"
	"syscall"

	"eidchain/internal/config"
	"eidchain/internal/node"
)

func cmdNode(args []string) error {
	fs := newFlagSet("node")
	data := fs.String("data", defaultData(), "data directory")
	listen := fs.String("listen", ":8080", "HTTP listen address")
	genesis := fs.String("genesis-hash", "", "expected genesis block hash (default: the one in <data>/genesis.json)")
	var peers stringList
	fs.Var(&peers, "peer", "base URL of a peer to gossip with and sync from (repeatable)")
	interval := fs.String("block-interval", "10m", "cut a block on every multiple of this interval, if payloads are pending")
	syncInt := fs.String("sync-interval", "30s", "how often to pull from peers")
	ocsp := fs.String("ocsp", "required", `OCSP policy for submitted payloads: "required" or "skip" (testing only)`)
	keys := fs.String("keys", "", "directory of authority private keys (*.key); default <data>/keys")
	noWeb := fs.Bool("no-web", false, "do not serve the example web app")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	set := visited(fs)
	cfg, err := config.Load(*data)
	if err != nil {
		return err
	}
	if !set["listen"] && cfg.Listen != "" {
		*listen = cfg.Listen
	}
	if !set["block-interval"] && cfg.BlockInterval != "" {
		*interval = cfg.BlockInterval
	}
	if !set["sync-interval"] && cfg.SyncInterval != "" {
		*syncInt = cfg.SyncInterval
	}
	if !set["ocsp"] && cfg.OCSP != "" {
		*ocsp = cfg.OCSP
	}
	if !set["keys"] && cfg.KeysDir != "" {
		*keys = cfg.KeysDir
		if !filepath.IsAbs(*keys) {
			*keys = filepath.Join(*data, *keys) // config paths are relative to the data directory
		}
	}
	if !set["peer"] {
		peers = cfg.Peers
	}
	gh, err := genesisHashArg(*genesis, cfg)
	if err != nil {
		return err
	}
	bi, err := parseDuration("block-interval", *interval)
	if err != nil {
		return err
	}
	si, err := parseDuration("sync-interval", *syncInt)
	if err != nil {
		return err
	}
	n, err := node.New(node.Options{
		Data: *data, KeysDir: *keys, Listen: *listen, Peers: peers, BlockInterval: bi, SyncInterval: si,
		OCSP: *ocsp, Web: !*noWeb, GenesisHash: gh,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	if err := n.Run(ctx); err != nil {
		return fmt.Errorf("node: %w", err)
	}
	return nil
}
