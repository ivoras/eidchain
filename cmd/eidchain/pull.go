package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/config"
	"eidchain/internal/remote"
)

// cmdPull behaves like `docker pull`: the first pull needs the chain's identity
// (its genesis hash, like an image digest), everything downloaded is verified
// locally, and a repeated pull only fetches what is new.
func cmdPull(args []string) error {
	fs := newFlagSet("pull")
	data := fs.String("data", defaultData(), "data directory")
	genesis := fs.String("genesis-hash", "", "expected genesis block hash (or EIDCHAIN_GENESIS_HASH, or genesisHash in config.json)")
	tofu := fs.Bool("trust-first-use", false, "accept whatever genesis the server offers when no hash is given")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: eidchain pull [flags] SERVER-URL")
	}
	server := pos[0]
	cfg, err := config.Load(*data)
	if err != nil {
		return err
	}
	want, err := genesisHashArg(*genesis, cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	c := remote.New(server)

	if _, err := os.Stat(chain.GenesisPath(*data)); errors.Is(err, os.ErrNotExist) {
		if want.IsZero() && !*tofu {
			return errors.New("no chain in " + *data + ": give the genesis hash with --genesis-hash (or pass --trust-first-use)")
		}
		fmt.Printf("Looking up genesis on %s\n", server)
		raw, err := c.GenesisRaw(ctx)
		if err != nil {
			return err
		}
		g, err := chain.ParseGenesis(raw)
		if err != nil {
			return err
		}
		if !want.IsZero() && g.Hash() != want {
			return fmt.Errorf("server's genesis hash is %s, expected %s", g.Hash(), want)
		}
		if want.IsZero() {
			fmt.Printf("WARNING: trusting genesis %s on first use\n", g.Hash())
		}
		if _, err := chain.Init(*data, g); err != nil {
			return err
		}
		want = g.Hash()
	}
	st, err := chain.Open(*data, want)
	if err != nil {
		return err
	}
	fmt.Printf("Pulling chain %s from %s\n", st.P.GenesisHash.Short(), server)
	fmt.Printf("  %q\n", st.P.Genesis.Message)
	_, before := st.Head()
	start := time.Now()
	res, err := remote.Sync(ctx, st, c, func(s string) { fmt.Println(" ", s) })
	if err != nil {
		return err
	}
	head, height := st.Head()
	fmt.Printf("Digest: sha256:%s\n", head)
	switch {
	case res.UpToDate:
		fmt.Printf("Status: Chain is up to date for %s (height %d)\n", server, height)
	case height > before:
		fmt.Printf("Status: Downloaded newer chain for %s (height %d -> %d, %s)\n", server, before, height, time.Since(start).Round(time.Millisecond))
	default:
		fmt.Printf("Status: Fetched %d block(s); local chain remains at height %d\n", res.Fetched, height)
	}
	// Remember the chain identity and the remote, so `node` and later pulls need no flags.
	cfg.GenesisHash = st.P.GenesisHash.String()
	if !slices.Contains(cfg.Peers, server) {
		cfg.Peers = append(cfg.Peers, server)
	}
	return config.Save(*data, cfg)
}
