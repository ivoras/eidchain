package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/config"
	"eidchain/internal/hrca"
)

// cmdGenesis creates a new chain: a genesis block (authority public keys,
// trusted CAs, rules, a message) plus the authorities' private keys.
func cmdGenesis(args []string) error {
	fs := newFlagSet("genesis")
	data := fs.String("data", defaultData(), "data directory")
	out := fs.String("out", "", "where to write the genesis file (default <data>/genesis.json)")
	keysDir := fs.String("keys", "", "where to write new authority private keys (default <data>/keys)")
	n := fs.Int("authorities", -1, "number of new authority keys to generate (default 3, or 0 if --authority-pubkey is given)")
	var pubs, cas stringList
	fs.Var(&pubs, "authority-pubkey", "existing authority public key: base64 SPKI or a PEM file path (repeatable)")
	fs.Var(&cas, "trust-ca", `eID CA certificates to trust: a PEM file, or "builtin:hr" (repeatable; default: "trustCAs" in config.json, else builtin:hr = AKDCA Root + HRIDCA)`)
	message := fs.String("message", "", "free text recorded in the genesis block, e.g. a news headline (required)")
	quorum := fs.Int("rotation-quorum", 0, "approvals needed to rotate an authority key (default: a majority)")
	created := fs.String("created", "", "creation time, RFC 3339 (default now)")
	force := fs.Bool("force", false, "overwrite an existing genesis file")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if strings.TrimSpace(*message) == "" {
		return errors.New("--message is required")
	}
	if *out == "" {
		*out = chain.GenesisPath(*data)
	}
	if *keysDir == "" {
		*keysDir = filepath.Join(*data, "keys")
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("%s already exists (use --force to replace it; that makes a different chain)", *out)
	}
	when := time.Now()
	if *created != "" {
		t, err := time.Parse(time.RFC3339, *created)
		if err != nil {
			return fmt.Errorf("--created: %w", err)
		}
		when = t
	}

	var auths []chain.Authority
	for i, p := range pubs {
		if raw, err := os.ReadFile(p); err == nil {
			p = string(raw)
		}
		pub, err := chain.DecodePublicKey(p)
		if err != nil {
			return fmt.Errorf("--authority-pubkey %d: %w", i+1, err)
		}
		enc, _ := chain.EncodePublicKey(pub)
		auths = append(auths, chain.Authority{Name: fmt.Sprintf("authority-%d", len(auths)+1), PublicKey: enc})
	}
	count := *n
	if count < 0 {
		count = 3
		if len(pubs) > 0 {
			count = 0
		}
	}
	var newKeys []string
	for i := 0; i < count; i++ {
		key, err := chain.GenerateKey()
		if err != nil {
			return err
		}
		path := nextKeyPath(*keysDir)
		if err := chain.SavePrivateKey(path, key); err != nil {
			return err
		}
		newKeys = append(newKeys, path)
		enc, _ := chain.EncodePublicKey(&key.PublicKey)
		auths = append(auths, chain.Authority{Name: fmt.Sprintf("authority-%d", len(auths)+1), PublicKey: enc})
	}
	cfg, err := config.Load(*data)
	if err != nil {
		return err
	}
	anchors, err := resolveTrustCAs(cas, cfg, *data)
	if err != nil {
		return err
	}
	g, err := chain.NewGenesis(*message, auths, anchors, when)
	if err != nil {
		return err
	}
	if *quorum != 0 {
		g.Rules.RotationQuorum = *quorum
		if _, err := chain.NewParams(g); err != nil {
			return err
		}
	}
	if err := chain.SaveGenesis(*out, g); err != nil {
		return err
	}
	fmt.Printf("Genesis written to %s\n", *out)
	fmt.Printf("Genesis hash: %s\n", g.Hash())
	fmt.Printf("Message:      %q\n", g.Message)
	fmt.Printf("Authorities:  %d (rotation quorum %d)\n", len(g.Authorities), g.Rules.RotationQuorum)
	for _, a := range g.Authorities {
		pub, _ := chain.DecodePublicKey(a.PublicKey)
		id, _ := chain.KeyID(pub)
		fmt.Printf("  %s  %s\n", a.Name, id)
	}
	for _, k := range newKeys {
		fmt.Printf("New private key: %s (keep it secret; it is not part of the genesis)\n", k)
	}
	fmt.Println("Trusted eID CAs (fixed in the genesis for every node):")
	if p, err := chain.NewParams(g); err == nil {
		for _, c := range p.Trust.Certificates() {
			fp := sha256.Sum256(c.Raw)
			fmt.Printf("  %s  (valid until %s, sha256 %x…)\n", chain.CertName(c), c.NotAfter.Format("2006-01-02"), fp[:6])
		}
	}
	if filepath.Clean(*out) == filepath.Clean(chain.GenesisPath(*data)) {
		cfg.GenesisHash = g.Hash().String()
		if err := config.Save(*data, cfg); err != nil {
			return err
		}
		fmt.Printf("Configured genesisHash in %s\n", filepath.Join(*data, "config.json"))
	}
	return nil
}

func nextKeyPath(dir string) string {
	for i := 1; ; i++ {
		p := filepath.Join(dir, fmt.Sprintf("authority-%d.key", i))
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p
		}
	}
}

// resolveTrustCAs picks the eID CA certificates for a new chain: --trust-ca
// flags, else "trustCAs" from config.json, else the embedded AKD CA. Entries
// are PEM file paths or "builtin:<name>".
func resolveTrustCAs(flagVals []string, cfg config.File, dataDir string) ([]string, error) {
	entries, base := flagVals, ""
	if len(entries) == 0 {
		entries, base = cfg.TrustCAs, dataDir // config paths are relative to the data directory
	}
	if len(entries) == 0 {
		entries = []string{"builtin:hr"}
	}
	var out []string
	for _, e := range entries {
		if name, ok := strings.CutPrefix(e, "builtin:"); ok {
			pem, found := hrca.Builtin(name)
			if !found {
				return nil, fmt.Errorf("unknown built-in CA bundle %q (available: hr)", name)
			}
			out = append(out, pem)
			continue
		}
		path := e
		if base != "" && !filepath.IsAbs(path) {
			path = filepath.Join(base, path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("trust CA %q: %w", e, err)
		}
		out = append(out, string(raw))
	}
	return out, nil
}
