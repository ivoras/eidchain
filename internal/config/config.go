// Package config reads and writes <data>/config.json, which supplies defaults
// for command-line flags (flags always win).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"eidchain/internal/chain"
)

// File is the on-disk configuration. Every field is optional.
type File struct {
	GenesisHash   string   `json:"genesisHash,omitempty"`
	Listen        string   `json:"listen,omitempty"`
	Peers         []string `json:"peers,omitempty"`
	BlockInterval string   `json:"blockInterval,omitempty"` // e.g. "10m"
	SyncInterval  string   `json:"syncInterval,omitempty"`
	OCSP          string   `json:"ocsp,omitempty"` // "required" or "skip"
	KeysDir       string   `json:"keysDir,omitempty"`
	// Advertise is this node's public base URL (for example https://host/chain). If set,
	// the node announces it to its peers, which then gossip with it too.
	Advertise string `json:"advertise,omitempty"`
	// PeerExchange false turns peer exchange off (default on).
	PeerExchange *bool `json:"peerExchange,omitempty"`
	// Features maps feature names to the height they apply from. This is a
	// consensus rule: every node of a chain must have the same value. `eidchain
	// pull` copies it from the server if this file has none.
	Features map[string]uint64 `json:"features,omitempty"`
	// TrustCAs lists the CA certificates accepted for eID signatures in a NEW
	// chain (`eidchain genesis`): PEM file paths (relative paths are relative
	// to the data directory) or "builtin:hr" for the embedded AKDCA Root and
	// HRIDCA. Default: ["builtin:hr"]. Once a chain exists its CA set is fixed
	// in the genesis block, because every node must apply the same rules.
	TrustCAs []string `json:"trustCAs,omitempty"`
}

func path(dir string) string { return filepath.Join(dir, "config.json") }

// Load returns the configuration in dir; a missing file is not an error.
func Load(dir string) (File, error) {
	var f File
	raw, err := os.ReadFile(path(dir))
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := chain.StrictUnmarshal(raw, &f); err != nil {
		return File{}, fmt.Errorf("%s: %w", path(dir), err) // a misspelt setting must not be ignored
	}
	return f, nil
}

// Save writes the configuration to dir.
func Save(dir string, f File) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path(dir), append(raw, '\n'), 0o644)
}
