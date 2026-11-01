package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/remote"
)

const rotateUsage = `usage:
  eidchain rotate create --old KEY-ID-PREFIX --new-key FILE [--server URL] [--out rotation.json]
  eidchain rotate sign   --key AUTHORITY.key [--yes] rotation.json
  eidchain rotate submit [--server URL] rotation.json

A rotation replaces one authority key by another. It needs approvals from at
least the chain's rotation quorum of currently valid authority keys: each
authority runs "rotate sign" on the same file, then anyone submits it to a node.
The file is a proposal until enough signatures are collected.`

func cmdRotate(args []string) error {
	if len(args) == 0 {
		return errors.New(rotateUsage)
	}
	switch args[0] {
	case "create":
		return rotateCreate(args[1:])
	case "sign":
		return rotateSign(args[1:])
	case "submit":
		return rotateSubmit(args[1:])
	}
	return errors.New(rotateUsage)
}

func rotateCreate(args []string) error {
	fs := newFlagSet("rotate create")
	data := fs.String("data", defaultData(), "data directory (to find a configured peer)")
	server := fs.String("server", "", "node URL")
	old := fs.String("old", "", "ID (or unique prefix) of the authority key to replace")
	newKey := fs.String("new-key", "", "private key file for the new authority key; generated if it does not exist")
	out := fs.String("out", "rotation.json", "proposal file to write")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *old == "" || *newKey == "" {
		return errors.New("--old and --new-key are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	info, err := remote.New(serverArg(*server, *data)).Info(ctx)
	if err != nil {
		return err
	}
	var oldID string
	for _, id := range info.Authorities {
		if strings.HasPrefix(id, *old) {
			if oldID != "" {
				return fmt.Errorf("--old %q is ambiguous", *old)
			}
			oldID = id
		}
	}
	if oldID == "" {
		return fmt.Errorf("no current authority matches %q", *old)
	}
	key, err := chain.LoadPrivateKey(*newKey)
	if errors.Is(err, os.ErrNotExist) {
		if key, err = chain.GenerateKey(); err != nil {
			return err
		}
		if err = chain.SavePrivateKey(*newKey, key); err != nil {
			return err
		}
		fmt.Printf("Generated new authority key %s\n", *newKey)
	} else if err != nil {
		return err
	}
	pub, _ := chain.EncodePublicKey(&key.PublicKey)
	newID, _ := chain.KeyID(&key.PublicKey)
	rot := chain.Rotation{Change: chain.KeyChange{Type: "replace", Chain: info.GenesisHash, Seq: info.RotationSeq, Old: oldID, NewKey: pub}}
	if err := writeRotation(*out, rot); err != nil {
		return err
	}
	fmt.Printf("Proposal %s written to %s\n  replace %s\n  with    %s\nNeeds %d approval(s): run `eidchain rotate sign --key <authority.key> %s`.\n",
		rot.Change.Hash().Short(), *out, oldID, newID, info.RotationQuorum, *out)
	return nil
}

func rotateSign(args []string) error {
	fs := newFlagSet("rotate sign")
	keyFile := fs.String("key", "", "this authority's private key file")
	yes := fs.Bool("yes", false, "approve without asking (for scripts; check the file some other way first)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *keyFile == "" || len(pos) != 1 {
		return errors.New("usage: eidchain rotate sign --key AUTHORITY.key [--yes] rotation.json")
	}
	key, err := chain.LoadPrivateKey(*keyFile)
	if err != nil {
		return err
	}
	id, _ := chain.KeyID(&key.PublicKey)
	rot, err := readRotation(pos[0])
	if err != nil {
		return err
	}
	if err := confirmRotation(rot, id, *yes); err != nil {
		return err
	}
	sig, err := chain.SignKeyChange(chain.Signer{ID: id, Key: key}, rot.Change)
	if err != nil {
		return err
	}
	rot.AddSignature(sig)
	if err := writeRotation(pos[0], rot); err != nil {
		return err
	}
	fmt.Printf("Approved as %s…; %s now holds %d approval(s).\n", id[:12], pos[0], len(rot.Signatures))
	return nil
}

// confirmRotation shows what is about to be approved. A proposal is just a file
// someone sent you, and approving it hands authority to whoever holds the new key.
func confirmRotation(r chain.Rotation, signer string, yes bool) error {
	pub, err := chain.DecodePublicKey(r.Change.NewKey)
	if err != nil {
		return fmt.Errorf("proposal: %w", err)
	}
	newID, err := chain.KeyID(pub)
	if err != nil {
		return err
	}
	fmt.Printf("You are approving, as %s…:\n  chain    %s\n  sequence %d\n  replace  %s\n  with     %s\n", signer[:12], r.Change.Chain, r.Change.Seq, r.Change.Old, newID)
	fmt.Printf("Whoever holds the new key becomes a chain authority. Check its ID with them over a channel you trust.\n")
	if yes {
		return nil
	}
	fmt.Print("Approve? [y/N] ")
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		return errors.New("not approved; the file is unchanged")
	}
	return nil
}

func rotateSubmit(args []string) error {
	fs := newFlagSet("rotate submit")
	data := fs.String("data", defaultData(), "data directory (to find a configured peer)")
	server := fs.String("server", "", "node URL")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: eidchain rotate submit [--server URL] rotation.json")
	}
	rot, err := readRotation(pos[0])
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := remote.New(serverArg(*server, *data)).PostRotation(ctx, rot)
	if err != nil {
		return err
	}
	if st.Ready {
		fmt.Printf("Accepted: %d/%d approvals. It goes into the next block that a node cuts.\n", st.Approvals, st.Quorum)
	} else {
		fmt.Printf("Accepted but not ready: %d/%d approvals. Collect more signatures and submit again.\n", st.Approvals, st.Quorum)
	}
	return nil
}

func readRotation(path string) (chain.Rotation, error) {
	var r chain.Rotation
	raw, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	return r, chain.StrictUnmarshal(raw, &r)
}

func writeRotation(path string, r chain.Rotation) error {
	if r.Signatures == nil {
		r.Signatures = []chain.RotationSig{}
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
