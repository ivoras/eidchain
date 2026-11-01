package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/config"
	"eidchain/internal/remote"
)

// cmdSubmit sends a record and its detached CAdES signature (as made by the
// /signer page or `openssl cms -sign`) to a node.
func cmdSubmit(args []string) error {
	fs := newFlagSet("submit")
	data := fs.String("data", defaultData(), "data directory (to find a configured peer)")
	server := fs.String("server", "", "node URL (default: first peer in config.json, else http://localhost:8080)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return errors.New("usage: eidchain submit [flags] PAYLOAD-FILE SIGNATURE-FILE")
	}
	payload, err := os.ReadFile(pos[0]) // the exact bytes that were signed
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(pos[1])
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := remote.New(serverArg(*server, *data)).PostPayload(ctx, chain.PayloadEntry{
		Payload: string(payload), Signature: base64.StdEncoding.EncodeToString(normaliseCMS(raw)),
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s: payload %s (OCSP checked: %v)\n", res.Status, res.ID, res.OCSP)
	return nil
}

// normaliseCMS accepts DER, PEM or bare base64 and returns DER.
func normaliseCMS(raw []byte) []byte {
	if blk, _ := pem.Decode(raw); blk != nil {
		return blk.Bytes
	}
	if len(raw) > 0 && raw[0] != 0x30 {
		if der, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw))); err == nil {
			return der
		}
	}
	return raw
}

func cmdVerify(args []string) error {
	fs := newFlagSet("verify")
	data := fs.String("data", defaultData(), "data directory")
	genesis := fs.String("genesis-hash", "", "expected genesis hash")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	cfg, err := config.Load(*data)
	if err != nil {
		return err
	}
	want, err := genesisHashArg(*genesis, cfg)
	if err != nil {
		return err
	}
	st, err := chain.Open(*data, want)
	if err != nil {
		return err
	}
	start := time.Now()
	h, err := st.Verify()
	if err != nil {
		return fmt.Errorf("chain invalid after height %d: %w", h, err)
	}
	if len(st.Skipped) > 0 {
		for _, line := range st.Skipped {
			fmt.Fprintln(os.Stderr, "  ", line)
		}
		return fmt.Errorf("%d block file(s) are damaged or do not connect; only height %d could be checked", len(st.Skipped), h)
	}
	head, _ := st.Head()
	fmt.Printf("OK: chain %s verified from the genesis to height %d (head %s) in %s\n",
		st.P.GenesisHash.Short(), h, head.Short(), time.Since(start).Round(time.Millisecond))
	return nil
}

func cmdInfo(args []string) error {
	fs := newFlagSet("info")
	data := fs.String("data", defaultData(), "data directory (to find a configured peer)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	server := ""
	if len(pos) > 0 {
		server = pos[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	i, err := remote.New(serverArg(server, *data)).Info(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("chain:        %s\nmessage:      %q\nheight:       %d\nhead:         %s\n", i.GenesisHash, i.Message, i.Height, i.Head)
	fmt.Printf("pending:      %d payload(s), %d rotation(s)\nauthorities:  %d (rotation seq %d, quorum %d)\n",
		i.Pending, i.PendingRotations, len(i.Authorities), i.RotationSeq, i.RotationQuorum)
	for _, a := range i.Authorities {
		fmt.Println("  ", a)
	}
	fmt.Printf("next block:   %s (every %ds, if anything is pending)\n", time.Unix(i.NextBlockAt, 0).Format(time.RFC3339), i.BlockIntervalSeconds)
	return nil
}
