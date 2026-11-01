// Command eidchain runs and operates an eidchain node.
package main

import (
	"fmt"
	"os"
)

const usage = `eidchain: proof-of-authority chain of JSON records signed with eID certificates

Usage:
  eidchain node     [flags]                 run a node (API, web app, block production, gossip)
  eidchain pull     [flags] SERVER-URL      download and verify a chain from a running node
  eidchain genesis  [flags]                 create a new chain (genesis block and authority keys)
  eidchain submit   [flags] PAYLOAD SIG     submit a signed record to a node
  eidchain rotate   create|sign|submit      rotate an authority key
  eidchain verify   [flags]                 re-verify the local chain from the genesis
  eidchain info     [flags] [SERVER-URL]    show a node's status

Every command takes -h for its flags. The data directory defaults to ./data
(override with --data or EIDCHAIN_DATA); <data>/config.json supplies defaults.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "node":
		err = cmdNode(args)
	case "pull":
		err = cmdPull(args)
	case "genesis":
		err = cmdGenesis(args)
	case "submit":
		err = cmdSubmit(args)
	case "rotate":
		err = cmdRotate(args)
	case "verify":
		err = cmdVerify(args)
	case "info":
		err = cmdInfo(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
