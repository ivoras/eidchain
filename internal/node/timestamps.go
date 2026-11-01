package node

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/remote"
	"eidchain/internal/tsa"
)

const (
	maxStampsPerBlock = 4
	stampPageHeights  = 200
)

// stampLoop keeps one authority's tokens up to date: it works through the
// canonical blocks that lack one, oldest first, then watches for new ones.
func (n *Node) stampLoop(ctx context.Context, a tsa.Authority) {
	poll := n.opt.TimestampPoll
	next := uint64(1)
	for {
		h, height, ok := n.unstamped(a, next)
		wait := poll
		if ok {
			wait = a.Gap
			if err := n.stamp(ctx, a, h); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("timestamp from %s for block %d: %v", a.URL, height, err)
				wait = 5 * poll // a problem at the authority never affects the chain
			} else {
				next = height + 1
			}
		} else if _, head := n.store.Head(); head > chain.MaxReorgDepth {
			next = head - chain.MaxReorgDepth // a reorganisation can only change blocks above this
		} else {
			next = 1
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// unstamped finds the first canonical block from height from without a's token.
func (n *Node) unstamped(a tsa.Authority, from uint64) (chain.Hash, uint64, bool) {
	for h := from; ; h++ {
		hash, ok := n.store.HashAt(h)
		if !ok {
			return chain.Hash{}, 0, false
		}
		if !n.stamps.Has(hash, a.Root) {
			return hash, h, true
		}
	}
}

func (n *Node) stamp(ctx context.Context, a tsa.Authority, hash chain.Hash) error {
	token, info, err := tsa.Request(ctx, n.tsaHTTP, a.URL, hash, n.opt.TSARoots)
	if err != nil {
		return err
	}
	if info.Authority != a.Root {
		return errors.New("the token chains to " + info.Authority + ", not " + a.Root)
	}
	added, err := n.stamps.Add(hash, token)
	if err != nil {
		return err
	}
	if added {
		log.Printf("block %s timestamped by %s at %s", hash.Short(), info.Authority, info.Time.UTC().Format(time.RFC3339))
		n.broadcastStamps(hash, [][]byte{token})
	}
	return nil
}

func (n *Node) broadcastStamps(hash chain.Hash, tokens [][]byte) {
	n.fanout("timestamp", func(ctx context.Context, p *remote.Client) error {
		return p.PostStamps(ctx, remote.BlockStamps{Block: hash, Tokens: tokens})
	})
}

func (n *Node) handleStamps(w http.ResponseWriter, r *http.Request) {
	from, _ := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	if from == 0 {
		from = 1
	}
	page := remote.StampPage{Stamps: []remote.BlockStamps{}}
	for h := from; h < from+stampPageHeights; h++ {
		hash, ok := n.store.HashAt(h)
		if !ok {
			break
		}
		if list := n.stamps.List(hash); len(list) > 0 {
			tokens := make([][]byte, len(list))
			for i, s := range list {
				tokens[i] = s.Token
			}
			page.Stamps = append(page.Stamps, remote.BlockStamps{Block: hash, Tokens: tokens})
		}
	}
	if _, ok := n.store.HashAt(from + stampPageHeights); ok {
		page.Next = from + stampPageHeights
	}
	writeJSON(w, 200, page)
}

// handlePostStamps takes tokens from peers. They need no sender: a token either
// verifies for this block or it does not.
func (n *Node) handlePostStamps(w http.ResponseWriter, r *http.Request) {
	var req remote.BlockStamps
	if !decode(w, r, maxStampsPerBlock*(tsa.MaxToken*4/3+64), &req) {
		return
	}
	if len(req.Tokens) == 0 || len(req.Tokens) > maxStampsPerBlock {
		writeErr(w, 400, errors.New("expected 1 to 4 tokens"))
		return
	}
	if _, ok := n.store.Block(req.Block); !ok {
		writeErr(w, 404, errors.New("unknown block"))
		return
	}
	var fresh [][]byte
	for _, t := range req.Tokens {
		added, err := n.stamps.Add(req.Block, t)
		if err != nil {
			writeErr(w, 422, err)
			return
		}
		if added {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) > 0 {
		n.broadcastStamps(req.Block, fresh)
	}
	writeJSON(w, 200, map[string]int{"added": len(fresh)})
}
