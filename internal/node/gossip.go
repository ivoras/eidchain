package node

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/remote"
)

// fanout runs fn against every peer concurrently.
func (n *Node) fanout(what string, fn func(context.Context, *remote.Client) error) {
	for _, p := range n.allPeers() {
		go func(p *remote.Client) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := fn(ctx, p); err != nil {
				log.Printf("gossip %s to %s: %v", what, p.Base, err)
			}
		}(p)
	}
}

func (n *Node) broadcastBlock(b *chain.Block) {
	n.fanout("block", func(ctx context.Context, p *remote.Client) error {
		_, err := p.PostBlock(ctx, b)
		return err
	})
}

func (n *Node) broadcastPayload(e chain.PayloadEntry) {
	n.fanout("payload", func(ctx context.Context, p *remote.Client) error {
		_, err := p.PostPayload(ctx, e)
		return err
	})
}

func (n *Node) broadcastRotation(r chain.Rotation) {
	n.fanout("rotation", func(ctx context.Context, p *remote.Client) error {
		_, err := p.PostRotation(ctx, r)
		return err
	})
}

// syncLoop pulls from every peer at startup, periodically, and when a pushed
// block arrives whose parent we do not have.
func (n *Node) syncLoop(ctx context.Context) {
	t := time.NewTicker(n.opt.SyncInterval)
	defer t.Stop()
	go n.syncAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-n.kick:
		}
		go n.syncAll(ctx) // never wait: a slow peer must not hold up the others
	}
}

// syncAll syncs with every peer at once and returns when they are done. A peer
// still busy from an earlier round is skipped, so a slow or hostile peer only ever
// costs its own connection.
func (n *Node) syncAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, p := range n.allPeers() {
		if _, busy := n.syncing.LoadOrStore(p.Base, true); busy {
			continue
		}
		wg.Add(1)
		go func(p *remote.Client) {
			defer wg.Done()
			defer n.syncing.Delete(p.Base)
			n.syncPeer(ctx, p)
		}(p)
	}
	wg.Wait()
}

func (n *Node) syncPeer(ctx context.Context, p *remote.Client) {
	sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	res, err := remote.Sync(sctx, n.store, p, nil)
	cancel()
	n.recordPeerResult(p.Base, err)
	if err == nil {
		n.exchange(ctx, p)
	}
	switch {
	case err != nil && !errors.Is(err, context.Canceled):
		log.Printf("sync from %s: %v", p.Base, err)
	case err == nil && res.Fetched > 0:
		log.Printf("sync from %s: fetched %d block(s), now at height %d", p.Base, res.Fetched, res.Height)
	}
}

func (n *Node) kickSync() {
	select {
	case n.kick <- struct{}{}:
	default:
	}
}
