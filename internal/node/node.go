// Package node runs an eidchain node: HTTP API, payload and rotation pools,
// block production, gossip and periodic sync.
package node

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/remote"
)

// Options configure a node.
type Options struct {
	Data          string        // data directory
	KeysDir       string        // authority private keys (*.key); default <Data>/keys
	Listen        string        // HTTP listen address
	Peers         []string      // base URLs of peers to gossip with and sync from
	BlockInterval time.Duration // blocks are cut on wall-clock multiples of this
	SyncInterval  time.Duration
	OCSP          string // "required" or "skip"
	Web           bool   // serve the example web app
	GenesisHash   chain.Hash
	MaxPending    int

	// Peer exchange (see peers.go).
	Advertise         string // this node's public base URL, announced to peers; empty = do not announce
	NoPeerExchange    bool   // use only the peers named in Peers
	AllowPrivatePeers bool   // let learned peers have loopback/private addresses (tests, closed networks)
}

// Node is a running instance.
type Node struct {
	opt       Options
	store     *chain.Store
	pool      *Pool
	rots      *RotationPool
	signers   []chain.Signer
	peers     []*remote.Client // the operator's peers
	book      *peerBook        // peers learned through exchange
	safeHTTP  *http.Client     // client for learned peers: refuses non-public addresses
	selfURL   string           // normalized Advertise
	staticSet map[string]bool  // normalized operator peers
	lookupIP  func(context.Context, string) ([]net.IPAddr, error)

	staticOnce   sync.Once
	staticShared []string // operator peers that may be shared
	ocspHTTP  *http.Client
	meta      sync.Map // payload ID -> msgMeta
	syncing   sync.Map // peer base URL -> a sync is running
	kick      chan struct{}

	warnMu      sync.Mutex
	warnedNoKey bool
}

type msgMeta struct{ Subject, Serial string }

// New opens the chain in opt.Data and prepares a node.
func New(opt Options) (*Node, error) {
	if opt.KeysDir == "" {
		opt.KeysDir = filepath.Join(opt.Data, "keys")
	}
	if opt.BlockInterval < time.Second {
		return nil, errors.New("block interval must be at least 1s")
	}
	if opt.OCSP != "required" && opt.OCSP != "skip" {
		return nil, fmt.Errorf("ocsp policy must be \"required\" or \"skip\", not %q", opt.OCSP)
	}
	if opt.MaxPending <= 0 {
		opt.MaxPending = 5000
	}
	st, err := chain.Open(opt.Data, opt.GenesisHash)
	if err != nil {
		return nil, err
	}
	signers, err := chain.LoadSigners(opt.KeysDir)
	if err != nil {
		return nil, err
	}
	pool, err := newPool(opt.Data, opt.MaxPending)
	if err != nil {
		return nil, fmt.Errorf("load pending payloads: %w", err)
	}
	n := &Node{
		opt: opt, store: st, pool: pool, rots: newRotationPool(), signers: signers,
		ocspHTTP: &http.Client{Timeout: 10 * time.Second}, kick: make(chan struct{}, 1),
	}
	n.lookupIP = net.DefaultResolver.LookupIPAddr
	n.staticSet = map[string]bool{}
	for _, p := range opt.Peers {
		n.peers = append(n.peers, remote.New(p))
		if norm, err := normalizePeerURL(p); err == nil {
			n.staticSet[norm] = true
		}
	}
	if opt.Advertise != "" {
		if n.selfURL, err = normalizePeerURL(opt.Advertise); err != nil {
			return nil, fmt.Errorf("--advertise: %w", err)
		}
	}
	n.safeHTTP = safeHTTPClient(opt.AllowPrivatePeers)
	n.book = newPeerBook(opt.Data, !opt.NoPeerExchange)
	st.OnChange = n.onChange
	// Drop pending payloads that are already on the chain.
	done := map[chain.Hash]bool{}
	for _, it := range pool.Snapshot() {
		if st.OnChain(it.Entry.ID()) {
			done[it.Entry.ID()] = true
		}
	}
	pool.Remove(done)
	return n, nil
}

// Store exposes the underlying store (used by tests and the CLI).
func (n *Node) Store() *chain.Store { return n.store }

// Run serves until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	head, h := n.store.Head()
	log.Printf("chain %s (%q)", n.store.P.GenesisHash.Short(), n.store.P.Genesis.Message)
	log.Printf("head: height %d, %s; %d authorities; %d local signing key(s); ocsp=%s; block interval %s",
		h, head.Short(), len(n.store.P.Initial.IDs), len(n.signers), n.opt.OCSP, n.opt.BlockInterval)
	if n.exchangeEnabled() {
		log.Printf("peers: %d configured, %d learned; peer exchange on, advertising %q", len(n.peers), len(n.book.urls()), n.selfURL)
	} else {
		log.Printf("peers: %d configured; peer exchange off", len(n.peers))
	}
	for _, c := range n.store.P.Trust.Certificates() {
		log.Printf("trust anchor: %q ski=%x valid until %s", chain.CertName(c), c.SubjectKeyId, c.NotAfter.Format("2006-01-02"))
	}
	srv := &http.Server{Addr: n.opt.Listen, Handler: n.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	go n.produceLoop(ctx)
	go n.syncLoop(ctx)
	log.Printf("listening on %s", n.opt.Listen)
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		return err
	}
}

// onChange keeps the pools consistent with the canonical chain.
func (n *Node) onChange(res chain.AddResult) {
	if !res.NewHead {
		return
	}
	included := map[chain.Hash]bool{}
	for _, b := range res.Adopted {
		for _, p := range b.Payloads {
			included[p.ID()] = true
		}
	}
	n.pool.Remove(included)
	state := n.store.HeadState()
	n.rots.Prune(state)
	for _, b := range res.Orphaned {
		for _, p := range b.Payloads {
			if n.store.OnChain(p.ID()) || n.pool.Has(p.ID()) {
				continue
			}
			info, err := n.store.P.VerifyPayload(p, time.Now())
			if err != nil {
				log.Printf("reorg: dropping orphaned payload %s: %v", p.ID().Short(), err)
				continue
			}
			n.pool.Add(poolItem{Entry: p, Subject: info.Subject, Serial: info.Serial, Added: time.Now().Unix()})
		}
		for _, r := range b.Rotations {
			n.rots.Add(n.store.P, state, r) // dropped silently if it no longer applies
		}
	}
	head, h := n.store.Head()
	log.Printf("new head: height %d, %s (%d block(s) adopted, %d orphaned)", h, head.Short(), len(res.Adopted), len(res.Orphaned))
}

// ---- payload submission ----

// ErrBadPayload wraps a validation failure caused by the submitted data.
type ErrBadPayload struct{ Err error }

func (e ErrBadPayload) Error() string { return e.Err.Error() }
func (e ErrBadPayload) Unwrap() error { return e.Err }

// SubmitPayload validates a record and queues it for the next block. The
// signer's certificate is checked against the OCSP responder (or against the
// OCSP response that came with the record, for gossiped payloads).
func (n *Node) SubmitPayload(ctx context.Context, e chain.PayloadEntry, from string) (remote.SubmitResult, error) {
	id := e.ID()
	if n.store.OnChain(id) || n.pool.Has(id) {
		return remote.SubmitResult{Status: "known", ID: id}, nil
	}
	info, err := n.store.P.VerifyPayload(e, time.Now())
	if err != nil {
		log.Printf("payload %s REJECTED from %s: %v", id.Short(), from, err)
		for _, line := range n.store.P.DiagnosePayload(e) {
			log.Printf("  | %s", line)
		}
		return remote.SubmitResult{}, ErrBadPayload{err}
	}
	if e.OCSP != "" || n.opt.OCSP == "required" {
		issuer := n.store.P.Trust.Issuer(info.Cert)
		if issuer == nil {
			log.Printf("payload %s REJECTED from %s: no trust anchor issued the signer certificate: %s", id.Short(), from, chain.DescribeCert(info.Cert))
			return remote.SubmitResult{}, ErrBadPayload{errors.New("the signer's issuing CA is not among the genesis trust anchors")}
		}
		if e.OCSP != "" {
			raw, err := base64.StdEncoding.DecodeString(e.OCSP)
			if err != nil {
				return remote.SubmitResult{}, ErrBadPayload{errors.New("ocsp is not valid base64")}
			}
			if err := chain.VerifyOCSP(raw, info.Cert, issuer, time.Now()); err != nil {
				log.Printf("payload %s REJECTED from %s: supplied OCSP response invalid: %v", id.Short(), from, err)
				return remote.SubmitResult{}, ErrBadPayload{fmt.Errorf("ocsp: %w", err)}
			}
		} else {
			raw, err := chain.FetchOCSP(ctx, n.ocspHTTP, info.Cert, issuer)
			if err != nil {
				log.Printf("payload %s REJECTED from %s: %v; signer certificate: %s", id.Short(), from, err, chain.DescribeCert(info.Cert))
				return remote.SubmitResult{}, ErrBadPayload{err}
			}
			e.OCSP = base64.StdEncoding.EncodeToString(raw)
		}
	}
	added, err := n.pool.Add(poolItem{Entry: e, Subject: info.Subject, Serial: info.Serial, Added: time.Now().Unix()})
	if err != nil {
		return remote.SubmitResult{}, err
	}
	if !added {
		return remote.SubmitResult{Status: "known", ID: id}, nil
	}
	n.meta.Store(id, msgMeta{info.Subject, info.Serial})
	// Success path: no signer name, serial number or client address (PII) here;
	// the rejection paths above keep them because they exist for debugging.
	log.Printf("payload %s accepted (%d bytes, ocsp=%v, issuer %q)", id.Short(), len(e.Payload), e.OCSP != "", info.Cert.Issuer.CommonName)
	n.broadcastPayload(e)
	return remote.SubmitResult{Status: "accepted", ID: id, OCSP: e.OCSP != ""}, nil
}

// ---- block production ----

func nextBoundary(now time.Time, interval time.Duration) time.Time {
	sec := int64(interval / time.Second)
	return time.Unix((now.Unix()/sec+1)*sec, 0)
}

func (n *Node) produceLoop(ctx context.Context) {
	maxJitter := min(5*time.Second, n.opt.BlockInterval/10)
	for {
		wait := time.Until(nextBoundary(time.Now(), n.opt.BlockInterval))
		if maxJitter > 0 {
			// Small random delay so several authority nodes do not all cut the same block.
			wait += rand.N(maxJitter)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			n.produce()
		}
	}
}

// eligibleSigner picks a local key that may sign the next block.
func (n *Node) eligibleSigner(parent chain.Parent) (chain.Signer, bool) {
	for _, s := range n.signers {
		if n.store.P.CanSign(s.ID, parent) {
			return s, true
		}
	}
	return chain.Signer{}, false
}

// blockOverhead is a safe bound on a block's JSON apart from its payloads and rotations.
const blockOverhead = 2048

// produce cuts a block from pending payloads and ready rotations, if any.
func (n *Node) produce() {
	parent := n.store.HeadParent()
	rots := n.rots.Ready(n.store.P, parent.State)
	items := n.pool.Snapshot()
	if len(items) == 0 && len(rots) == 0 {
		return
	}
	signer, ok := n.eligibleSigner(parent)
	if !ok {
		n.warnMu.Lock()
		if !n.warnedNoKey {
			n.warnedNoKey = true
			log.Printf("work is pending but no local authority key may sign now (keys: %d; a key cannot sign again within %d blocks of its last one)",
				len(n.signers), n.store.P.RecentSignerWindow())
		}
		n.warnMu.Unlock()
		return
	}
	n.warnMu.Lock()
	n.warnedNoKey = false
	n.warnMu.Unlock()

	now := time.Now().Unix()
	if now < parent.Time {
		now = parent.Time
	}
	var entries []chain.PayloadEntry
	drop := map[chain.Hash]bool{}
	size := blockOverhead
	for _, r := range rots {
		raw, _ := json.Marshal(r)
		size += len(raw) + 1
	}
	for _, it := range items {
		id := it.Entry.ID()
		if n.store.OnChain(id) {
			drop[id] = true
			continue
		}
		if _, err := n.store.P.VerifyPayload(it.Entry, time.Unix(now, 0)); err != nil {
			log.Printf("dropping pending payload %s: %v", id.Short(), err)
			drop[id] = true
			continue
		}
		raw, _ := json.Marshal(it.Entry)
		if size+len(raw)+1 > chain.MaxBlockBytes {
			break // the rest stays pending for the next block
		}
		size += len(raw) + 1
		entries = append(entries, it.Entry)
	}
	if len(drop) > 0 {
		n.pool.Remove(drop)
	}
	if len(entries) == 0 && len(rots) == 0 {
		return
	}
	b := &chain.Block{
		Header:    chain.Header{Height: parent.Height + 1, Prev: parent.Hash, Time: now},
		Payloads:  entries,
		Rotations: rots,
	}
	if err := chain.SignBlock(signer, b); err != nil {
		log.Printf("sign block: %v", err)
		return
	}
	if _, err := n.store.AddBlock(b); err != nil {
		log.Printf("produced block rejected: %v", err)
		return
	}
	log.Printf("cut block %d (%s): %d payload(s), %d rotation(s), signed by %s…", b.Header.Height, b.Hash().Short(), len(entries), len(rots), signer.ID[:12])
	n.broadcastBlock(b)
}
