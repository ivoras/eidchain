package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"eidchain/internal/remote"
)

// Peer exchange: a small step on top of the static peer list.
//
//   - Every sync round, a node asks each peer for the peers it knows (GET /peers)
//     and, if it has a public address (--advertise), announces itself (POST /peers),
//     which turns one-way links into two-way ones.
//   - An address is only used after the node has fetched its /info and seen the
//     same genesis hash, so a bogus or foreign address never becomes a peer.
//   - Learned peers cannot point at loopback, private or link-local addresses
//     (otherwise an announcement could make a node probe its own network). The
//     check is made on the connection itself, so DNS tricks do not get around it.
//   - Announcements are rate-limited, the number of learned peers is capped, and
//     a learned peer that keeps failing is dropped.
//
// Peers named by the operator (--peer, config.json) are always trusted and may be
// private; they are not shared with others unless they are public.
const (
	maxLearnedPeers = 32
	maxPeersPerHost = 2 // learned peers on one host, so one server cannot fill the book
	maxSharedPeers  = 20
	maxPeerFailures = 6                // consecutive failed syncs before a learned peer is dropped
	reannounceEvery = 30 * time.Minute // how often to repeat our announcement to a peer
	announcePerMin  = 20               // announcements accepted per minute, in total
	rejectedMemory  = 10 * time.Minute // how long a failed candidate is not retried
)

type learnedPeer struct {
	URL    string `json:"url"`
	LastOK int64  `json:"lastOk,omitempty"`
	fails  int
}

// peerBook holds the peers learned through exchange, persisted in <data>/peers.json.
type peerBook struct {
	mu        sync.Mutex
	path      string
	learned   map[string]*learnedPeer
	announced map[string]time.Time // when we last announced ourselves to a peer
	rejected  map[string]time.Time // candidates that failed verification
	recent    []time.Time          // accepted announcements, for the rate limit
}

func newPeerBook(dir string, load bool) *peerBook {
	b := &peerBook{
		path: filepath.Join(dir, "peers.json"), learned: map[string]*learnedPeer{},
		announced: map[string]time.Time{}, rejected: map[string]time.Time{},
	}
	if !load {
		return b
	}
	if raw, err := os.ReadFile(b.path); err == nil {
		var list []*learnedPeer
		if json.Unmarshal(raw, &list) == nil {
			for _, p := range list {
				if u, err := normalizePeerURL(p.URL); err == nil && len(b.learned) < maxLearnedPeers {
					p.URL = u
					b.learned[u] = p
				}
			}
		}
	}
	return b
}

func (b *peerBook) saveLocked() {
	list := make([]*learnedPeer, 0, len(b.learned))
	for _, p := range b.learned {
		list = append(list, p)
	}
	raw, _ := json.MarshalIndent(list, "", "  ")
	tmp := b.path + ".tmp"
	if os.WriteFile(tmp, raw, 0o644) == nil {
		os.Rename(tmp, b.path)
	}
}

func (b *peerBook) urls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.learned))
	for u := range b.learned {
		out = append(out, u)
	}
	return out
}

// onHostLocked counts learned peers that share a host name with u, whatever their
// port or path.
func (b *peerBook) onHostLocked(u string) int {
	host := func(s string) string {
		p, err := url.Parse(s)
		if err != nil {
			return s
		}
		return p.Hostname()
	}
	count, want := 0, host(u)
	for known := range b.learned {
		if host(known) == want {
			count++
		}
	}
	return count
}

// ---- address checks ----

// normalizePeerURL accepts only plain http(s) base URLs and gives them one spelling.
func normalizePeerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 200 {
		return "", errors.New("peer address is empty or too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("peer address is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("peer address must be http or https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", errors.New("peer address has no host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("peer address must be a plain base URL (no credentials, query or fragment)")
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// publicIP reports whether ip is an address that is routable on the internet.
func publicIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
		if v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10, carrier-grade NAT
			return false
		}
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// privateLiteral reports whether the URL names a non-public address directly
// (an IP literal or a "localhost" name). Other host names are checked when
// connecting, where the resolved address is known.
func privateLiteral(normalized string) bool {
	u, err := url.Parse(normalized)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return !publicIP(ip)
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal")
}

// safeHTTPClient is used for learned peers. Unless allowPrivate is set it refuses
// to connect to any non-public address, checked on the actual connection.
func safeHTTPClient(allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if !allowPrivate {
		d.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || !publicIP(ip) {
				return fmt.Errorf("refusing to connect to non-public address %s", host)
			}
			return nil
		}
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: d.DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
			MaxIdleConns: 16, IdleConnTimeout: 30 * time.Second, // no Proxy: never route through an environment proxy
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ---- node methods ----

func (n *Node) exchangeEnabled() bool { return !n.opt.NoPeerExchange }

// allPeers is the operator's peers followed by the learned ones.
func (n *Node) allPeers() []*remote.Client {
	out := append([]*remote.Client(nil), n.peers...)
	if !n.exchangeEnabled() {
		return out
	}
	for _, u := range n.book.urls() {
		c := remote.New(u)
		c.HTTP = n.safeHTTP
		out = append(out, c)
	}
	return out
}

// recordPeerResult tracks how a learned peer is doing and drops it when it keeps failing.
func (n *Node) recordPeerResult(base string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	n.book.mu.Lock()
	defer n.book.mu.Unlock()
	p := n.book.learned[base]
	if p == nil {
		return
	}
	if err == nil {
		p.fails, p.LastOK = 0, time.Now().Unix()
	} else if p.fails++; p.fails >= maxPeerFailures {
		delete(n.book.learned, base)
		log.Printf("peer %s dropped after %d failed syncs", base, maxPeerFailures)
	}
	n.book.saveLocked()
}

// verifyPeer fetches the candidate's /info and checks it serves our chain.
func (n *Node) verifyPeer(ctx context.Context, base string) error {
	c := remote.New(base)
	c.HTTP = n.safeHTTP
	info, err := c.Info(ctx)
	if err != nil {
		return fmt.Errorf("cannot reach it: %w", err)
	}
	if info.GenesisHash != n.store.P.GenesisHash {
		return errors.New("it serves a different chain")
	}
	return nil
}

var (
	errKnownPeer = errors.New("already a peer")
	errPeerLimit = errors.New("the learned-peer limit is reached")
)

// addLearned validates, verifies and records a candidate. Errors say why it was refused.
func (n *Node) addLearned(ctx context.Context, raw string) (string, error) {
	norm, err := normalizePeerURL(raw)
	if err != nil {
		return "", err
	}
	if norm == n.selfURL {
		return norm, errors.New("that is this node")
	}
	if n.staticSet[norm] {
		return norm, errKnownPeer
	}
	if !n.opt.AllowPrivatePeers && privateLiteral(norm) {
		return norm, errors.New("peer addresses must be public")
	}
	n.book.mu.Lock()
	switch {
	case n.book.learned[norm] != nil:
		n.book.mu.Unlock()
		return norm, errKnownPeer
	case len(n.book.learned) >= maxLearnedPeers:
		n.book.mu.Unlock()
		return norm, errPeerLimit
	case !n.opt.AllowPrivatePeers && n.book.onHostLocked(norm) >= maxPeersPerHost:
		n.book.mu.Unlock()
		return norm, errors.New("too many learned peers on that host")
	case time.Since(n.book.rejected[norm]) < rejectedMemory:
		n.book.mu.Unlock()
		return norm, errors.New("recently failed verification")
	}
	n.book.mu.Unlock()

	vctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := n.verifyPeer(vctx, norm); err != nil {
		n.book.mu.Lock()
		n.book.rejected[norm] = time.Now()
		n.book.mu.Unlock()
		return norm, err
	}
	n.book.mu.Lock()
	n.book.learned[norm] = &learnedPeer{URL: norm, LastOK: time.Now().Unix()}
	n.book.saveLocked()
	n.book.mu.Unlock()
	log.Printf("learned peer %s", norm)
	return norm, nil
}

// exchange runs after a successful sync with p: announce ourselves, then learn p's peers.
func (n *Node) exchange(ctx context.Context, p *remote.Client) {
	if !n.exchangeEnabled() {
		return
	}
	if n.selfURL != "" {
		n.book.mu.Lock()
		due := time.Since(n.book.announced[p.Base]) > reannounceEvery
		n.book.mu.Unlock()
		if due {
			actx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := p.Announce(actx, n.selfURL)
			cancel()
			if err != nil {
				log.Printf("peer %s: announcing %s failed: %v", p.Base, n.selfURL, err)
			}
			// Remembered either way, so a refusal is not retried every round.
			n.book.mu.Lock()
			n.book.announced[p.Base] = time.Now()
			n.book.mu.Unlock()
		}
	}
	lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	list, err := p.Peers(lctx)
	cancel()
	if err != nil {
		return // an older node without peer exchange, or a transient failure
	}
	if len(list) > maxSharedPeers {
		list = list[:maxSharedPeers]
	}
	for _, u := range list {
		if _, err := n.addLearned(ctx, u); err != nil && err != errKnownPeer && err != errPeerLimit {
			log.Printf("peer candidate %q from %s ignored: %v", u, p.Base, err)
		}
	}
}

// publicStaticPeers lists the operator's peers that are safe to tell others
// about, in a normal form with no credentials. A host name only qualifies if every
// address it resolves to is public, so names on an internal DNS stay private; if
// the lookup fails, the peer is left out. The answer is worked out once.
func (n *Node) publicStaticPeers() []string {
	n.staticOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, p := range n.peers {
			norm, err := normalizePeerURL(p.Base)
			if err != nil {
				continue // for example credentials in the URL: never published
			}
			if n.opt.AllowPrivatePeers || n.resolvesPublic(ctx, norm) {
				n.staticShared = append(n.staticShared, norm)
			}
		}
	})
	return n.staticShared
}

func (n *Node) resolvesPublic(ctx context.Context, normalized string) bool {
	if privateLiteral(normalized) {
		return false
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return false
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		return publicIP(ip)
	}
	addrs, err := n.lookupIP(ctx, u.Hostname())
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !publicIP(a.IP) {
			return false
		}
	}
	return true
}

// shareablePeers are the peers this node tells others about: itself, the
// operator's public peers, and learned peers that are answering.
func (n *Node) shareablePeers() []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !seen[u] && len(out) < maxSharedPeers {
			seen[u] = true
			out = append(out, u)
		}
	}
	add(n.selfURL)
	for _, u := range n.publicStaticPeers() {
		add(u)
	}
	n.book.mu.Lock()
	defer n.book.mu.Unlock()
	for u, p := range n.book.learned {
		if p.LastOK > 0 && p.fails == 0 {
			add(u)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// allowAnnounce is a global rate limit on accepted announcements.
func (b *peerBook) allowAnnounce() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	cut := time.Now().Add(-time.Minute)
	kept := b.recent[:0]
	for _, t := range b.recent {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	b.recent = kept
	if len(b.recent) >= announcePerMin {
		return false
	}
	b.recent = append(b.recent, time.Now())
	return true
}

// ---- HTTP handlers ----

func (n *Node) handlePeers(w http.ResponseWriter, r *http.Request) {
	if !n.exchangeEnabled() {
		writeErr(w, http.StatusNotFound, errors.New("peer exchange is disabled on this node"))
		return
	}
	writeJSON(w, 200, map[string]any{"peers": n.shareablePeers(), "self": n.selfURL})
}

func (n *Node) handleAnnounce(w http.ResponseWriter, r *http.Request) {
	if !n.exchangeEnabled() {
		writeErr(w, http.StatusNotFound, errors.New("peer exchange is disabled on this node"))
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if !decode(w, r, 4<<10, &req) {
		return
	}
	if !n.book.allowAnnounce() {
		writeErr(w, http.StatusTooManyRequests, errors.New("too many announcements; try again in a minute"))
		return
	}
	norm, err := n.addLearned(r.Context(), req.URL)
	switch {
	case err == errKnownPeer:
		writeJSON(w, 200, map[string]string{"status": "known", "url": norm})
	case err != nil:
		writeErr(w, http.StatusUnprocessableEntity, err)
	default:
		writeJSON(w, 200, map[string]string{"status": "added", "url": norm})
	}
}
