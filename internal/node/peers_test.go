package node

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/testpki"
)

// peerWorld is a chain (one authority, never used for signing here) and a way to
// start nodes on it.
type peerWorld struct {
	t    *testing.T
	g    *chain.Genesis
	pki  *testpki.PKI
	card testpki.Leaf
}

func newPeerWorld(t *testing.T, message string) *peerWorld {
	pki := testpki.New(t)
	k, _ := chain.GenerateKey()
	pub, _ := chain.EncodePublicKey(&k.PublicKey)
	g, err := chain.NewGenesis(message, []chain.Authority{{PublicKey: pub}}, []string{pki.RootPEM, pki.InterPEM}, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return &peerWorld{t: t, g: g, pki: pki, card: pki.Leaf(t, "PERA PERIC", x509.KeyUsageContentCommitment, false)}
}

// start creates n nodes whose HTTP servers are up before the nodes are configured,
// so each can name the others' addresses. peers[i] lists the indexes node i is told about.
func (w *peerWorld) start(n int, peers map[int][]int, mutate func(i int, o *Options)) ([]*Node, []*httptest.Server) {
	nodes := make([]*Node, n)
	srvs := make([]*httptest.Server, n)
	for i := range srvs {
		i := i
		srvs[i] = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { nodes[i].Handler().ServeHTTP(rw, r) }))
		w.t.Cleanup(srvs[i].Close)
	}
	for i := range nodes {
		dir := w.t.TempDir()
		if _, err := chain.Init(dir, w.g); err != nil {
			w.t.Fatal(err)
		}
		o := Options{Data: dir, Listen: "unused", BlockInterval: time.Minute, SyncInterval: time.Hour, OCSP: "skip",
			Advertise: srvs[i].URL, AllowPrivatePeers: true}
		for _, j := range peers[i] {
			o.Peers = append(o.Peers, srvs[j].URL)
		}
		if mutate != nil {
			mutate(i, &o)
		}
		var err error
		if nodes[i], err = New(o); err != nil {
			w.t.Fatal(err)
		}
	}
	return nodes, srvs
}

func peerBases(n *Node) map[string]bool {
	m := map[string]bool{}
	for _, p := range n.allPeers() {
		m[p.Base] = true
	}
	return m
}

func jsonBody(t *testing.T, v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// A -> B -> C are the only links an operator configured. After a few sync rounds
// every node must know the other two, and gossip must reach all of them.
func TestPeerExchangeConnectsEveryone(t *testing.T) {
	ctx := context.Background()
	w := newPeerWorld(t, "exchange")
	nodes, srvs := w.start(3, map[int][]int{0: {1}, 1: {2}}, nil)

	if len(peerBases(nodes[2])) != 0 {
		t.Fatal("the last node should start with no peers at all")
	}
	for round := 0; round < 4; round++ {
		for _, n := range nodes {
			n.syncAll(ctx)
		}
	}
	for i, n := range nodes {
		got := peerBases(n)
		for j, s := range srvs {
			if j != i && !got[s.URL] {
				t.Errorf("node %d never learned node %d (knows %v)", i, j, got)
			}
		}
		if got[srvs[i].URL] {
			t.Errorf("node %d has itself as a peer", i)
		}
	}

	// Gossip now flows over links nobody configured: C (index 2) was only ever
	// reachable from B, yet a message submitted to A arrives at both.
	p := `{"type":"message","text":"exchange"}`
	e := chain.PayloadEntry{Payload: p, Signature: base64.StdEncoding.EncodeToString(testpki.CadesSign(t, w.card, []byte(p)))}
	if _, err := nodes[0].SubmitPayload(ctx, e, "test"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 3; i++ {
		i := i
		waitFor(t, fmt.Sprintf("payload gossip to node %d", i), func() bool { return nodes[i].pool.Has(e.ID()) })
	}
}

// Learned peers survive a restart; those that stop answering are dropped.
func TestLearnedPeersPersistAndFailingOnesAreDropped(t *testing.T) {
	ctx := context.Background()
	w := newPeerWorld(t, "persist")
	nodes, srvs := w.start(2, map[int][]int{0: {1}}, nil)
	nodes[0].syncAll(ctx)
	nodes[1].syncAll(ctx) // node 1 learns node 0 from the announcement
	if !peerBases(nodes[1])[srvs[0].URL] {
		t.Fatalf("node 1 should have learned node 0: %v", peerBases(nodes[1]))
	}
	// Restart node 1 on the same directory: the learned peer comes back.
	re, err := New(Options{Data: nodes[1].opt.Data, Listen: "unused", BlockInterval: time.Minute, SyncInterval: time.Hour,
		OCSP: "skip", AllowPrivatePeers: true})
	if err != nil {
		t.Fatal(err)
	}
	if !peerBases(re)[srvs[0].URL] {
		t.Fatal("learned peer was not persisted")
	}

	// A peer whose server has gone away is dropped after repeated failures.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + l.Addr().String()
	l.Close()
	re.book.mu.Lock()
	re.book.learned[dead] = &learnedPeer{URL: dead, LastOK: 1}
	re.book.mu.Unlock()
	for i := 0; i < maxPeerFailures; i++ {
		if !peerBases(re)[dead] {
			t.Fatalf("dropped too early, after %d failures", i)
		}
		re.syncAll(ctx)
	}
	if peerBases(re)[dead] {
		t.Fatal("a peer that never answers is still listed")
	}
	if !peerBases(re)[srvs[0].URL] {
		t.Fatal("the healthy learned peer was dropped too")
	}
}

// Nothing a stranger announces may make a node connect to a non-public address,
// talk to a different chain, or accept junk.
func TestAnnouncementsAreChecked(t *testing.T) {
	ctx := context.Background()
	w := newPeerWorld(t, "announce")
	other := newPeerWorld(t, "a different chain") // different genesis
	strict, _ := w.start(1, nil, func(i int, o *Options) { o.AllowPrivatePeers = false; o.Advertise = "https://node.example/chain" })
	lenient, _ := w.start(1, nil, nil)
	friend, _ := w.start(1, nil, nil)
	stranger, strangerSrv := other.start(1, nil, nil)
	_ = stranger
	hs, hl := strict[0].Handler(), lenient[0].Handler()

	announce := func(h http.Handler, url string) *httptest.ResponseRecorder {
		return post(h, "/api/v1/peers", jsonBody(t, map[string]string{"url": url}))
	}
	// Syntax and policy refusals on a node that only accepts public peers.
	for _, c := range []struct{ url, want string }{
		{"ftp://example.org/x", "http or https"},
		{"http://user:pw@example.org", "credentials"},
		{"http://example.org/?q=1", "credentials, query"},
		{"http://127.0.0.1:8080", "must be public"},
		{"http://localhost:8080", "must be public"},
		{"http://[::1]:8080", "must be public"},
		{"http://10.1.2.3", "must be public"},
		{"http://192.168.0.7", "must be public"},
		{"http://169.254.169.254/latest", "must be public"},
		{"http://100.64.0.1", "must be public"},
		{"https://node.example/chain/", "this node"},
		{"", "empty"},
	} {
		rec := announce(hs, c.url)
		if rec.Code != 422 || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("announce %q: HTTP %d %s, want 422 containing %q", c.url, rec.Code, rec.Body.String(), c.want)
		}
	}
	if len(strict[0].book.urls()) != 0 {
		t.Error("a refused announcement was recorded")
	}
	// Strict JSON applies to announcements as well.
	for _, body := range []string{`{"url":"https://a.example","url":"https://b.example"}`, `{"URL":"https://a.example"}`, `{"url":"https://a.example","x":1}`} {
		if rec := post(hs, "/api/v1/peers", body); rec.Code != 400 {
			t.Errorf("body %s: HTTP %d, want 400", body, rec.Code)
		}
	}
	// Even if the literal check were bypassed, the connection itself refuses non-public addresses.
	if err := strict[0].verifyPeer(ctx, strangerSrv[0].URL); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Errorf("dialling a loopback server from a strict node: %v", err)
	}

	// A node on a different chain is refused; one on this chain is accepted, once.
	if rec := announce(hl, strangerSrv[0].URL); rec.Code != 422 || !strings.Contains(rec.Body.String(), "different chain") {
		t.Errorf("foreign chain: HTTP %d %s", rec.Code, rec.Body.String())
	}
	friendSrv := friend[0].opt.Advertise
	if rec := announce(hl, friendSrv); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"added"`) {
		t.Errorf("friend: HTTP %d %s", rec.Code, rec.Body.String())
	}
	if rec := announce(hl, friendSrv+"/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"known"`) {
		t.Errorf("friend again (different spelling): HTTP %d %s", rec.Code, rec.Body.String())
	}
	// An address nobody answers on is refused and then not retried straight away.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + l.Addr().String()
	l.Close()
	if rec := announce(hl, dead); rec.Code != 422 {
		t.Errorf("dead address: HTTP %d", rec.Code)
	}
	if _, err := lenient[0].addLearned(ctx, dead); err == nil || !strings.Contains(err.Error(), "recently failed") {
		t.Errorf("dead address retried at once: %v", err)
	}
}

func TestAnnouncementRateLimit(t *testing.T) {
	w := newPeerWorld(t, "rate")
	nodes, _ := w.start(1, nil, nil)
	h := nodes[0].Handler()
	var limited int
	for i := 0; i < announcePerMin+5; i++ {
		rec := post(h, "/api/v1/peers", jsonBody(t, map[string]string{"url": fmt.Sprintf("http://127.0.0.1:%d", 20000+i)}))
		if rec.Code == 429 {
			limited++
		}
	}
	if limited != 5 {
		t.Errorf("%d announcements were rate limited, want 5", limited)
	}
}

// What a node tells others: itself, its public peers and healthy learned ones, never private addresses.
func TestShareablePeers(t *testing.T) {
	w := newPeerWorld(t, "share")
	mk := func(allowPrivate bool) *Node {
		dir := t.TempDir()
		if _, err := chain.Init(dir, w.g); err != nil {
			t.Fatal(err)
		}
		n, err := New(Options{Data: dir, Listen: "unused", BlockInterval: time.Minute, SyncInterval: time.Hour, OCSP: "skip",
			Advertise: "https://node.example/chain/", Peers: []string{"http://127.0.0.1:9", "https://other.example/x/", "http://192.168.1.5:80",
				"https://user:secret@other.example", "http://chain-b.corp:8080", "http://unresolvable.example"},
			AllowPrivatePeers: allowPrivate})
		if err != nil {
			t.Fatal(err)
		}
		n.lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
			switch host {
			case "other.example":
				return []net.IPAddr{{IP: net.ParseIP("198.51.100.7")}}, nil
			case "chain-b.corp":
				return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
			}
			return nil, errors.New("no such host")
		}
		n.book.learned["https://learned.example"] = &learnedPeer{URL: "https://learned.example", LastOK: 1}
		n.book.learned["https://silent.example"] = &learnedPeer{URL: "https://silent.example"}                        // never answered
		n.book.learned["https://failing.example"] = &learnedPeer{URL: "https://failing.example", LastOK: 1, fails: 2} // failing now
		return n
	}
	got := mk(false).shareablePeers()
	want := []string{"https://node.example/chain", "https://other.example/x", "https://learned.example"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("public node shares %v, want %v", got, want)
	}
	if all := mk(true).shareablePeers(); len(all) != 7 || strings.Contains(strings.Join(all, " "), "secret") {
		t.Errorf("a closed network shares private peers too, got %v", all)
	}
}

func TestPeerExchangeCanBeDisabled(t *testing.T) {
	w := newPeerWorld(t, "off")
	nodes, srvs := w.start(2, map[int][]int{0: {1}}, func(i int, o *Options) { o.NoPeerExchange = true })
	nodes[0].syncAll(context.Background())
	nodes[1].syncAll(context.Background())
	if len(peerBases(nodes[1])) != 0 {
		t.Error("a node with exchange off learned a peer")
	}
	if rec := get(nodes[0].Handler(), "/api/v1/peers"); rec.Code != 404 {
		t.Errorf("GET /peers: HTTP %d, want 404", rec.Code)
	}
	if rec := post(nodes[0].Handler(), "/api/v1/peers", jsonBody(t, map[string]string{"url": srvs[1].URL})); rec.Code != 404 {
		t.Errorf("POST /peers: HTTP %d, want 404", rec.Code)
	}
	if got := peerBases(nodes[0]); len(got) != 1 || !got[srvs[1].URL] {
		t.Errorf("configured peers changed: %v", got)
	}
}
