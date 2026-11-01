package node

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/remote"
	"eidchain/internal/testpki"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTwoNodesGossipSyncAndRotation(t *testing.T) {
	ctx := context.Background()
	pki := testpki.New(t)
	card := pki.Leaf(t, "PERA PERIC", x509.KeyUsageContentCommitment, false)
	entry := func(text string, l testpki.Leaf) chain.PayloadEntry {
		p := `{"type":"message","text":"` + text + `"}`
		return chain.PayloadEntry{Payload: p, Signature: base64.StdEncoding.EncodeToString(testpki.CadesSign(t, l, []byte(p)))}
	}

	// Three authorities; node A holds two of the keys, node B one.
	var keys []*chain.Signer
	var auths []chain.Authority
	for i := 0; i < 3; i++ {
		k, _ := chain.GenerateKey()
		id, _ := chain.KeyID(&k.PublicKey)
		pub, _ := chain.EncodePublicKey(&k.PublicKey)
		keys = append(keys, &chain.Signer{ID: id, Key: k})
		auths = append(auths, chain.Authority{PublicKey: pub})
	}
	g, err := chain.NewGenesis("integration test", auths, []string{pki.RootPEM, pki.InterPEM}, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	mkDir := func(signers ...*chain.Signer) string {
		dir := t.TempDir()
		if _, err := chain.Init(dir, g); err != nil {
			t.Fatal(err)
		}
		for i, s := range signers {
			if err := chain.SavePrivateKey(filepath.Join(dir, "keys", string(rune('a'+i))+".key"), s.Key); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	dirA, dirB, dirC := mkDir(keys[0], keys[1]), mkDir(keys[2]), mkDir()

	var na, nb *Node
	sa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { na.Handler().ServeHTTP(w, r) }))
	sb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nb.Handler().ServeHTTP(w, r) }))
	defer sa.Close()
	defer sb.Close()
	opts := func(dir string, peer string) Options {
		return Options{Data: dir, Listen: "unused", Peers: []string{peer}, BlockInterval: time.Minute,
			SyncInterval: time.Hour, OCSP: "skip", Web: true}
	}
	if na, err = New(opts(dirA, sb.URL)); err != nil {
		t.Fatal(err)
	}
	if nb, err = New(opts(dirB, sa.URL)); err != nil {
		t.Fatal(err)
	}
	ca, cb := remote.New(sa.URL), remote.New(sb.URL)

	// 1. A payload submitted to A reaches B's pool by gossip.
	p1 := entry("hello from A", card)
	res, err := ca.PostPayload(ctx, p1)
	if err != nil || res.Status != "accepted" {
		t.Fatalf("submit: %+v %v", res, err)
	}
	waitFor(t, "payload gossip to B", func() bool { return nb.pool.Has(p1.ID()) })
	if res, _ = ca.PostPayload(ctx, p1); res.Status != "known" {
		t.Fatalf("resubmission: %+v", res)
	}

	// Bad submissions are refused with a client error.
	other := testpki.New(t).Leaf(t, "EVE", x509.KeyUsageContentCommitment, false)
	if _, err := ca.PostPayload(ctx, entry("forged", other)); err == nil {
		t.Fatal("untrusted certificate accepted")
	} else if ae, ok := err.(*remote.APIError); !ok || ae.Status != 422 {
		t.Fatalf("want HTTP 422, got %v", err)
	}
	tooBig := entry(string(make([]byte, 0))+repeat("x", 11*1024), card)
	if _, err := ca.PostPayload(ctx, tooBig); err == nil {
		t.Fatal("oversized payload accepted")
	}

	// 2. A cuts a block; B receives it by gossip and clears its pool.
	na.produce()
	waitFor(t, "block 1 on B", func() bool { _, h := nb.store.Head(); return h == 1 })
	waitFor(t, "B pool cleared", func() bool { return nb.pool.Len() == 0 })
	if na.pool.Len() != 0 {
		t.Fatal("A kept an included payload in its pool")
	}

	// 3. B cuts the next block with its only key (A's last signer cannot sign twice in a row).
	p2 := entry("hello from B", card)
	if _, err := cb.PostPayload(ctx, p2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "payload gossip to A", func() bool { return na.pool.Has(p2.ID()) })
	nb.produce()
	waitFor(t, "block 2 on A", func() bool { _, h := na.store.Head(); return h == 2 })

	// 4. A third node with an empty chain catches up with a verified pull.
	stC, err := chain.Open(dirC, g.Hash())
	if err != nil {
		t.Fatal(err)
	}
	r, err := remote.Sync(ctx, stC, remote.New(sa.URL), nil)
	if err != nil || r.Fetched != 2 || r.Height != 2 {
		t.Fatalf("pull: %+v %v", r, err)
	}
	if h, err := stC.Verify(); err != nil || h != 2 {
		t.Fatalf("verify pulled chain: %d %v", h, err)
	}
	if r, _ = remote.Sync(ctx, stC, remote.New(sa.URL), nil); !r.UpToDate {
		t.Fatalf("second pull should be a no-op: %+v", r)
	}

	// 5. Key rotation by API: replace authority 0 with a new key, approved by authorities 1 and 2.
	nk, _ := chain.GenerateKey()
	npub, _ := chain.EncodePublicKey(&nk.PublicKey)
	nid, _ := chain.KeyID(&nk.PublicKey)
	rot := chain.Rotation{Change: chain.KeyChange{Type: "replace", Chain: g.Hash(), Seq: 0, Old: keys[0].ID, NewKey: npub}}
	sig1, _ := chain.SignKeyChange(*keys[1], rot.Change)
	rot.AddSignature(sig1)
	st, err := ca.PostRotation(ctx, rot)
	if err != nil || st.Ready || st.Approvals != 1 {
		t.Fatalf("first approval: %+v %v", st, err)
	}
	sig2, _ := chain.SignKeyChange(*keys[2], rot.Change)
	rot.AddSignature(sig2)
	if st, err = ca.PostRotation(ctx, rot); err != nil || !st.Ready {
		t.Fatalf("second approval: %+v %v", st, err)
	}
	waitFor(t, "rotation gossip to B", func() bool { return len(nb.rots.List()) == 1 })
	// An approval from a non-authority is refused.
	bad := rot
	bad.Signatures = nil
	osig, _ := chain.SignKeyChange(chain.Signer{ID: nid, Key: nk}, bad.Change)
	bad.AddSignature(osig)
	if _, err := ca.PostRotation(ctx, bad); err == nil {
		t.Fatal("approval by a non-authority accepted")
	}
	// The last signer was B's key 2, so A cuts the rotation-only block (key 1 is eligible).
	na.produce()
	waitFor(t, "rotation block on B", func() bool { _, h := nb.store.Head(); return h == 3 })
	for _, n := range []*Node{na, nb} {
		state := n.store.HeadState()
		if state.Has(keys[0].ID) || !state.Has(nid) || state.Seq != 1 {
			t.Fatalf("authority set not rotated: %v", state.IDs)
		}
		if len(n.rots.List()) != 0 {
			t.Fatal("applied rotation left in the pool")
		}
	}
	info, err := ca.Info(ctx)
	if err != nil || info.Height != 3 || info.RotationSeq != 1 || len(info.TrustAnchors) != 2 {
		t.Fatalf("info: %+v %v", info, err)
	}
	// 6. The web app is served from the embedded files.
	resp, err := http.Get(sa.URL + "/app.js")
	if err != nil || resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("web app: %v %v", resp, err)
	}
	resp.Body.Close()
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// A rejected payload must leave enough in the log to see why: the signer
// certificate's fields and how it relates to each trust anchor.
func TestRejectedPayloadIsExplainedInTheLog(t *testing.T) {
	pki := testpki.New(t)
	k, _ := chain.GenerateKey()
	pub, _ := chain.EncodePublicKey(&k.PublicKey)
	g, err := chain.NewGenesis("log test", []chain.Authority{{PublicKey: pub}}, []string{pki.RootPEM, pki.InterPEM}, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := chain.Init(dir, g); err != nil {
		t.Fatal(err)
	}
	n, err := New(Options{Data: dir, Listen: "unused", BlockInterval: time.Minute, SyncInterval: time.Hour, OCSP: "skip"})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	stranger := testpki.New(t).Leaf(t, "STRANGER", x509.KeyUsageContentCommitment, false)
	p := `{"type":"message","text":"hi"}`
	_, err = n.SubmitPayload(context.Background(),
		chain.PayloadEntry{Payload: p, Signature: base64.StdEncoding.EncodeToString(testpki.CadesSign(t, stranger, []byte(p)))}, "203.0.113.5")
	if err == nil {
		t.Fatal("untrusted payload accepted")
	}
	out := buf.String()
	t.Log("\n" + out)
	for _, want := range []string{"REJECTED from 203.0.113.5", "signer certificate:", "subject=", "issuer=", "aki=",
		"trust anchor", "authority key id", "path verification now"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q", want)
		}
	}
	// Neither the payload text nor signature bytes belong in the log.
	if strings.Contains(out, "hi\"}") || strings.Contains(out, "MII") {
		t.Error("log leaks payload text or signature bytes")
	}
}

// newSoloNode is a one-authority node with a test PKI and a signing card.
func newSoloNode(t *testing.T) (*Node, testpki.Leaf, *testpki.PKI) {
	t.Helper()
	pki := testpki.New(t)
	k, _ := chain.GenerateKey()
	pub, _ := chain.EncodePublicKey(&k.PublicKey)
	g, err := chain.NewGenesis("solo", []chain.Authority{{PublicKey: pub}}, []string{pki.RootPEM, pki.InterPEM}, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := chain.Init(dir, g); err != nil {
		t.Fatal(err)
	}
	if err := chain.SavePrivateKey(filepath.Join(dir, "keys", "a.key"), k); err != nil {
		t.Fatal(err)
	}
	n, err := New(Options{Data: dir, Listen: "unused", BlockInterval: time.Minute, SyncInterval: time.Hour, OCSP: "skip", Web: true})
	if err != nil {
		t.Fatal(err)
	}
	return n, pki.Leaf(t, "PERA PERIC", x509.KeyUsageContentCommitment, false), pki
}

func post(h http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.77:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

// The API refuses ambiguous JSON (duplicate keys, case-variant names).
func TestAPIRejectsAmbiguousJSON(t *testing.T) {
	n, _, _ := newSoloNode(t)
	h := n.Handler()
	for name, body := range map[string]string{
		"duplicate key": `{"payload":"{}","payload":"{}","signature":""}`,
		"case variant":  `{"Payload":"{}","signature":""}`,
		"unknown field": `{"payload":"{}","signature":"","x":1}`,
	} {
		rec := post(h, "/api/v1/payloads", body)
		if rec.Code != 400 {
			t.Errorf("%s: HTTP %d, want 400 (%s)", name, rec.Code, rec.Body.String())
		}
	}
}

// Success paths must not log personal data (signer name, serial, client address);
// the error paths keep it for debugging.
func TestLogsContainNoPIIOnSuccess(t *testing.T) {
	n, card, pki := newSoloNode(t)
	h := n.Handler()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	p := `{"type":"message","text":"private words"}`
	good, _ := json.Marshal(chain.PayloadEntry{Payload: p, Signature: base64.StdEncoding.EncodeToString(testpki.CadesSign(t, card, []byte(p)))})
	if rec := post(h, "/api/v1/payloads", string(good)); rec.Code != 200 {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
	}
	n.produce()
	success := buf.String()
	t.Log("\n" + success)
	for _, pii := range []string{"PERA PERIC", card.Cert.SerialNumber.Text(16), "192.0.2.77", "private words"} {
		if strings.Contains(success, pii) {
			t.Errorf("success-path log contains %q", pii)
		}
	}
	if !strings.Contains(success, "accepted") || !strings.Contains(success, "cut block") {
		t.Error("expected log lines are missing")
	}

	// A rejection logs the details needed to debug it, including the caller and the certificate.
	buf.Reset()
	stranger := testpki.New(t).Leaf(t, "STRANGER NAME", x509.KeyUsageContentCommitment, false)
	bad, _ := json.Marshal(chain.PayloadEntry{Payload: p + " ", Signature: base64.StdEncoding.EncodeToString(testpki.CadesSign(t, stranger, []byte(p+" ")))})
	if rec := post(h, "/api/v1/payloads", string(bad)); rec.Code != 422 {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
	failure := buf.String()
	for _, want := range []string{"REJECTED from 192.0.2.77", "STRANGER NAME", "http: POST /api/v1/payloads from 192.0.2.77 -> 422"} {
		if !strings.Contains(failure, want) {
			t.Errorf("error-path log lacks %q", want)
		}
	}
	_ = pki
}

func TestExplorerAPI(t *testing.T) {
	n, card, _ := newSoloNode(t)
	h := n.Handler()
	p := `{"type":"message","text":"hello explorer"}`
	e := chain.PayloadEntry{Payload: p, Signature: base64.StdEncoding.EncodeToString(testpki.CadesSign(t, card, []byte(p)))}
	body, _ := json.Marshal(e)
	if rec := post(h, "/api/v1/payloads", string(body)); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	id := e.ID().String()

	// Pending transaction.
	var tx map[string]any
	rec := get(h, "/api/v1/explorer/tx/"+id)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &tx) != nil || tx["status"] != "pending" || tx["valid"] != true {
		t.Fatalf("pending tx: %d %s", rec.Code, rec.Body.String())
	}
	n.produce()

	// Confirmed transaction with its certificate and block position.
	rec = get(h, "/api/v1/explorer/tx/"+id)
	tx = nil
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &tx) != nil || tx["status"] != "confirmed" || tx["height"].(float64) != 1 {
		t.Fatalf("confirmed tx: %d %s", rec.Code, rec.Body.String())
	}
	cert, _ := tx["certificate"].(map[string]any)
	if cert == nil || !strings.Contains(cert["subject"].(string), "PERA PERIC") {
		t.Fatalf("certificate missing from tx view: %v", tx)
	}

	// Block by height and by hash; list; search.
	var blk map[string]any
	rec = get(h, "/api/v1/explorer/block/1")
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &blk) != nil || blk["canonical"] != true || len(blk["transactions"].([]any)) != 1 {
		t.Fatalf("block: %d %s", rec.Code, rec.Body.String())
	}
	hash := blk["hash"].(string)
	if rec = get(h, "/api/v1/explorer/block/"+hash); rec.Code != 200 {
		t.Fatalf("block by hash: %d", rec.Code)
	}
	var list struct {
		Blocks []map[string]any `json:"blocks"`
		Height float64          `json:"height"`
	}
	rec = get(h, "/api/v1/explorer/blocks?limit=5")
	if json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Blocks) != 1 || list.Height != 1 {
		t.Fatalf("blocks: %s", rec.Body.String())
	}
	for q, kind := range map[string]string{"1": "block", hash: "block", id: "tx", n.store.P.GenesisHash.String(): "node"} {
		var sr map[string]string
		rec = get(h, "/api/v1/explorer/search?q="+q)
		if json.Unmarshal(rec.Body.Bytes(), &sr) != nil || sr["kind"] != kind {
			t.Errorf("search %.12s: want %s, got %s", q, kind, rec.Body.String())
		}
	}
	keyID := n.store.HeadState().IDs[0]
	var sr map[string]string
	if rec = get(h, "/api/v1/explorer/search?q="+keyID); json.Unmarshal(rec.Body.Bytes(), &sr) != nil || sr["kind"] != "authority" {
		t.Errorf("authority search: %s", rec.Body.String())
	}
	if rec = get(h, "/api/v1/explorer/search?q=nonsense"); rec.Code != 404 {
		t.Errorf("unknown query: %d", rec.Code)
	}
	if rec = get(h, "/api/v1/explorer/block/99"); rec.Code != 404 {
		t.Errorf("missing block: %d", rec.Code)
	}
	rec = get(h, "/api/v1/explorer/authorities")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), keyID) {
		t.Errorf("authorities: %d %s", rec.Code, rec.Body.String())
	}
	// The UI iterates these lists: they must be [] and never null.
	var auth map[string]json.RawMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &auth)
	for _, k := range []string{"history", "pending", "canSign", "current"} {
		if string(auth[k]) == "null" || len(auth[k]) == 0 {
			t.Errorf("authorities.%s is %q, want a JSON array", k, auth[k])
		}
	}
}

// A pull must find where its chain and the remote's diverged, fetch from there,
// and let the fork rule decide: the longer remote branch wins and the local
// branch's message goes back to being unconfirmed.
func TestPullResolvesAForkAndNeverGoesBackwards(t *testing.T) {
	ctx := context.Background()
	pki := testpki.New(t)
	card := pki.Leaf(t, "PERA PERIC", x509.KeyUsageContentCommitment, false)
	var keys []chain.Signer
	var auths []chain.Authority
	for i := 0; i < 3; i++ {
		k, _ := chain.GenerateKey()
		id, _ := chain.KeyID(&k.PublicKey)
		pub, _ := chain.EncodePublicKey(&k.PublicKey)
		keys = append(keys, chain.Signer{ID: id, Key: k})
		auths = append(auths, chain.Authority{PublicKey: pub})
	}
	g, err := chain.NewGenesis("fork test", auths, []string{pki.RootPEM, pki.InterPEM}, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	mkStore := func() *chain.Store {
		st, err := chain.Init(t.TempDir(), g)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	entry := func(text string) chain.PayloadEntry {
		p := `{"type":"message","text":"` + text + `"}`
		return chain.PayloadEntry{Payload: p, Signature: base64.StdEncoding.EncodeToString(testpki.CadesSign(t, card, []byte(p)))}
	}
	extend := func(st *chain.Store, parent *chain.Block, signer chain.Signer, text string) *chain.Block {
		prev, height := st.Head()
		if parent != nil {
			prev, height = parent.Hash(), parent.Header.Height
		}
		b := &chain.Block{Header: chain.Header{Height: height + 1, Prev: prev, Time: time.Now().Unix()}, Payloads: []chain.PayloadEntry{entry(text)}}
		if err := chain.SignBlock(signer, b); err != nil {
			t.Fatal(err)
		}
		if _, err := st.AddBlock(b); err != nil {
			t.Fatalf("add %s: %v", text, err)
		}
		return b
	}

	// The remote node (Y) and the local store (X) share block 1, then diverge.
	dirY := t.TempDir()
	if _, err := chain.Init(dirY, g); err != nil {
		t.Fatal(err)
	}
	ny, err := New(Options{Data: dirY, Listen: "unused", BlockInterval: time.Minute, SyncInterval: time.Hour, OCSP: "skip"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(ny.Handler())
	defer srv.Close()
	x := mkStore()
	common := extend(ny.Store(), nil, keys[0], "common")
	if _, err := x.AddBlock(common); err != nil {
		t.Fatal(err)
	}
	x2 := extend(x, common, keys[1], "only on X") // X's branch: height 2
	y2 := extend(ny.Store(), common, keys[2], "on Y, block 2")
	y3 := extend(ny.Store(), y2, keys[0], "on Y, block 3") // Y's branch is longer: height 3
	if _, h := x.Head(); h != 2 {
		t.Fatalf("X at height %d, want 2", h)
	}
	if !x.OnChain(x2.Payloads[0].ID()) {
		t.Fatal("X lost its own message before the pull")
	}

	res, err := remote.Sync(ctx, x, remote.New(srv.URL), nil)
	if err != nil {
		t.Fatalf("pull across a fork: %v", err)
	}
	if head, h := x.Head(); head != y3.Hash() || h != 3 || res.Height != 3 {
		t.Fatalf("after the pull X is at height %d (%s), want Y's block 3", h, head.Short())
	}
	if res.Fetched != 2 {
		t.Errorf("fetched %d blocks, want 2 (it must start at the fork point, not at genesis)", res.Fetched)
	}
	if x.OnChain(x2.Payloads[0].ID()) {
		t.Error("X's orphaned message is still counted as on the chain")
	}
	if !x.OnChain(y2.Payloads[0].ID()) || !x.OnChain(y3.Payloads[0].ID()) {
		t.Error("Y's messages are not on X's chain after the pull")
	}
	if h, err := x.Verify(); err != nil || h != 3 {
		t.Fatalf("verify after the fork: %d %v", h, err)
	}

	// Pulling again changes nothing, and pulling from a node that is behind never moves X back.
	if res, err = remote.Sync(ctx, x, remote.New(srv.URL), nil); err != nil || !res.UpToDate {
		t.Fatalf("second pull: %+v %v", res, err)
	}
	behind := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A stale node: the same chain, truncated to block 1.
		nb, _ := New(Options{Data: func() string {
			d := t.TempDir()
			chain.Init(d, g)
			st, _ := chain.Open(d, g.Hash())
			st.AddBlock(common)
			return d
		}(), Listen: "unused", BlockInterval: time.Minute, SyncInterval: time.Hour, OCSP: "skip"})
		nb.Handler().ServeHTTP(w, r)
	}))
	defer behind.Close()
	if res, err = remote.Sync(ctx, x, remote.New(behind.URL), nil); err != nil || res.Height != 3 {
		t.Fatalf("pull from a node that is behind: %+v %v", res, err)
	}
	if head, h := x.Head(); head != y3.Hash() || h != 3 {
		t.Fatal("pulling from a node that is behind moved the local head")
	}
}

func TestExplorerHidesThePersonalIDNumber(t *testing.T) {
	l := testpki.New(t).LeafSubject(t, pkix.Name{CommonName: "PERIC PERO", SerialNumber: "PNOHR-12345678903"})
	if got := chain.SubjectDetail(l.Cert); strings.Contains(got, "12345678903") || !strings.Contains(got, "PERIC PERO") {
		t.Fatalf("subject detail: %q", got)
	}
	noCN := testpki.New(t).LeafSubject(t, pkix.Name{SerialNumber: "PNOHR-12345678903"})
	if got := chain.SubjectName(noCN.Cert); strings.Contains(got, "12345678903") {
		t.Fatalf("subject name: %q", got)
	}
}
