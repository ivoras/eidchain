package node

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
