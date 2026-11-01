package node

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"eidchain/internal/chain"
)

// ---- JSON views for the explorer UI ----

type blockSummary struct {
	Hash      chain.Hash `json:"hash"`
	Height    uint64     `json:"height"`
	Time      int64      `json:"time"`
	Signer    string     `json:"signer"`
	Payloads  int        `json:"payloads"`
	Rotations int        `json:"rotations"`
	Size      int        `json:"size"`
	Canonical bool       `json:"canonical"`
}

type txSummary struct {
	ID      chain.Hash `json:"id"`
	Index   int        `json:"index"`
	Preview string     `json:"preview"`
	Bytes   int        `json:"bytes"`
	Subject string     `json:"subject"`
	OCSP    bool       `json:"ocsp"`
}

type blockView struct {
	blockSummary
	Header        chain.Header     `json:"header"`
	Signature     string           `json:"signature"`
	Prev          *chain.Hash      `json:"prev,omitempty"` // nil for height 1's parent being the genesis
	PrevIsGenesis bool             `json:"prevIsGenesis"`
	Next          *chain.Hash      `json:"next,omitempty"`
	Confirmations uint64           `json:"confirmations"`
	Transactions  []txSummary      `json:"transactions"`
	Rotations_    []chain.Rotation `json:"rotationList"`
}

type certView struct {
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	Serial     string   `json:"serial"`
	NotBefore  int64    `json:"notBefore"`
	NotAfter   int64    `json:"notAfter"`
	SHA256     string   `json:"sha256"`
	KeyUsage   []string `json:"keyUsage"`
	SigAlg     string   `json:"signatureAlgorithm"`
	OCSPServer []string `json:"ocspServer"`
}

type txView struct {
	ID        chain.Hash      `json:"id"`
	Payload   string          `json:"payload"`
	Parsed    json.RawMessage `json:"parsed,omitempty"`
	Status    string          `json:"status"` // confirmed or pending
	Block     *chain.Hash     `json:"block,omitempty"`
	Height    uint64          `json:"height,omitempty"`
	Index     int             `json:"index"`
	Time      int64           `json:"time,omitempty"`
	Valid     bool            `json:"valid"`
	Error     string          `json:"error,omitempty"`
	Cert      *certView       `json:"certificate,omitempty"`
	Hash      string          `json:"hashFunction,omitempty"`
	Claimed   int64           `json:"claimedSigningTime,omitempty"`
	SigBytes  int             `json:"signatureBytes"`
	OCSP      *chain.OCSPInfo `json:"ocsp,omitempty"`
	OCSPError string          `json:"ocspError,omitempty"`
}

func summarize(b *chain.Block, canonical bool) blockSummary {
	raw, _ := json.Marshal(b)
	return blockSummary{Hash: b.Hash(), Height: b.Header.Height, Time: b.Header.Time, Signer: b.Header.Signer,
		Payloads: len(b.Payloads), Rotations: len(b.Rotations), Size: len(raw), Canonical: canonical}
}

func preview(payload string) string {
	// A map, not a struct: encoding/json matches struct fields case-insensitively,
	// and this must pick the same field as the browser's JSON.parse(...).text.
	var m map[string]json.RawMessage
	text := payload
	if json.Unmarshal([]byte(payload), &m) == nil {
		var t string
		if json.Unmarshal(m["text"], &t) == nil && t != "" {
			text = t
		}
	}
	if r := []rune(text); len(r) > 140 {
		text = string(r[:140]) + "…"
	}
	return text
}

func certToView(c *x509.Certificate) *certView {
	fp := sha256.Sum256(c.Raw)
	return &certView{Subject: chain.SubjectDetail(c), Issuer: chain.CertName2(c.Issuer.CommonName, c.Issuer.Organization), Serial: c.SerialNumber.Text(16),
		NotBefore: c.NotBefore.Unix(), NotAfter: c.NotAfter.Unix(), SHA256: hexOf(fp[:]), KeyUsage: chain.KeyUsageNames(c),
		SigAlg: c.SignatureAlgorithm.String(), OCSPServer: c.OCSPServer}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, d[x>>4], d[x&15])
	}
	return string(out)
}

// txFor builds the transaction view for a payload; at is the time the
// certificate chain is judged at (the block time, or now for pending ones).
func (n *Node) txFor(e chain.PayloadEntry, at time.Time) txView {
	v := txView{ID: e.ID(), Payload: e.Payload, Status: "pending"}
	if json.Valid([]byte(e.Payload)) {
		v.Parsed = json.RawMessage(e.Payload)
	}
	if sig, err := base64.StdEncoding.DecodeString(e.Signature); err == nil {
		v.SigBytes = len(sig)
		if s, err := chain.VerifyDetached(sig, []byte(e.Payload)); err == nil {
			v.Cert = certToView(s.Cert)
			v.Hash = s.HashFunction.String()
			if !s.SigningTime.IsZero() {
				v.Claimed = s.SigningTime.Unix()
			}
		}
	}
	if _, err := n.store.P.VerifyPayload(e, at); err != nil {
		v.Error = err.Error()
	} else {
		v.Valid = true
	}
	if e.OCSP != "" {
		raw, err := base64.StdEncoding.DecodeString(e.OCSP)
		if err != nil {
			v.OCSPError = "not valid base64"
		} else if sig, serr := base64.StdEncoding.DecodeString(e.Signature); serr == nil {
			if s, verr := chain.VerifyDetached(sig, []byte(e.Payload)); verr == nil {
				info, ierr := chain.InspectOCSP(raw, s.Cert, n.store.P.Trust.Issuer(s.Cert))
				v.OCSP = &info
				if ierr != nil {
					v.OCSPError = ierr.Error()
				}
			}
		}
	}
	return v
}

func (n *Node) txSummaries(b *chain.Block) []txSummary {
	out := make([]txSummary, 0, len(b.Payloads))
	for i, e := range b.Payloads {
		m := n.metaFor(e, time.Unix(b.Header.Time, 0))
		out = append(out, txSummary{ID: e.ID(), Index: i, Preview: preview(e.Payload), Bytes: len(e.Payload), Subject: m.Subject, OCSP: e.OCSP != ""})
	}
	return out
}

// ---- handlers ----

func (n *Node) registerExplorer(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/explorer/blocks", n.handleExplorerBlocks)
	mux.HandleFunc("GET /api/v1/explorer/block/{ref}", n.handleExplorerBlock)
	mux.HandleFunc("GET /api/v1/explorer/tx/{id}", n.handleExplorerTx)
	mux.HandleFunc("GET /api/v1/explorer/authorities", n.handleExplorerAuthorities)
	mux.HandleFunc("GET /api/v1/explorer/search", n.handleExplorerSearch)
	mux.HandleFunc("GET /api/v1/explorer/messages", n.handleExplorerMessages)
}

func (n *Node) handleExplorerBlocks(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseUint(r.URL.Query().Get("before"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	blocks := n.store.Window(before, limit)
	out := make([]blockSummary, 0, len(blocks))
	for _, b := range blocks {
		out = append(out, summarize(b, true))
	}
	var older uint64 // pass as ?before= to get the next page; 0 = no more
	if len(blocks) == limit && blocks[len(blocks)-1].Header.Height > 1 {
		older = blocks[len(blocks)-1].Header.Height
	}
	head, height := n.store.Head()
	writeJSON(w, 200, map[string]any{"blocks": out, "older": older, "height": height, "head": head})
}

// handleExplorerMessages pages through messages block by block, newest first.
// Pending messages come with the first page.
func (n *Node) handleExplorerMessages(w http.ResponseWriter, r *http.Request) {
	const blocksPerPage = 20
	before, _ := strconv.ParseUint(r.URL.Query().Get("before"), 10, 64)
	out := []Message{}
	if before == 0 {
		out = n.pendingMessages()
	}
	blocks := n.store.Window(before, blocksPerPage)
	for _, b := range blocks {
		out = append(out, n.blockMessages(b)...)
	}
	var older uint64
	if len(blocks) == blocksPerPage && blocks[len(blocks)-1].Header.Height > 1 {
		older = blocks[len(blocks)-1].Header.Height
	}
	writeJSON(w, 200, map[string]any{"messages": out, "older": older})
}

// resolveBlock finds a block by decimal height or by 64-hex hash.
func (n *Node) resolveBlock(ref string) (*chain.Block, bool) {
	if h, err := strconv.ParseUint(ref, 10, 64); err == nil {
		return n.store.BlockAt(h)
	}
	if hash, err := chain.ParseHash(ref); err == nil {
		return n.store.Block(hash)
	}
	return nil, false
}

func (n *Node) handleExplorerBlock(w http.ResponseWriter, r *http.Request) {
	b, ok := n.resolveBlock(r.PathValue("ref"))
	if !ok {
		writeErr(w, 404, errors.New("no such block"))
		return
	}
	h := b.Hash()
	canon := n.store.IsCanonical(h)
	v := blockView{blockSummary: summarize(b, canon), Header: b.Header, Signature: b.Signature,
		Transactions: n.txSummaries(b), Rotations_: b.Rotations}
	if v.Rotations_ == nil {
		v.Rotations_ = []chain.Rotation{}
	}
	prev := b.Header.Prev
	if b.Header.Height == 1 {
		v.PrevIsGenesis = true
	}
	v.Prev = &prev
	if canon {
		_, head := n.store.Head()
		v.Confirmations = head - b.Header.Height + 1
		if nh, ok := n.store.HashAt(b.Header.Height + 1); ok {
			v.Next = &nh
		}
	}
	writeJSON(w, 200, v)
}

func (n *Node) handleExplorerTx(w http.ResponseWriter, r *http.Request) {
	id, err := chain.ParseHash(r.PathValue("id"))
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if b, idx, ok := n.store.FindPayload(id); ok {
		v := n.txFor(b.Payloads[idx], time.Unix(b.Header.Time, 0))
		bh := b.Hash()
		v.Status, v.Block, v.Height, v.Index, v.Time = "confirmed", &bh, b.Header.Height, idx, b.Header.Time
		writeJSON(w, 200, v)
		return
	}
	for _, it := range n.pool.Snapshot() {
		if it.Entry.ID() == id {
			v := n.txFor(it.Entry, time.Now())
			v.Time = it.Added
			writeJSON(w, 200, v)
			return
		}
	}
	writeErr(w, 404, errors.New("no such transaction"))
}

func (n *Node) handleExplorerAuthorities(w http.ResponseWriter, r *http.Request) {
	type event struct {
		Height    uint64     `json:"height"`
		Block     chain.Hash `json:"block"`
		Time      int64      `json:"time"`
		Old       string     `json:"old"`
		NewKey    string     `json:"newKey"`
		Approvers []string   `json:"approvers"`
		Seq       uint64     `json:"seq"`
	}
	hist := []event{}
	for _, e := range n.store.RotationHistory() {
		ev := event{Height: e.Height, Block: e.Block, Time: e.Time, Old: e.Rotation.Change.Old, NewKey: e.Rotation.Change.NewKey, Seq: e.Rotation.Change.Seq}
		for _, s := range e.Rotation.Signatures {
			ev.Approvers = append(ev.Approvers, s.Signer)
		}
		hist = append(hist, ev)
	}
	st := n.store.HeadState()
	pending := n.rots.List()
	if pending == nil {
		pending = []chain.Rotation{} // JSON [] rather than null
	}
	writeJSON(w, 200, map[string]any{
		"genesis":  n.store.P.Genesis.Authorities,
		"current":  st.IDs,
		"seq":      st.Seq,
		"quorum":   n.store.P.Rules.RotationQuorum,
		"window":   n.store.P.RecentSignerWindow(),
		"history":  hist,
		"pending":  pending,
		"canSign":  n.localKeyIDs(),
		"rotation": n.store.P.Rules,
	})
}

// localKeyIDs lists the authority keys this node holds, so the UI can show which ones sign here.
func (n *Node) localKeyIDs() []string {
	ids := []string{}
	for _, s := range n.signers {
		ids = append(ids, s.ID)
	}
	return ids
}

// handleExplorerSearch resolves a query to something the UI can open.
func (n *Node) handleExplorerSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	found := func(kind, ref string) { writeJSON(w, 200, map[string]string{"kind": kind, "ref": ref}) }
	if q == "" {
		writeErr(w, 400, errors.New("empty query"))
		return
	}
	if h, err := strconv.ParseUint(q, 10, 64); err == nil {
		if h == 0 {
			found("node", "")
			return
		}
		if _, ok := n.store.BlockAt(h); ok {
			found("block", q)
			return
		}
	}
	if hash, err := chain.ParseHash(q); err == nil {
		switch {
		case hash == n.store.P.GenesisHash:
			found("node", "")
			return
		case func() bool { _, ok := n.store.Block(hash); return ok }():
			found("block", q)
			return
		case n.store.OnChain(hash) || n.pool.Has(hash):
			found("tx", q)
			return
		}
		for _, id := range n.store.HeadState().IDs {
			if id == q {
				found("authority", q)
				return
			}
		}
		for _, e := range n.store.RotationHistory() {
			if e.Rotation.Change.Old == q {
				found("authority", q)
				return
			}
		}
	}
	switch hits := n.searchShort(q); {
	case len(hits) == 1:
		found(hits[0].kind, hits[0].ref)
		return
	case len(hits) > 1:
		writeErr(w, 404, errors.New("that matches more than one item: give more of the hash"))
		return
	}
	writeErr(w, 404, errors.New("nothing matches: try a block height, a block hash, a message id or an authority key id"))
}

type searchHit struct{ kind, ref string }

// searchShort resolves the shortened hashes the UI displays: "1a96878e…45a82", or
// a bare prefix of at least 8 hex digits.
func (n *Node) searchShort(q string) []searchHit {
	prefix, suffix, _ := strings.Cut(strings.ReplaceAll(q, "...", "…"), "…")
	if len(prefix) < 8 {
		return nil
	}
	seen := map[searchHit]bool{}
	var hits []searchHit
	try := func(kind, full string) {
		if h := (searchHit{kind, full}); strings.HasPrefix(full, prefix) && strings.HasSuffix(full, suffix) && !seen[h] {
			seen[h] = true
			hits = append(hits, h)
		}
	}
	blocks, payloads := n.store.AllHashes()
	for _, h := range blocks {
		try("block", h.String())
	}
	for _, h := range payloads {
		try("tx", h.String())
	}
	for _, it := range n.pool.Snapshot() {
		try("tx", it.Entry.ID().String())
	}
	for _, id := range n.store.HeadState().IDs {
		try("authority", id)
	}
	for _, e := range n.store.RotationHistory() {
		try("authority", e.Rotation.Change.Old)
	}
	if strings.HasPrefix(n.store.P.GenesisHash.String(), prefix) {
		try("node", n.store.P.GenesisHash.String())
	}
	for i := range hits {
		if hits[i].kind == "node" {
			hits[i].ref = ""
		}
	}
	return hits
}
