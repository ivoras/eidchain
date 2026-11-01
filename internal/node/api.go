package node

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/remote"
	"eidchain/internal/webapp"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// decode reads a size-limited JSON body with the strict rules of chain.StrictUnmarshal.
func decode(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, errors.New("request body too large"))
		return false
	}
	if err := chain.StrictUnmarshal(raw, v); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

// cors lets the API be called from pages served elsewhere; this is a PoC with
// no accounts, and every write needs an eID or authority signature anyway.
func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Handler returns the node's HTTP handler.
func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/info", n.handleInfo)
	mux.HandleFunc("GET /api/v1/genesis", n.handleGenesis)
	mux.HandleFunc("GET /api/v1/hashes/{height}", n.handleHash)
	mux.HandleFunc("GET /api/v1/blocks", n.handleBlocks)
	mux.HandleFunc("GET /api/v1/blocks/{hash}", n.handleBlock)
	mux.HandleFunc("POST /api/v1/blocks", n.handlePostBlock)
	mux.HandleFunc("GET /api/v1/messages", n.handleMessages)
	mux.HandleFunc("POST /api/v1/payloads", n.handlePostPayload)
	mux.HandleFunc("GET /api/v1/peers", n.handlePeers)
	mux.HandleFunc("POST /api/v1/peers", n.handleAnnounce)
	mux.HandleFunc("GET /api/v1/authorities", n.handleAuthorities)
	mux.HandleFunc("GET /api/v1/rotations", n.handleRotations)
	mux.HandleFunc("POST /api/v1/rotations", n.handlePostRotation)
	n.registerExplorer(mux)
	if n.opt.Web {
		mux.Handle("/", webapp.Handler())
	}
	return accessLog(cors(mux))
}

// clientAddr is the caller's address, honouring the reverse proxy's header.
func clientAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }

// accessLog logs every write request and every failed request. Successful GETs
// are not logged: the web app polls every few seconds. Client addresses are
// personal data, so they appear only in lines about failed requests.
func accessLog(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		start := time.Now()
		h.ServeHTTP(rec, r)
		switch {
		case rec.status >= 400: // error handler: the caller's address is kept for debugging
			log.Printf("http: %s %s from %s -> %d (%s)", r.Method, r.URL.Path, clientAddr(r), rec.status, time.Since(start).Round(time.Millisecond))
		case r.Method != http.MethodGet && r.Method != http.MethodOptions: // success: no client address (PII)
			log.Printf("http: %s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
		}
	})
}

func (n *Node) info() remote.Info {
	head, h := n.store.Head()
	parent := n.store.HeadParent()
	_, can := n.eligibleSigner(parent)
	var anchors []string
	for _, c := range n.store.P.Trust.Certificates() {
		anchors = append(anchors, chain.CertName(c))
	}
	var headTime int64
	if b, ok := n.store.Block(head); ok {
		headTime = b.Header.Time
	} else {
		headTime = n.store.P.Genesis.Created
	}
	return remote.Info{
		Version: chain.Version, GenesisHash: n.store.P.GenesisHash, Message: n.store.P.Genesis.Message,
		Height: h, Head: head, HeadTime: headTime,
		Authorities: parent.State.IDs, RotationSeq: parent.State.Seq, RotationQuorum: n.store.P.Rules.RotationQuorum,
		Pending: n.pool.Len(), PendingRotations: len(n.rots.List()),
		MaxPayloadBytes:      n.store.P.Rules.MaxPayloadBytes,
		BlockIntervalSeconds: int(n.opt.BlockInterval / time.Second),
		NextBlockAt:          nextBoundary(time.Now(), n.opt.BlockInterval).Unix(),
		CanProduce:           can,
		TrustAnchors:         anchors,
	}
}

func (n *Node) handleInfo(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, n.info()) }

func (n *Node) handleGenesis(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, n.store.P.Genesis)
}

func (n *Node) handleHash(w http.ResponseWriter, r *http.Request) {
	h, err := strconv.ParseUint(r.PathValue("height"), 10, 64)
	if err != nil {
		writeErr(w, 400, errors.New("bad height"))
		return
	}
	hash, ok := n.store.HashAt(h)
	if !ok {
		writeErr(w, 404, errors.New("no block at that height"))
		return
	}
	writeJSON(w, 200, map[string]chain.Hash{"hash": hash})
}

func (n *Node) handleBlocks(w http.ResponseWriter, r *http.Request) {
	from, _ := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	bs := n.store.Range(from, limit)
	if bs == nil {
		bs = []*chain.Block{}
	}
	writeJSON(w, 200, bs)
}

func (n *Node) handleBlock(w http.ResponseWriter, r *http.Request) {
	h, err := chain.ParseHash(r.PathValue("hash"))
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	b, ok := n.store.Block(h)
	if !ok {
		writeErr(w, 404, errors.New("unknown block"))
		return
	}
	writeJSON(w, 200, b)
}

func (n *Node) handlePostBlock(w http.ResponseWriter, r *http.Request) {
	var b chain.Block
	if !decode(w, r, 16<<20, &b) {
		return
	}
	res, err := n.store.AddBlock(&b)
	switch {
	case errors.Is(err, chain.ErrKnown):
		writeJSON(w, 200, map[string]string{"status": "known"})
	case errors.Is(err, chain.ErrUnknownParent):
		log.Printf("block %s (height %d) has an unknown parent %s: syncing", b.Hash().Short(), b.Header.Height, b.Header.Prev.Short())
		n.kickSync() // we are behind: catch up from our peers
		writeJSON(w, 202, map[string]string{"status": "unknown-parent"})
	case err != nil:
		log.Printf("block %s (height %d, signer %.12s…, %d payload(s), %d rotation(s)) from %s REJECTED: %v",
			b.Hash().Short(), b.Header.Height, b.Header.Signer, len(b.Payloads), len(b.Rotations), clientAddr(r), err)
		writeErr(w, 422, err)
	default:
		_ = res
		n.broadcastBlock(&b) // flood; peers that know it answer "known" and stop
		writeJSON(w, 201, map[string]string{"status": "added"})
	}
}

func (n *Node) handlePostPayload(w http.ResponseWriter, r *http.Request) {
	var e chain.PayloadEntry
	if !decode(w, r, 256<<10, &e) {
		return
	}
	res, err := n.SubmitPayload(r.Context(), e, clientAddr(r))
	var bad ErrBadPayload
	switch {
	case errors.As(err, &bad):
		writeErr(w, 422, err)
	case err != nil:
		writeErr(w, 503, err)
	default:
		writeJSON(w, 200, res)
	}
}

func (n *Node) handleAuthorities(w http.ResponseWriter, r *http.Request) {
	st := n.store.HeadState()
	writeJSON(w, 200, map[string]any{"authorities": st.IDs, "rotationSeq": st.Seq, "rotationQuorum": n.store.P.Rules.RotationQuorum})
}

func (n *Node) handleRotations(w http.ResponseWriter, r *http.Request) {
	list := n.rots.List()
	if list == nil {
		list = []chain.Rotation{}
	}
	writeJSON(w, 200, list)
}

func (n *Node) handlePostRotation(w http.ResponseWriter, r *http.Request) {
	var rot chain.Rotation
	if !decode(w, r, 64<<10, &rot) {
		return
	}
	id, approvals, changed, err := n.rots.Add(n.store.P, n.store.HeadState(), rot)
	if err != nil {
		log.Printf("rotation %s from %s REJECTED: %v", id.Short(), clientAddr(r), err)
		writeErr(w, 422, err)
		return
	}
	quorum := n.store.P.Rules.RotationQuorum
	if changed {
		if cur := n.rots.find(id); cur != nil {
			n.broadcastRotation(*cur)
		}
	}
	writeJSON(w, 200, remote.RotationStatus{Change: id, Approvals: approvals, Quorum: quorum, Ready: approvals >= quorum})
}

// Message is a record as shown to the web app.
type Message struct {
	Status  string      `json:"status"` // "pending" or "confirmed"
	ID      chain.Hash  `json:"id"`
	Payload string      `json:"payload"`
	Subject string      `json:"subject"`
	Serial  string      `json:"serial"`
	Height  uint64      `json:"height,omitempty"`
	Block   *chain.Hash `json:"block,omitempty"`
	Time    int64       `json:"time,omitempty"`
	OCSP    bool        `json:"ocsp"`
}

func (n *Node) handleMessages(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := []Message{}
	for _, it := range n.pool.Snapshot() {
		out = append(out, Message{Status: "pending", ID: it.Entry.ID(), Payload: it.Entry.Payload,
			Subject: it.Subject, Serial: it.Serial, Time: it.Added, OCSP: it.Entry.OCSP != ""})
	}
	for _, b := range n.store.Latest(limit) {
		h := b.Hash()
		for _, e := range b.Payloads {
			if len(out) >= limit {
				break
			}
			m := n.metaFor(e, time.Unix(b.Header.Time, 0))
			out = append(out, Message{Status: "confirmed", ID: e.ID(), Payload: e.Payload, Subject: m.Subject,
				Serial: m.Serial, Height: b.Header.Height, Block: &h, Time: b.Header.Time, OCSP: e.OCSP != ""})
		}
	}
	writeJSON(w, 200, out)
}

// metaFor returns the signer details of a payload, caching the (slow) verification.
func (n *Node) metaFor(e chain.PayloadEntry, at time.Time) msgMeta {
	id := e.ID()
	if v, ok := n.meta.Load(id); ok {
		return v.(msgMeta)
	}
	m := msgMeta{Subject: "(unverified)"}
	if info, err := n.store.P.VerifyPayload(e, at); err == nil {
		m = msgMeta{info.Subject, info.Serial}
	}
	n.meta.Store(id, m)
	return m
}
