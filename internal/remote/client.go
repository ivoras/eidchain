// Package remote is the HTTP client for an eidchain node, and the chain
// synchronisation that both `eidchain pull` and node-to-node sync use.
package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"eidchain/internal/chain"
)

// Info is the node status served at /api/v1/info.
type Info struct {
	Version              int        `json:"version"`
	GenesisHash          chain.Hash `json:"genesisHash"`
	Message              string     `json:"message"`
	Height               uint64     `json:"height"`
	Head                 chain.Hash `json:"head"`
	HeadTime             int64      `json:"headTime"`
	Authorities          []string   `json:"authorities"`
	RotationSeq          uint64     `json:"rotationSeq"`
	RotationQuorum       int        `json:"rotationQuorum"`
	Pending              int        `json:"pending"`
	PendingRotations     int        `json:"pendingRotations"`
	MaxPayloadBytes      int        `json:"maxPayloadBytes"`
	BlockIntervalSeconds int        `json:"blockIntervalSeconds"`
	NextBlockAt          int64      `json:"nextBlockAt"`
	CanProduce           bool       `json:"canProduce"`
	TrustAnchors         []string   `json:"trustAnchors"` // subjects of the eID CA certificates fixed in the genesis
}

// SubmitResult is the answer to a payload submission.
type SubmitResult struct {
	Status string     `json:"status"` // "accepted" or "known"
	ID     chain.Hash `json:"id"`
	OCSP   bool       `json:"ocsp"`
}

// RotationStatus is the answer to a rotation submission.
type RotationStatus struct {
	Change    chain.Hash `json:"change"`
	Approvals int        `json:"approvals"`
	Quorum    int        `json:"quorum"`
	Ready     bool       `json:"ready"`
}

// Client talks to one node.
type Client struct {
	Base string
	HTTP *http.Client
}

// New returns a client for a base URL such as http://host:8080.
func New(base string) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 60 * time.Second}}
}

const maxResponse = 64 << 20

// APIError is a non-2xx answer from a node.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message) }

func (c *Client) do(ctx context.Context, method, path string, in, out any) (int, error) {
	status, raw, err := c.fetch(ctx, method, path, in)
	if err != nil || out == nil {
		return status, err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return status, fmt.Errorf("decode response: %w", err)
	}
	return status, nil
}

// fetch performs a request and returns the raw body of a 2xx answer.
func (c *Client) fetch(ctx context.Context, method, path string, in any) (int, []byte, error) {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return 0, nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(raw))
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return resp.StatusCode, nil, &APIError{resp.StatusCode, msg}
	}
	return resp.StatusCode, raw, nil
}

func (c *Client) Info(ctx context.Context) (Info, error) {
	var i Info
	_, err := c.do(ctx, "GET", "/api/v1/info", nil, &i)
	return i, err
}

// GenesisRaw returns the genesis document exactly as the node serves it.
func (c *Client) GenesisRaw(ctx context.Context) ([]byte, error) {
	var raw json.RawMessage
	if _, err := c.do(ctx, "GET", "/api/v1/genesis", nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// HashAt returns the node's canonical block hash at a height.
func (c *Client) HashAt(ctx context.Context, height uint64) (chain.Hash, error) {
	var r struct {
		Hash chain.Hash `json:"hash"`
	}
	_, err := c.do(ctx, "GET", fmt.Sprintf("/api/v1/hashes/%d", height), nil, &r)
	return r.Hash, err
}

// Blocks fetches canonical blocks from height from.
func (c *Client) Blocks(ctx context.Context, from uint64, limit int) ([]*chain.Block, error) {
	_, raw, err := c.fetch(ctx, "GET", fmt.Sprintf("/api/v1/blocks?from=%d&limit=%d", from, limit), nil)
	if err != nil {
		return nil, err
	}
	var bs []*chain.Block
	if err := chain.StrictUnmarshal(raw, &bs); err != nil { // blocks from a peer get the strict rules too
		return nil, fmt.Errorf("decode blocks: %w", err)
	}
	return bs, nil
}

// PostBlock pushes a block; the returned status is "added", "known" or "unknown-parent".
func (c *Client) PostBlock(ctx context.Context, b *chain.Block) (string, error) {
	var r struct {
		Status string `json:"status"`
	}
	_, err := c.do(ctx, "POST", "/api/v1/blocks", b, &r)
	return r.Status, err
}

func (c *Client) PostPayload(ctx context.Context, e chain.PayloadEntry) (SubmitResult, error) {
	var r SubmitResult
	_, err := c.do(ctx, "POST", "/api/v1/payloads", e, &r)
	return r, err
}

// Peers returns the peer addresses a node is willing to share.
func (c *Client) Peers(ctx context.Context) ([]string, error) {
	var r struct {
		Peers []string `json:"peers"`
	}
	_, err := c.do(ctx, "GET", "/api/v1/peers", nil, &r)
	return r.Peers, err
}

// Announce tells a node this node's public address, so it can gossip with us too.
func (c *Client) Announce(ctx context.Context, url string) error {
	_, err := c.do(ctx, "POST", "/api/v1/peers", map[string]string{"url": url}, nil)
	return err
}

func (c *Client) PostRotation(ctx context.Context, rot chain.Rotation) (RotationStatus, error) {
	var r RotationStatus
	_, err := c.do(ctx, "POST", "/api/v1/rotations", rot, &r)
	return r, err
}

// ---- synchronisation ----

// SyncResult summarises a Sync.
type SyncResult struct {
	Remote   Info
	Fetched  int
	UpToDate bool
	Head     chain.Hash
	Height   uint64
}

const batch = 100

// Sync downloads and verifies every block the node has that the store lacks.
// Each block is fully validated by Store.AddBlock; nothing from the remote is
// trusted. A fork is handled by locating the last block both sides agree on
// and fetching from there, after which the store's fork choice decides.
func Sync(ctx context.Context, st *chain.Store, c *Client, progress func(string)) (SyncResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	info, err := c.Info(ctx)
	if err != nil {
		return SyncResult{}, fmt.Errorf("contact %s: %w", c.Base, err)
	}
	res := SyncResult{Remote: info}
	if info.GenesisHash != st.P.GenesisHash {
		return res, fmt.Errorf("%s serves a different chain (genesis %s, ours %s)", c.Base, info.GenesisHash.Short(), st.P.GenesisHash.Short())
	}
	if st.Has(info.Head) {
		res.UpToDate = true
		res.Head, res.Height = st.Head()
		return res, nil
	}
	// Find the highest height at which the remote's canonical block is one we know.
	_, localH := st.Head()
	h := min(localH, info.Height)
	common := uint64(0)
	for step := uint64(1); ; step *= 2 {
		rh, err := c.HashAt(ctx, h)
		if err != nil {
			return res, fmt.Errorf("fetch hash at %d: %w", h, err)
		}
		if st.Has(rh) {
			common = h
			break
		}
		if h == 0 {
			break // unreachable: the genesis always matches
		}
		if h > step {
			h -= step
		} else {
			h = 0
		}
	}
	from := common + 1
	for from <= info.Height {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		bs, err := c.Blocks(ctx, from, batch)
		if err != nil {
			return res, fmt.Errorf("fetch blocks from %d: %w", from, err)
		}
		if len(bs) == 0 {
			break
		}
		progress(fmt.Sprintf("Fetching blocks %d-%d of %d", from, from+uint64(len(bs))-1, info.Height))
		for _, b := range bs {
			if _, err := st.AddBlock(b); err != nil && !errors.Is(err, chain.ErrKnown) {
				return res, fmt.Errorf("block %d from %s rejected: %w", b.Header.Height, c.Base, err)
			}
			res.Fetched++
		}
		from += uint64(len(bs))
	}
	res.Head, res.Height = st.Head()
	return res, nil
}
