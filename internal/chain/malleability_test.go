package chain_test

import (
	"encoding/json"
	"strings"
	"testing"

	"eidchain/internal/chain"
)

// The block hash is computed from the parsed header, never from the received
// bytes, so JSON layout cannot change a block's identity: key order, whitespace
// and string escapes are all accepted and give the same hash.
func TestHashDoesNotDependOnJSONLayout(t *testing.T) {
	e := newEnv(t, 1)
	b := e.next(e.signers[0], []chain.PayloadEntry{e.payload("layout")}, nil)
	want := b.Hash()

	canon, _ := json.Marshal(b)
	var generic map[string]json.RawMessage
	_ = json.Unmarshal(canon, &generic)
	var hdr map[string]json.RawMessage
	_ = json.Unmarshal(generic["header"], &hdr)
	keys := []string{"signer", "rotationCount", "rotationsRoot", "payloadCount", "payloadsRoot", "time", "prev", "height", "version"}
	var parts []string
	for _, k := range keys {
		parts = append(parts, "  \""+k+"\" :\n"+string(hdr[k]))
	}
	// The payload string contains the word "message"; write one letter as a \u escape.
	payloads := strings.Replace(string(generic["payloads"]), "message", "messag"+"\\u0065", 1)
	if payloads == string(generic["payloads"]) {
		t.Fatalf("test bug: nothing was escaped in %.80q (keys %d)", string(generic["payloads"]), len(generic))
	}
	reordered := `{ "signature":` + string(generic["signature"]) + `, "payloads":` + payloads + `,
 "header": {` + strings.Join(parts, ",") + `} }`
	var got chain.Block
	if err := chain.StrictUnmarshal([]byte(reordered), &got); err != nil {
		t.Fatalf("a re-laid-out but valid block was refused: %v", err)
	}
	if got.Hash() != want {
		t.Fatal("hash changed when only the JSON layout changed")
	}
	if _, err := e.store.AddBlock(&got); err != nil {
		t.Fatalf("re-laid-out block rejected: %v", err)
	}
}

// Documents that Go's decoder would read one way and other parsers another are refused.
func TestStrictUnmarshalRejectsAmbiguousJSON(t *testing.T) {
	e := newEnv(t, 1)
	b := e.next(e.signers[0], []chain.PayloadEntry{e.payload("strict")}, nil)
	canon, _ := json.Marshal(b)
	doc := string(canon)

	var ok chain.Block
	if err := chain.StrictUnmarshal(canon, &ok); err != nil {
		t.Fatalf("canonical block refused: %v", err)
	}
	cases := []struct{ name, doc, want string }{
		{"duplicate header key", strings.Replace(doc, `"header":{"version":1,`, `"header":{"version":7,"version":1,`, 1), "duplicate key"},
		{"duplicate top-level key", strings.Replace(doc, `{"header"`, `{"signature":"x","header"`, 1), "duplicate key"},
		{"duplicate key in a payload entry", strings.Replace(doc, `"payloads":[{`, `"payloads":[{"signature":"x",`, 1), "duplicate key"},
		{"case variant in the header", strings.Replace(doc, `"height"`, `"HEIGHT"`, 1), "case-sensitive"},
		{"case variant at the top level", strings.Replace(doc, `"payloads"`, `"Payloads"`, 1), "case-sensitive"},
		{"unknown field", strings.Replace(doc, `{"header"`, `{"extra":1,"header"`, 1), "unknown field"},
		{"trailing data", doc + ` {}`, "trailing"},
	}
	for _, c := range cases {
		if c.doc == doc {
			t.Fatalf("%s: test bug, document unchanged", c.name)
		}
		var blk chain.Block
		err := chain.StrictUnmarshal([]byte(c.doc), &blk)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", c.name, c.want, err)
		}
	}
	// The rule applies to genesis files too.
	g, _ := json.Marshal(e.genesis)
	if _, err := chain.ParseGenesis([]byte(strings.Replace(string(g), `"message"`, `"Message"`, 1))); err == nil {
		t.Error("genesis with a case-variant field accepted")
	}
	if _, err := chain.ParseGenesis(g); err != nil {
		t.Errorf("canonical genesis refused: %v", err)
	}
}
