package tsa_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"eidchain/internal/testpki"
	"eidchain/internal/tsa"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// These tokens came from the real services, so the verifier is tested against
// what they actually send.
func TestVerifiesRealTokens(t *testing.T) {
	var hash [32]byte
	copy(hash[:], fixture(t, "hash.bin"))
	for name, authority := range map[string]string{"freetsa.tok": "www.freetsa.org", "sectigo.tok": "Sectigo Public Time Stamping Root R46"} {
		token := fixture(t, name)
		info, err := tsa.Verify(token, hash, tsa.Roots())
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if info.Authority != authority || info.Time.IsZero() {
			t.Errorf("%s: %+v", name, info)
		}
		other := hash
		other[0] ^= 1
		if _, err := tsa.Verify(token, other, tsa.Roots()); err == nil {
			t.Errorf("%s verified for another hash", name)
		}
		bad := append([]byte(nil), token...)
		bad[len(bad)-20] ^= 1
		if _, err := tsa.Verify(bad, hash, tsa.Roots()); err == nil {
			t.Errorf("a damaged %s verified", name)
		}
	}
}

func TestRequest(t *testing.T) {
	fake := testpki.NewTSA(t)
	srv := httptest.NewServer(fake)
	defer srv.Close()
	hash := [32]byte{1, 2, 3}
	token, info, err := tsa.Request(context.Background(), srv.Client(), srv.URL, hash, fake.Roots())
	if err != nil {
		t.Fatal(err)
	}
	if info.Authority != fake.RootName() || time.Since(info.Time) > time.Minute {
		t.Fatalf("%+v", info)
	}
	if _, err := tsa.Verify(token, hash, tsa.Roots()); err == nil {
		t.Error("a token from an unknown root verified")
	}
	if _, _, err := tsa.Request(context.Background(), srv.Client(), srv.URL, hash, tsa.Roots()); err == nil {
		t.Error("an untrusted authority was accepted")
	}
}

func TestRequestRefusesARepliedOldToken(t *testing.T) {
	fake := testpki.NewTSA(t)
	hash := [32]byte{4}
	real := httptest.NewServer(fake)
	defer real.Close()
	var saved []byte
	replay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(saved) }))
	defer replay.Close()
	rec := httptest.NewRecorder()
	body := fake.QueryFor(t, hash)
	fake.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader(string(body))))
	saved = rec.Body.Bytes()
	_, _, err := tsa.Request(context.Background(), replay.Client(), replay.URL, hash, fake.Roots())
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("got %v", err)
	}
}

func TestRefusesTokenNamingAnotherCertificate(t *testing.T) {
	fake := testpki.NewTSA(t)
	fake.WrongESS = true
	h := [32]byte{5}
	if _, err := tsa.Verify(fake.Token(t, h, time.Now()), h, fake.Roots()); err == nil || !strings.Contains(err.Error(), "different certificate") {
		t.Fatalf("got %v", err)
	}
}
