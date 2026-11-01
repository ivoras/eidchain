package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"eidchain/internal/chain"
	"eidchain/internal/config"
)

func TestFeatureHeights(t *testing.T) {
	dir := t.TempDir()
	raw := `{"features": {"block-timestamps": null}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, listed := f.Features[chain.FeatureBlockTimestamps]
	if !listed || h != nil || f.Features.Active(chain.FeatureBlockTimestamps, 100) {
		t.Fatalf("null height: %v %v", listed, h)
	}
	if err := config.Save(dir, f); err != nil {
		t.Fatal(err)
	}
	again, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h, listed := again.Features[chain.FeatureBlockTimestamps]; !listed || h != nil {
		t.Fatalf("null was lost when saving: %v %v", listed, h)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"features": {"block-timestamps": 4}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if f, err = config.Load(dir); err != nil || !f.Features.Active(chain.FeatureBlockTimestamps, 4) || f.Features.Active(chain.FeatureBlockTimestamps, 3) {
		t.Fatalf("height 4: %v %v", err, f.Features)
	}
}
