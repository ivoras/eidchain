package chain

import (
	"fmt"
	"sort"
	"strings"
)

// A feature is a change to the block format or the consensus rules that starts at
// a chosen height, so a running chain can gain it without a new genesis. Blocks
// below that height keep the rules they were made under. Every feature bumps the
// block version, so a block says which format it is in.
//
// To add one: name it here with its version, then branch on Schedule.Active
// wherever the rules or the format differ.
const (
	// FeatureBlockTimestamps requires an RFC 3161 token in every block, covered by
	// the block hash.
	FeatureBlockTimestamps = "block-timestamps"
)

// featureVersions gives the block version each known feature introduces.
var featureVersions = map[string]int{
	FeatureBlockTimestamps: 2,
}

// Schedule says from which height each feature applies. It comes from the "features"
// setting in config.json. A nil height, null in the file, means the feature never
// applies, the same as leaving it out but stated on purpose. Unlike the genesis the
// schedule is not hashed into the chain, yet it is a consensus rule: nodes with
// different schedules reject each other's blocks, so they compare schedules before
// syncing (see remote.Sync).
type Schedule map[string]*uint64

// At is a height for a Schedule entry.
func At(height uint64) *uint64 { return &height }

// Validate refuses unknown features. A node must never ignore a rule it was told
// to enforce because of a misspelt or newer feature name. That holds for a null
// height too, or a typo there would go unnoticed until someone sets a height.
func (s Schedule) Validate() error {
	for name, height := range s {
		if _, ok := featureVersions[name]; !ok {
			names := make([]string, 0, len(featureVersions))
			for n := range featureVersions {
				names = append(names, n)
			}
			sort.Strings(names)
			return fmt.Errorf("unknown feature %q (known: %v)", name, names)
		}
		if height != nil && *height == 0 {
			return fmt.Errorf("feature %q: height must be at least 1, or null for never", name)
		}
	}
	return nil
}

// Active reports whether a feature applies to the block at height.
func (s Schedule) Active(name string, height uint64) bool {
	from := s[name]
	return from != nil && height >= *from
}

// VersionAt is the block version required at height.
func (s Schedule) VersionAt(height uint64) int {
	v := Version
	for name := range s {
		if s.Active(name, height) {
			v = max(v, featureVersions[name])
		}
	}
	return v
}

// Equal reports whether two schedules have the same effect: a feature that is null
// and one that is left out are the same.
func (s Schedule) Equal(o Schedule) bool {
	covered := func(a, b Schedule) bool {
		for name, h := range a {
			if h != nil && (b[name] == nil || *b[name] != *h) {
				return false
			}
		}
		return true
	}
	return covered(s, o) && covered(o, s)
}

// String lists the entries in a stable order, for messages.
func (s Schedule) String() string {
	parts := make([]string, 0, len(s))
	for name, h := range s {
		if h == nil {
			parts = append(parts, name+"=never")
		} else {
			parts = append(parts, fmt.Sprintf("%s=%d", name, *h))
		}
	}
	sort.Strings(parts)
	return "[" + strings.Join(parts, " ") + "]"
}
