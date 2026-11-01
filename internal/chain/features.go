package chain

import (
	"fmt"
	"maps"
	"sort"
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
// setting in config.json. Unlike the genesis it is not hashed into the chain, yet it
// is a consensus rule: nodes with different schedules reject each other's blocks,
// so they compare schedules before syncing (see remote.Sync).
type Schedule map[string]uint64

// Validate refuses unknown features. A node must never ignore a rule it was told
// to enforce because of a misspelt or newer feature name.
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
		if height == 0 {
			return fmt.Errorf("feature %q: height must be at least 1", name)
		}
	}
	return nil
}

// Active reports whether a feature applies to the block at height.
func (s Schedule) Active(name string, height uint64) bool {
	from, ok := s[name]
	return ok && height >= from
}

// VersionAt is the block version required at height.
func (s Schedule) VersionAt(height uint64) int {
	v := Version
	for name, from := range s {
		if height >= from {
			v = max(v, featureVersions[name])
		}
	}
	return v
}

// Equal reports whether two schedules are the same. Nil and empty are.
func (s Schedule) Equal(o Schedule) bool { return maps.Equal(s, o) }
