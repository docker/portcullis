package portcullis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAhoCorasickOverlappingPatterns verifies that the AC automaton
// correctly detects all overlapping patterns in a single scan. This
// is a regression guard for the fail-link computation in
// buildAhoCorasick: if the BFS-based table construction incorrectly
// inherits transitions, suffix patterns can be missed.
func TestAhoCorasickOverlappingPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		patterns []string
		text     string
		expected []int // indices of patterns that should match
	}{
		{
			name:     "overlapping at boundary",
			patterns: []string{"ab", "bc"},
			text:     "abc",
			expected: []int{0, 1},
		},
		{
			name:     "suffix patterns",
			patterns: []string{"he", "she", "his", "hers"},
			text:     "ushers",
			expected: []int{0, 1, 3}, // "he" in "ushers", "she" in "ushers", "hers" in "ushers"
		},
		{
			name:     "nested patterns",
			patterns: []string{"abc", "bc", "c"},
			text:     "abc",
			expected: []int{0, 1, 2},
		},
		{
			name:     "repeated patterns",
			patterns: []string{"a", "aa", "aaa"},
			text:     "aaa",
			expected: []int{0, 1, 2},
		},
		{
			name:     "no match",
			patterns: []string{"xyz", "foo"},
			text:     "bar",
			expected: nil,
		},
		{
			name:     "case folding",
			patterns: []string{"key"},
			text:     "KEY",
			expected: []int{0},
		},
		{
			name:     "multiple occurrences",
			patterns: []string{"key"},
			text:     "key and key again",
			expected: []int{0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ac := buildAhoCorasick(tt.patterns)
			mask := ac.scan(tt.text)

			var found []int
			for i := range len(tt.patterns) {
				if mask[i>>6]&(1<<uint(i&63)) != 0 {
					found = append(found, i)
				}
			}

			assert.Equal(t, tt.expected, found,
				"patterns %v in text %q", tt.patterns, tt.text)
		})
	}
}

// TestAhoCorasickPanicOnTooManyPatterns verifies that buildAhoCorasick
// panics when given more than 256 patterns, which would overflow the
// kwMask bitset.
func TestAhoCorasickPanicOnTooManyPatterns(t *testing.T) {
	t.Parallel()

	patterns := make([]string, 257)
	for i := range patterns {
		// Each pattern must be unique to avoid trie conflicts; encode
		// the index as a 3-letter base-26 string.
		a := byte('a' + (i/26/26)%26)
		b := byte('a' + (i/26)%26)
		c := byte('a' + i%26)
		patterns[i] = string([]byte{a, b, c})
	}

	assert.PanicsWithValue(t, "portcullis: too many AC patterns for kwMask",
		func() { buildAhoCorasick(patterns) })
}

// TestEveryRuleCompiles is a catalogue-hygiene guard: every rule's
// regex must be valid syntax and every rule must declare at least
// one keyword (otherwise its regex would never be reached). Without
// this test, a typo in a freshly-added rule expression would only
// surface when an input happened to trigger that rule's compile()
// path — which, for rare credential formats, might never happen in
// the rest of the suite.
func TestEveryRuleCompiles(t *testing.T) {
	t.Parallel()

	rs := compiledRuleSet()
	require.NotEmpty(t, rs.rules, "catalogue must not be empty")

	for i := range rs.rules {
		r := &rs.rules[i]
		assert.Falsef(t, r.kwBits.empty(),
			"rule %d has no keywords — its regex would never run", i)
		require.NotPanicsf(t, func() { r.compile() },
			"rule %d's regex must compile", i)
		re, _ := r.compile()
		require.NotNilf(t, re, "rule %d compile returned nil regexp", i)
	}
}

// TestKwMaskOperations verifies the kwMask bitset operations.
func TestKwMaskOperations(t *testing.T) {
	t.Parallel()

	var m kwMask
	assert.True(t, m.empty(), "zero-initialized mask should be empty")

	m.set(0)
	assert.False(t, m.empty(), "mask with bit 0 set should not be empty")
	assert.Equal(t, uint64(1), m[0], "bit 0 should be set in first word")

	m.set(63)
	assert.Equal(t, uint64(1<<63|1), m[0], "bit 63 should be set in first word")

	m.set(64)
	assert.Equal(t, uint64(1), m[1], "bit 64 should be set in second word")

	m.set(127)
	assert.Equal(t, uint64(1<<63|1), m[1], "bit 127 should be set in second word")

	m.set(128)
	assert.Equal(t, uint64(1), m[2], "bit 128 should be set in third word")

	m.set(192)
	assert.Equal(t, uint64(1), m[3], "bit 192 should be set in fourth word")

	m.set(255)
	assert.Equal(t, uint64(1<<63|1), m[3], "bit 255 should be set in fourth word")

	var other kwMask
	other.set(0)
	assert.True(t, m.overlaps(other), "masks with shared bit should overlap")

	other = kwMask{}
	other.set(200)
	assert.False(t, m.overlaps(other), "masks with no shared bits should not overlap")
}
