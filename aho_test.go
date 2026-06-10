package portcullis

import (
	"math/rand"
	"strings"
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

func TestAhoCorasickPropagatesAllKwMaskWords(t *testing.T) {
	t.Parallel()

	patterns := make([]string, 257)
	for i := range 256 {
		patterns[i] = string([]byte{'x', byte(i)})
	}
	patterns[256] = "bc"
	patterns = append(patterns, "abc")

	mask := buildAhoCorasick(patterns).scan("abc")

	assert.NotZero(t, mask[4]&(1<<0), "suffix match at keyword index 256 must propagate through fail links")
}

// TestAhoCorasickPanicOnTooManyPatterns verifies that buildAhoCorasick
// panics when given more than 320 patterns, which would overflow the
// kwMask bitset.
func TestAhoCorasickPanicOnTooManyPatterns(t *testing.T) {
	t.Parallel()

	patterns := make([]string, 321)
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

// TestAhoScanShardedMatchesSerial guards the sharded scan against
// the serial reference: both must report the same keyword set on
// randomized inputs long enough to take the sharded path, including
// keywords planted to straddle shard boundaries.
func TestAhoScanShardedMatchesSerial(t *testing.T) {
	t.Parallel()

	rs := compiledRuleSet()
	rng := rand.New(rand.NewSource(42))
	keywords := []string{"ghp_", "aws", "secret-live-", "token", "sb_secret_", "-----begin"}
	alphabet := "abcdefghijklmnopqrstuvwxyz ._-=:"

	for range 200 {
		n := shardedScanMin + rng.Intn(4096)
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = alphabet[rng.Intn(len(alphabet))]
		}
		// Plant keywords at random offsets, plus one straddling a few
		// shard boundaries.
		size := (n + 7) / 8
		for _, pos := range []int{rng.Intn(n), size - 2, 3*size - 2, 5*size - 2, 7*size - 2} {
			kw := keywords[rng.Intn(len(keywords))]
			if pos+len(kw) <= n {
				copy(buf[pos:], kw)
			}
		}
		text := string(buf)

		assert.Equal(t, rs.ac.scanSerial(text), rs.ac.scanSharded(text), "input: %q", text)
	}
}

// TestAhoScanShardedBoundarySpanningKeyword pins the overlap
// arithmetic: the longest keyword placed to straddle every shard
// boundary must still be detected by the sharded scan.
func TestAhoScanShardedBoundarySpanningKeyword(t *testing.T) {
	t.Parallel()

	patterns := []string{"boundary-keyword"}
	ac := buildAhoCorasick(patterns)

	n := shardedScanMin * 2
	size := (n + 7) / 8
	for boundary := size; boundary < n; boundary += size {
		for shift := 1; shift < len(patterns[0]); shift++ {
			buf := []byte(strings.Repeat(".", n))
			copy(buf[boundary-shift:], patterns[0])
			mask := ac.scan(string(buf))
			assert.Falsef(t, mask.empty(), "keyword spanning boundary %d at shift %d must be found", boundary, shift)
		}
	}
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
		compiled := r.compile()
		re := compiled.re
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
