package portcullis

import (
	"strings"
	"testing"
)

// BenchmarkAhoScanCleanInput isolates the keyword pre-filter from
// the rest of [Redact] so a regression in the scan loop is visible
// directly, not diluted by regex compile / rule-iteration costs.
func BenchmarkAhoScanCleanInput(b *testing.B) {
	rs := compiledRuleSet()
	text := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = rs.ac.scan(text)
	}
}

// BenchmarkAhoScanWithKeyword measures the same loop on a payload
// that hits a couple of keyword acceptance states; the inner OR
// chain runs harder than on a clean input.
func BenchmarkAhoScanWithKeyword(b *testing.B) {
	rs := compiledRuleSet()
	text := strings.Repeat("noise ", 100) +
		"token=ghp_xxxxxx and key=" + strings.Repeat("a", 40) +
		strings.Repeat(" trailing", 100)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = rs.ac.scan(text)
	}
}
