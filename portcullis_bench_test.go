package portcullis_test

import (
	"strings"
	"testing"

	"github.com/docker/portcullis"
)

// BenchmarkRedactCleanInput is the headline scenario: most messages
// contain no secrets, so the keyword pre-filter must skip every rule's
// regex.
func BenchmarkRedactCleanInput(b *testing.B) {
	text := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = portcullis.Redact(text)
	}
}

// BenchmarkRedactWithSecret exercises the full path: lower-case +
// keyword hit + regex match + cursor-rebuild redaction.
func BenchmarkRedactWithSecret(b *testing.B) {
	text := strings.Repeat("noise ", 100) +
		"ghp_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + "0uCPlr" +
		strings.Repeat(" trailing", 100)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = portcullis.Redact(text)
	}
}

// BenchmarkContainsCleanInput pins the Contains hot path on inputs
// that don't trip the pre-filter — the second-most-common scenario
// after Redact on clean text. Contains short-circuits on the first
// matching rule, so a clean payload exercises the same AC scan as
// Redact without the regex follow-ups.
func BenchmarkContainsCleanInput(b *testing.B) {
	text := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = portcullis.Contains(text)
	}
}

// BenchmarkContainsWithSecret measures the typical "is there a leak?"
// gate path: AC pre-filter hits, the matching rule's regex confirms,
// and Contains returns true on the first hit without scanning the
// rest of the catalogue.
func BenchmarkContainsWithSecret(b *testing.B) {
	text := strings.Repeat("noise ", 100) +
		"ghp_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + "0uCPlr" +
		strings.Repeat(" trailing", 100)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = portcullis.Contains(text)
	}
}

// BenchmarkFindBytesCleanInput vs BenchmarkRedactCleanInput / Find
// pins the no-copy property of the []byte entry point: the
// allocation count must stay flat as input size grows, while the
// equivalent Find(string(buf)) call grows linearly with the buffer.
func BenchmarkFindBytesCleanInput(b *testing.B) {
	buf := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200))
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = portcullis.FindBytes(buf)
	}
}

// BenchmarkFindStringCopyCleanInput is the same scenario as
// BenchmarkFindBytesCleanInput but goes through Find(string(buf)),
// which forces a copy. The delta vs FindBytes is the win the new
// API gives library callers who already hold a []byte.
func BenchmarkFindStringCopyCleanInput(b *testing.B) {
	buf := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200))
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = portcullis.Find(string(buf))
	}
}
