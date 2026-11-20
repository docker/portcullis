package portcullis

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func referenceSeparatedDigitRun(text string, minDigits int, ws bool) bool {
	run := 0
	afterDigit := false
	for i := range len(text) {
		c := text[i]
		switch {
		case c >= '0' && c <= '9':
			run++
			if run >= minDigits {
				return true
			}
			afterDigit = true
		case afterDigit && (c == '-' || c == ' ' ||
			(ws && (c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'))):
			afterDigit = false
		default:
			run = 0
			afterDigit = false
		}
	}
	return false
}

func referenceIBANAnchor(text string) bool {
	for i := 0; i+3 < len(text); i++ {
		if isASCIILetter(text[i]) && isASCIILetter(text[i+1]) &&
			isASCIIDigit(text[i+2]) && isASCIIDigit(text[i+3]) {
			return true
		}
	}
	return false
}

// referenceShapes spells out each shape on its own, one pass per
// shape, as the definition [scanShapes] has to agree with.
func referenceShapes(text string) (found shapes) {
	if referenceSeparatedDigitRun(text, 13, true) {
		found |= shapeCard
	}
	if referenceSeparatedDigitRun(text, 9, false) {
		found |= shapeSSN
	}
	if referenceIBANAnchor(text) {
		found |= shapeIBAN
	}
	return found
}

func FuzzScanShapes(f *testing.F) {
	for _, value := range []string{
		"", "clean prose", "123456789", "4111 1111 1111 1111",
		"1\t2\n3\r4\v5\f6-7 8 9", "1  234567890123", "é１２3\xff456789",
		"12345678", "123456789012", "1234567890123",
		"1234- 567890123", "1234\t\n567890123", "12345678-", "123456789012\t",
		"GB82", "B82", "GB8", "G8B2", "12GB82", "1 GB82", "1234\tGB82 WEST",
		"123 45\t6789", "12345\t6789 12345", "DE89 3704 0044 0532 0130 00 123-45-6789",
	} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		assert.Equal(t, referenceShapes(value), scanShapes(value), "input %q", value)
	})
}

// TestScanShapesMatchesReference feeds [scanShapes] digit-heavy noise,
// the inputs where its single pass has the most state to get wrong.
func TestScanShapesMatchesReference(t *testing.T) {
	t.Parallel()

	const alphabet = "0123456789- \t\n\r\v\fabZ.\xc3"
	rng := rand.New(rand.NewSource(1))
	for range 200_000 {
		buf := make([]byte, rng.Intn(48))
		for i := range buf {
			if rng.Intn(3) == 0 {
				buf[i] = alphabet[rng.Intn(len(alphabet))]
			} else {
				buf[i] = byte('0' + rng.Intn(10))
			}
		}
		value := string(buf)
		if want, got := referenceShapes(value), scanShapes(value); want != got {
			t.Fatalf("input %q: want %03b, got %03b", value, want, got)
		}
	}
}

func BenchmarkScanShapes(b *testing.B) {
	for _, tc := range []struct {
		name, input string
	}{
		{"clean", strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200)},
		{"short", "no digits"},
		{"numeric", strings.Repeat("2026-09-24 request 200 completed in 42 ms\n", 200)},
		{"card", "4111 1111 1111 1111"},
		{"late_card", strings.Repeat("clean prose ", 700) + "4111 1111 1111 1111"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				scanShapes(tc.input)
			}
		})
	}
}
