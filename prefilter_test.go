package portcullis

import (
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

func FuzzSeparatedDigitRun(f *testing.F) {
	for _, value := range []string{
		"", "clean prose", "123456789", "4111 1111 1111 1111",
		"1\t2\n3\r4\v5\f6-7 8 9", "1  234567890123", "é１２3\xff456789",
		"12345678", "123456789012", "1234567890123",
		"1234- 567890123", "1234\t\n567890123", "12345678-", "123456789012\t",
	} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		for _, n := range []int{-1, 0, 1, 9, 13, 19} {
			for _, ws := range []bool{false, true} {
				assert.Equal(t, referenceSeparatedDigitRun(value, n, ws), hasSeparatedDigitRun(value, n, ws),
					"input %q, threshold %d, whitespace %t", value, n, ws)
			}
		}
	})
}

func BenchmarkDigitPrefilter(b *testing.B) {
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
				maybeCreditCard(tc.input)
				maybeSSN(tc.input)
			}
		})
	}
}
