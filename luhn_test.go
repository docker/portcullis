package portcullis

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Keep the original implementation as an oracle for arbitrary byte strings.
func referenceLuhn(value string) bool {
	var digits []int
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	total := 0
	for i := range digits {
		d := digits[len(digits)-1-i]
		if i%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		total += d
	}
	return total%10 == 0
}

func FuzzValidLuhn(f *testing.F) {
	for _, value := range []string{
		"", "4111 1111 1111 1111", "5555-5555-5555-4444", "3782 822463 10005",
		"4111 1111 1111 1112", "４１１１1111é1111\xff1111\x001111", "no digits",
		strings.Repeat("0", 12), strings.Repeat("0", 13),
		strings.Repeat("0", 19), strings.Repeat("0", 20),
	} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		assert.Equal(t, referenceLuhn(value), validLuhn(value), "input: %q", value)
	})
}

func BenchmarkValidLuhn(b *testing.B) {
	for _, tc := range []struct {
		name, value string
	}{
		{"card", "4111111111111111"},
		{"separated", "5555-5555-5555-4444"},
		{"invalid", "4111111111111112"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				validLuhn(tc.value)
			}
		})
	}
}
