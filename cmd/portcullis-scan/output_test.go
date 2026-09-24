package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeValue(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input, want string
	}{
		{"", ""},
		{"unchanged é\xff", "unchanged é\xff"},
		{"a\r\nb", "a b"},
		{"a\rb\nc", "a b c"},
		{"\r\r\n\n", "   "},
		{"\n\r", "  "},
		{"a\t\vb", "a\t\vb"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, sanitizeValue(tc.input))
		})
	}
}

func BenchmarkSanitizeValue(b *testing.B) {
	for _, tc := range []struct {
		name, input string
	}{
		{"clean", githubPAT},
		{"multiline", strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n", 64)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			sanitizeValue(tc.input)
			b.ReportAllocs()
			for b.Loop() {
				sanitizeValue(tc.input)
			}
		})
	}
}
