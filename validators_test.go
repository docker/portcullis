package portcullis

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidGitHubChecksum(t *testing.T) {
	t.Parallel()

	cases := []string{
		"ghp_" + strings.Repeat("A", 30) + "1yBYBE",
		"gho_" + strings.Repeat("B", 30) + "2EnKYh",
		"ghu_" + strings.Repeat("C", 30) + "12Mf6L",
		"ghs_" + strings.Repeat("D", 30) + "1fOFde",
		"ghr_" + strings.Repeat("E", 30) + "0rAO3S",
		"github_pat_" + strings.Repeat("a", 22) + "_" + strings.Repeat("b", 53) + "2ioKsE",
	}

	for _, token := range cases {
		assert.Truef(t, validGitHubChecksum(token), "%q should have a valid checksum", token)
	}
}

func TestInvalidGitHubChecksum(t *testing.T) {
	t.Parallel()

	assert.False(t, validGitHubChecksum("ghp_"+strings.Repeat("a", 36)))
	assert.False(t, validGitHubChecksum("github_pat_"+strings.Repeat("a", 22)+"_"+strings.Repeat("b", 59)))
}

func TestBase62CRC32(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "000000", base62CRC32(""))
	assert.Equal(t, "1yBYBE", base62CRC32("ghp_"+strings.Repeat("A", 30)))
}
