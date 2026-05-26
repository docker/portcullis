package portcullis

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNextValidMatchSkipsZeroLengthMatches pins the guard that
// keeps redactWithRule's multi-match loop terminating. A regex
// that can match the empty string (here `a*`) returns a zero-length
// match at every byte of the input; without the `e > s` filter in
// nextValidMatch the redact loop's `cursor = e` would not advance
// and the call would spin forever. None of the current rules can
// produce a zero-length match, so this test exists purely to
// protect future rule authors from accidentally introducing one.
func TestNextValidMatchSkipsZeroLengthMatches(t *testing.T) {
	t.Parallel()

	re := regexp.MustCompile(`a*`)
	cm := compiledMatch{re: re, secretIdx: -1}

	assert.Nil(t, nextValidMatch(cm, "bbb"),
		"zero-length matches must not be returned")

	// A real (non-empty) match further along the input is still
	// found — the guard skips empty matches without giving up.
	m := nextValidMatch(cm, "bbbaaa")
	assert.NotNil(t, m)
	assert.Equal(t, "aaa", "bbbaaa"[m[0]:m[1]])
}
