package portcullis

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMergeOverlappingRedactionSpans(t *testing.T) {
	t.Parallel()

	matches := []Match{{Start: 0, End: 10}, {Start: 5, End: 15}, {Start: 15, End: 20}}

	merged := mergeOverlapping(matches)

	assert.Equal(t, []Match{{Start: 0, End: 15}, {Start: 15, End: 20}}, merged)
}
