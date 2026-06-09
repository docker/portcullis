package portcullis

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDedupOverlappingKeepsLongestMatch(t *testing.T) {
	t.Parallel()

	matches := []Match{
		{Start: 0, End: 5, Value: "short"},
		{Start: 3, End: 20, Value: "much-longer-match"},
	}

	deduped := dedupOverlapping(matches)

	assert.Equal(t, []Match{{Start: 3, End: 20, Value: "much-longer-match"}}, deduped)
}

func TestDedupOverlappingDropsContainedMatch(t *testing.T) {
	t.Parallel()

	matches := []Match{
		{Start: 10, End: 20, Value: "suffix"},
		{Start: 0, End: 20, Value: "full-token"},
	}

	deduped := dedupOverlapping(matches)

	assert.Equal(t, []Match{{Start: 0, End: 20, Value: "full-token"}}, deduped)
}

func TestDedupOverlappingKeepsTouchingSpans(t *testing.T) {
	t.Parallel()

	matches := []Match{
		{Start: 0, End: 5, Value: "first"},
		{Start: 5, End: 10, Value: "second"},
	}

	deduped := dedupOverlapping(matches)

	assert.Equal(t, []Match{{Start: 0, End: 5, Value: "first"}, {Start: 5, End: 10, Value: "second"}}, deduped)
}

func TestMergeOverlappingRedactionSpans(t *testing.T) {
	t.Parallel()

	matches := []Match{{Start: 0, End: 10}, {Start: 5, End: 15}, {Start: 15, End: 20}}

	merged := mergeOverlapping(matches)

	assert.Equal(t, []Match{{Start: 0, End: 15}, {Start: 15, End: 20}}, merged)
}
