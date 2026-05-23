package portcullis

import (
	"slices"
	"strings"
	"unsafe"
)

// Marker replaces every detected secret span. Chosen so it doesn't
// match any rule's keyword pre-filter — see TestMarkerIsNotASecret
// for the safety property that makes [Redact] idempotent.
const Marker = "[REDACTED]"

// Match describes a single secret span detected in an input. Start
// and End are byte offsets into the original text and delimit the
// same span [Redact] would replace with [Marker]: when the matching
// rule defines a (?P<secret>…) named subgroup, the span covers only
// that subgroup; otherwise it covers the whole match. Value is the
// substring text[Start:End] for caller convenience.
type Match struct {
	Start int
	End   int
	Value string
}

// Find returns every secret span detected in text, in left-to-right
// order. Overlapping matches are deduplicated: when two rules flag
// overlapping spans (e.g. a Grafana legacy `eyJrIjoi…` token whose
// suffix also matches the generic JWT shape) Find keeps the longest
// span and drops the shorter one, so each underlying secret is
// reported once.
//
// Find is safe for concurrent use. The returned slice is freshly
// allocated and owned by the caller.
func Find(text string) []Match {
	if text == "" {
		return nil
	}
	rs := compiledRuleSet()
	found := rs.ac.scan(text)
	if found.empty() {
		return nil
	}
	var matches []Match
	for i := range rs.rules {
		r := &rs.rules[i]
		if !found.overlaps(r.kwBits) {
			continue
		}
		re, secretIdx := r.compile()
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			s, e := redactSpan(m, secretIdx)
			matches = append(matches, Match{Start: s, End: e, Value: text[s:e]})
		}
	}
	return dedupOverlapping(matches)
}

// dedupOverlapping collapses overlapping matches to one per underlying
// span. Sorting by Start asc, End desc lets a single greedy walk keep
// the leftmost-longest match and drop anything contained in or
// touching it. The relative left-to-right order of surviving matches
// is preserved.
func dedupOverlapping(matches []Match) []Match {
	if len(matches) < 2 {
		return matches
	}
	slices.SortFunc(matches, func(a, b Match) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		return b.End - a.End
	})
	out := matches[:0]
	lastEnd := -1
	for _, m := range matches {
		if m.Start < lastEnd {
			continue
		}
		out = append(out, m)
		lastEnd = m.End
	}
	return out
}

// Contains reports whether text matches any built-in secret rule.
// It is safe for concurrent use.
func Contains(text string) bool {
	if text == "" {
		return false
	}
	rs := compiledRuleSet()
	found := rs.ac.scan(text)
	if found.empty() {
		return false
	}
	for i := range rs.rules {
		r := &rs.rules[i]
		if !found.overlaps(r.kwBits) {
			continue
		}
		re, _ := r.compile()
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// FindBytes is like [Find] but accepts a []byte. It does not copy
// the input: each returned [Match.Value] aliases b. Callers must
// not mutate b for as long as those Value strings are in use.
//
// Use this when scanning a buffer (file contents, HTTP body, log
// chunk) you'd otherwise pass through string(b) — that conversion
// always copies, FindBytes does not.
func FindBytes(b []byte) []Match {
	if len(b) == 0 {
		return nil
	}
	return Find(unsafe.String(unsafe.SliceData(b), len(b)))
}

// ContainsBytes is like [Contains] but accepts a []byte without
// copying it. b is read but never mutated.
func ContainsBytes(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return Contains(unsafe.String(unsafe.SliceData(b), len(b)))
}

// Redact returns a copy of text with every detected secret span
// replaced by [Marker]. When a rule defines a (?P<secret>…) named
// subgroup, only that span is replaced (so callers still see
// "AWS_SECRET_ACCESS_KEY=[REDACTED]"); otherwise the whole match is
// replaced.
//
// Idempotent: [Marker] does not match any rule, so calling Redact
// twice yields the same result. Safe for concurrent use.
func Redact(text string) string {
	if text == "" {
		return text
	}
	// One Aho–Corasick pass over the input gives us a mask of every
	// keyword present, so each rule's keyword check collapses to two
	// AND instructions. The mask is taken from the original input:
	// redaction can only REMOVE keywords (Marker contains none — see
	// TestMarkerIsNotASecret), so a stale "yes" after rewriting just
	// means we run a regex that won't match.
	rs := compiledRuleSet()
	found := rs.ac.scan(text)
	if found.empty() {
		return text
	}
	out := text
	for i := range rs.rules {
		r := &rs.rules[i]
		if !found.overlaps(r.kwBits) {
			continue
		}
		out = redactWithRule(r, out)
	}
	return out
}

// redactWithRule applies a single rule to text. We can't reach for
// [regexp.Regexp.ReplaceAllStringFunc] because we need the match
// indices to slice out the (?P<secret>…) subgroup while keeping the
// rest of the match intact.
func redactWithRule(r *compiledRule, text string) string {
	re, secretIdx := r.compile()

	// Probe for the first match before reaching for FindAll: that
	// avoids allocating the outer [][]int wrapper when there is at
	// most one hit (the overwhelmingly common case in real inputs).
	m := re.FindStringSubmatchIndex(text)
	if m == nil {
		return text
	}
	start, end := redactSpan(m, secretIdx)

	// Fast path: a single match collapses to a 3-way string concat
	// that allocates exactly the result buffer once. Probe the
	// remainder for a second match before committing to it.
	rest := re.FindStringSubmatchIndex(text[end:])
	if rest == nil {
		return text[:start] + Marker + text[end:]
	}

	// Multi-match path: walk the rest of the input one match at a
	// time, copying the in-between spans into a Builder.
	var b strings.Builder
	b.Grow(len(text))
	b.WriteString(text[:start])
	b.WriteString(Marker)
	cursor := end
	for m := rest; m != nil; m = re.FindStringSubmatchIndex(text[cursor:]) {
		s, e := redactSpan(m, secretIdx)
		s += cursor
		e += cursor
		b.WriteString(text[cursor:s])
		b.WriteString(Marker)
		cursor = e
	}
	b.WriteString(text[cursor:])
	return b.String()
}

// redactSpan returns the [start, end) byte offsets that should be
// replaced by [Marker] for a given regex match. When the rule
// declares a (?P<secret>…) named subgroup that participated in the
// match, only that span is replaced — preserving the framing text
// (e.g. "AWS_SECRET_ACCESS_KEY=" or "postgresql://app:") so log
// readers can still tell what was redacted. Otherwise the whole
// match span is replaced.
func redactSpan(m []int, secretIdx int) (start, end int) {
	if secretIdx >= 0 && m[2*secretIdx] >= 0 {
		return m[2*secretIdx], m[2*secretIdx+1]
	}
	return m[0], m[1]
}
