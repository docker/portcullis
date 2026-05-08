package portcullis

// kwMask is a fixed-size bitset over keyword indices, used to record
// which patterns occurred in a scanned input and which keywords each
// rule subscribes to. Storing it as a small array keeps every test
// branch-free; the cap of 256 indices accommodates today's catalogue
// of ~175 unique keywords with comfortable headroom for future rules
// (an overflow trips a deterministic panic in [buildAhoCorasick]).
type kwMask [4]uint64

func (m *kwMask) empty() bool { return m[0]|m[1]|m[2]|m[3] == 0 }
func (m *kwMask) overlaps(other kwMask) bool {
	return m[0]&other[0]|m[1]&other[1]|m[2]&other[2]|m[3]&other[3] != 0
}
func (m *kwMask) set(idx int) { m[idx>>6] |= 1 << uint(idx&63) }

// acceptBit is set in a [acAutomaton.next] cell when the destination
// state has at least one accepting pattern (directly or via fail
// links). Folding the flag into the same word as the transition
// turns the "did we just enter an accepting state?" test into a
// register-only AND on a value the scan loop has already loaded,
// removing the per-byte read of a separate hasMatch bitmap.
const acceptBit uint32 = 1 << 31

// stateShift converts between a state index and its row offset in
// [acAutomaton.next]. Cells store the destination state pre-multiplied
// by 256 so the slow loop's index becomes a plain `off + byte`,
// saving a shift on the data-dependency chain that feeds the next
// load. The state itself is recovered (only on accept hits) via
// `off >> stateShift`.
const stateShift = 8

// acAutomaton is an Aho–Corasick keyword pre-filter for [Redact] and
// [Contains]. A single linear pass over the input yields a [kwMask]
// of every keyword that occurs, after which each rule can decide
// whether to run its (relatively expensive) regex with two AND
// instructions instead of one [strings.Contains] call per keyword.
// ASCII case-folding is baked into the transition table so callers
// don't need to lower-case the input.
type acAutomaton struct {
	// next is the dense (state, byte) → state table laid out as
	// next[state*256 + byte]. Each cell packs two things: bits
	// 0..30 hold the destination's *row offset* (state << 8, ready
	// to be added to the next input byte), and bit 31 ([acceptBit])
	// is set when that destination has a non-empty [accept] entry.
	// Storing the offset rather than the bare state lets the slow
	// loop drop the `s*256` multiplication that used to sit on the
	// load-to-load critical path; the state index is only needed to
	// recover [accept] on the ~10% of bytes that hit an accepting
	// transition, where one shift is amortised by the work that
	// follows.
	next []uint32
	// accept[s] records which patterns match in state s, already
	// merged with patterns reachable via fail links so the scan loop
	// never has to walk them. The slow loop only touches this slice
	// for the ~10% of bytes whose transition has [acceptBit] set,
	// so on real-world inputs accept[] effectively stays cold.
	accept []kwMask
}

// buildAhoCorasick compiles patterns into an automaton. Patterns
// must be lower-cased ASCII.
func buildAhoCorasick(patterns []string) *acAutomaton {
	if len(patterns) > 256 {
		panic("portcullis: too many AC patterns for kwMask")
	}

	// Stage 1: build the trie sparsely. Each node knows its children
	// and which patterns terminate there.
	type tnode struct {
		children map[byte]uint32
		terms    kwMask
	}
	trie := []*tnode{{children: map[byte]uint32{}}}
	for idx, p := range patterns {
		cur := uint32(0)
		for i := range len(p) {
			c := p[i]
			child, ok := trie[cur].children[c]
			if !ok {
				child = uint32(len(trie))
				trie = append(trie, &tnode{children: map[byte]uint32{}})
				trie[cur].children[c] = child
			}
			cur = child
		}
		trie[cur].terms.set(idx)
	}

	// Stage 2: materialise the dense delta(state, byte) table by BFS
	// over the trie. Visiting in depth order means a state's fail
	// target is fully populated by the time we reach it, so we can
	// inherit its transitions wholesale and then overwrite the slots
	// for which the current state has its own children.
	n := len(trie)
	next := make([]uint32, n*256)
	accept := make([]kwMask, n)
	fail := make([]uint32, n)

	accept[0] = trie[0].terms
	for c, child := range trie[0].children {
		next[c] = child << stateShift
	}

	queue := make([]uint32, 0, n)
	for _, child := range trie[0].children {
		queue = append(queue, child) // fail[child] = 0 (root) by zero-init
	}
	for head := 0; head < len(queue); head++ {
		s := queue[head]
		fs := fail[s]
		accept[s] = trie[s].terms
		accept[s][0] |= accept[fs][0]
		accept[s][1] |= accept[fs][1]
		accept[s][2] |= accept[fs][2]
		accept[s][3] |= accept[fs][3]

		base, fbase := s<<stateShift, fs<<stateShift
		copy(next[base:base+256], next[fbase:fbase+256])
		for c, u := range trie[s].children {
			// fail[u] is "what fs would do on c". next[] holds row
			// offsets, so shift back to a state index for fail[].
			fail[u] = next[fbase+uint32(c)] >> stateShift
			next[base+uint32(c)] = u << stateShift
			queue = append(queue, u)
		}
	}

	// Stage 3: bake ASCII case-folding into the transition table so
	// the scan loop never has to touch the input byte. For every
	// state, alias the 'A'..'Z' transitions to whatever the state
	// does on 'a'..'z'. This is correct because patterns are
	// lower-case ASCII, so the trie/fail chain only ever populates
	// lowercase entries; the uppercase slots were left at zero (stay
	// at root).
	for s := range n {
		base := s * 256
		for c := byte('a'); c <= 'z'; c++ {
			next[base+int(c-'a'+'A')] = next[base+int(c)]
		}
	}

	// Stage 4: fold an "accept-here" bit into every transition cell
	// whose destination state has a non-empty accept entry. The scan
	// loop can then test for matches with a single AND on the value
	// it has just loaded, instead of reading a separate hasMatch
	// bitmap (the previous design). Note that root (state 0) has an
	// empty accept by construction, so cells holding 0 ("stay at
	// root") never get the bit set — preserving the fast loop's
	// next[byte] == 0 check.
	for i, off := range next {
		if !accept[off>>stateShift].empty() {
			next[i] = off | acceptBit
		}
	}

	return &acAutomaton{next: next, accept: accept}
}

// scan returns a kwMask of every pattern that occurs at least once
// in text. ASCII case-folding is handled by the transition table
// itself (see [buildAhoCorasick]) so the scan loop never has to
// touch the input byte before indexing.
func (a *acAutomaton) scan(text string) (mask kwMask) {
	// Hoist slice headers into locals so the compiler can prove the
	// (state, byte) index is in range once at function entry rather
	// than re-checking inside the hot loop.
	next, accept := a.next, a.accept
	n := len(text)
	i := 0
	for i < n {
		// Fast loop: stay at root and skip bytes that can't begin
		// any pattern. Cells holding 0 encode "go to root, no
		// accepts" (root has no accepts by construction), so neither
		// the destination state nor the accept bit needs to be
		// extracted here — close to memchr-grade throughput on the
		// overwhelmingly common clean-input path.
		for i < n && next[text[i]] == 0 {
			i++
		}
		if i >= n {
			return mask
		}
		// Slow loop: we just entered a non-root state, so accumulate
		// matches until the automaton drops back to the root. Then
		// the outer loop hands control back to the fast scan.
		//
		// Each transition cell carries an [acceptBit] in its high
		// bit when the destination state has matches; the OR-into-
		// mask path is gated behind that single AND on the same
		// value we just loaded for the next-state lookup. No second
		// memory load is needed on the ~90% of bytes whose
		// destination has nothing to contribute.
		raw := next[text[i]]
		off := raw &^ acceptBit
		i++
		if raw&acceptBit != 0 {
			ap := &accept[off>>stateShift]
			mask[0] |= ap[0]
			mask[1] |= ap[1]
			mask[2] |= ap[2]
			mask[3] |= ap[3]
		}
		for i < n && off != 0 {
			raw = next[off+uint32(text[i])]
			off = raw &^ acceptBit
			i++
			if raw&acceptBit != 0 {
				ap := &accept[off>>stateShift]
				mask[0] |= ap[0]
				mask[1] |= ap[1]
				mask[2] |= ap[2]
				mask[3] |= ap[3]
			}
		}
	}
	return mask
}
