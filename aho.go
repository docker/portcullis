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

// acAutomaton is an Aho–Corasick keyword pre-filter for [Redact] and
// [Contains]. A single linear pass over the input yields a [kwMask]
// of every keyword that occurs, after which each rule can decide
// whether to run its (relatively expensive) regex with two AND
// instructions instead of one [strings.Contains] call per keyword.
// ASCII case-folding is baked into the transition table so callers
// don't need to lower-case the input.
type acAutomaton struct {
	// next is the dense (state, byte) → state table laid out as
	// next[state*256 + byte]. Storing it flat keeps every transition
	// one indirection away from a register.
	next []int32
	// accept[s] records which patterns match in state s, already
	// merged with patterns reachable via fail links so the scan loop
	// never has to walk them.
	accept []kwMask
	// hasMatch is a compact bitmap of "states whose accept entry is
	// non-empty". The vast majority of AC states are pass-through
	// (no pattern terminates there and none reaches via fail
	// links), so consulting this bitmap before doing the four
	// 8-byte loads + ORs against [acAutomaton.accept] elides the
	// work for ~90% of slow-loop bytes. The bitmap is one bit per
	// state (~145 bytes for today's catalogue) so it stays
	// resident in L1 even when the (much larger) accept[] table
	// would spill to L2.
	hasMatch []uint64
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
		children map[byte]int32
		terms    kwMask
	}
	trie := []*tnode{{children: map[byte]int32{}}}
	for idx, p := range patterns {
		cur := int32(0)
		for i := range len(p) {
			c := p[i]
			child, ok := trie[cur].children[c]
			if !ok {
				child = int32(len(trie))
				trie = append(trie, &tnode{children: map[byte]int32{}})
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
	next := make([]int32, n*256)
	accept := make([]kwMask, n)
	fail := make([]int32, n)

	accept[0] = trie[0].terms
	for c, child := range trie[0].children {
		next[c] = child
	}

	queue := make([]int32, 0, n)
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

		base, fbase := int(s)*256, int(fs)*256
		copy(next[base:base+256], next[fbase:fbase+256])
		for c, u := range trie[s].children {
			// fail[u] is "what fs would do on c", which we read
			// before overwriting the slot for our own child.
			fail[u] = next[fbase+int(c)]
			next[base+int(c)] = u
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

	// Stage 4: compact "has match" bitmap. Loading [kwMask] (32
	// bytes) into the OR pipeline on every slow-loop byte is the
	// single most expensive thing the scan does on real-world
	// inputs (cf. pprof line attribution); gating that load behind
	// a 1-bit check against this bitmap is a near-pure win because
	// the bitmap is two orders of magnitude smaller than
	// [acAutomaton.accept] and stays in L1.
	hasMatch := make([]uint64, (n+63)/64)
	for s := range n {
		if !accept[s].empty() {
			hasMatch[s>>6] |= 1 << uint(s&63)
		}
	}

	return &acAutomaton{next: next, accept: accept, hasMatch: hasMatch}
}

// scan returns a kwMask of every pattern that occurs at least once
// in text. ASCII case-folding is handled by the transition table
// itself (see [buildAhoCorasick]) so the scan loop never has to
// touch the input byte before indexing.
func (a *acAutomaton) scan(text string) (mask kwMask) {
	// Hoist slice headers into locals so the compiler can prove the
	// (state, byte) index is in range once at function entry rather
	// than re-checking inside the hot loop.
	next, accept, hasMatch := a.next, a.accept, a.hasMatch
	n := len(text)
	i := 0
	for i < n {
		// Fast loop: stay at root and skip bytes that can't begin
		// any pattern. accept[0] is empty by construction (no
		// pattern ends at root), so the OR ops would be no-ops here
		// anyway. Skipping the read of accept[0] entirely keeps the
		// inner loop down to one bounds-checked memory load and one
		// branch per byte — close to memchr-grade throughput on the
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
		// The OR-into-mask path is gated behind the [hasMatch]
		// bitmap: most non-root states are pass-through (no pattern
		// terminates there or reaches via fail), so loading the
		// 32-byte accept entry would just OR zeroes into the mask.
		// Skipping that load on the ~90% of bytes where it's empty
		// is the dominant slow-loop optimisation.
		s := next[text[i]]
		i++
		if hasMatch[s>>6]>>uint(s&63)&1 != 0 {
			ap := &accept[s]
			mask[0] |= ap[0]
			mask[1] |= ap[1]
			mask[2] |= ap[2]
			mask[3] |= ap[3]
		}
		for i < n && s != 0 {
			s = next[int(s)*256+int(text[i])]
			i++
			if hasMatch[s>>6]>>uint(s&63)&1 != 0 {
				ap := &accept[s]
				mask[0] |= ap[0]
				mask[1] |= ap[1]
				mask[2] |= ap[2]
				mask[3] |= ap[3]
			}
		}
	}
	return mask
}
