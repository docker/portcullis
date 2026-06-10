package portcullis

// kwMask is a fixed-size bitset over keyword indices, used to record
// which patterns occurred in a scanned input and which keywords each
// rule subscribes to. Storing it as a small array keeps every test
// branch-free; the cap of 320 indices accommodates today's catalogue
// of ~285 unique keywords with limited remaining headroom for future
// rules (an overflow trips a deterministic panic in [buildAhoCorasick]).
type kwMask [5]uint64

func (m *kwMask) empty() bool { return m[0]|m[1]|m[2]|m[3]|m[4] == 0 }
func (m *kwMask) overlaps(other kwMask) bool {
	return m[0]&other[0]|m[1]&other[1]|m[2]&other[2]|m[3]&other[3]|m[4]&other[4] != 0
}
func (m *kwMask) set(idx int) { m[idx>>6] |= 1 << uint(idx&63) }
func (m *kwMask) orIn(other *kwMask) {
	m[0] |= other[0]
	m[1] |= other[1]
	m[2] |= other[2]
	m[3] |= other[3]
	m[4] |= other[4]
}

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
	// overlap is the longest pattern length minus one: the number of
	// bytes two adjacent shards must share so that a pattern spanning
	// the shard boundary is still seen in full by the left shard's
	// cursor (see [acAutomaton.scanSharded]).
	overlap int
}

// buildAhoCorasick compiles patterns into an automaton. Patterns
// must be lower-cased ASCII.
func buildAhoCorasick(patterns []string) *acAutomaton {
	if len(patterns) > 320 {
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
		for i := range accept[s] {
			accept[s][i] |= accept[fs][i]
		}

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

	maxLen := 0
	for _, p := range patterns {
		maxLen = max(maxLen, len(p))
	}

	return &acAutomaton{next: next, accept: accept, overlap: maxLen - 1}
}

// shardedScanMin is the input length below which [acAutomaton.scan]
// stays on the serial loop: below it the per-shard overlap and tail
// bookkeeping costs more than the extra instruction-level
// parallelism buys.
const shardedScanMin = 1024

// scan returns a kwMask of every pattern that occurs at least once
// in text. ASCII case-folding is handled by the transition table
// itself (see [buildAhoCorasick]) so the scan loop never has to
// touch the input byte before indexing.
func (a *acAutomaton) scan(text string) kwMask {
	if len(text) >= shardedScanMin {
		return a.scanSharded(text)
	}
	return a.scanSerial(text)
}

// scanSerial walks the whole input with a single cursor. It is the
// fastest option for short inputs, where its root-skip fast loop
// shines and sharding overhead would dominate.
func (a *acAutomaton) scanSerial(text string) (mask kwMask) {
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
			mask[4] |= ap[4]
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
				mask[4] |= ap[4]
			}
		}
	}
	return mask
}

// scanSharded splits the input into eight shards and advances eight
// independent automaton cursors in lockstep inside one loop. A
// single cursor is latency-bound: each byte's table lookup depends
// on the state produced by the previous lookup, so the CPU stalls
// for the full load latency on every byte. Eight interleaved
// dependency chains let those loads overlap, lifting throughput
// well past the serial loop on inputs long enough to amortise the
// setup (see [shardedScanMin]).
//
// Adjacent shards overlap by [acAutomaton.overlap] bytes (longest
// pattern minus one) so a pattern spanning a shard boundary is still
// fully traversed by the left shard's cursor. Duplicated hits are
// harmless: the result is a set union.
//
// The hot loop carries no accept bookkeeping at all: on any accept
// hit it breaks out, lets the cold block below OR in the accept
// masks, and resumes. accept[s] is empty for every non-accepting
// state, so blindly OR-ing all eight cursors' entries there is a
// no-op for the cursors that didn't hit. Keeping the loop body down
// to eight loads plus register-only ALU ops is what lets the eight
// chains actually retire one byte per chain per load-latency window;
// an in-loop branch ladder costs enough spills to halve the win.
func (a *acAutomaton) scanSharded(text string) (mask kwMask) {
	next, accept := a.next, a.accept
	n := len(text)
	size := (n + 7) / 8
	ov := a.overlap

	// All eight cursors advance one byte per iteration; run until the
	// shortest shard (the last one) is exhausted, then let scanFrom
	// finish the leftover tails (a few dozen bytes each) serially.
	steps := min(n-7*size, size+ov)

	s2, s3, s4, s5, s6, s7 := 2*size, 3*size, 4*size, 5*size, 6*size, 7*size
	var o0, o1, o2, o3, o4, o5, o6, o7 uint32
	k := 0
	for k < steps {
		for k < steps {
			r0 := next[o0+uint32(text[k])]
			r1 := next[o1+uint32(text[k+size])]
			r2 := next[o2+uint32(text[k+s2])]
			r3 := next[o3+uint32(text[k+s3])]
			r4 := next[o4+uint32(text[k+s4])]
			r5 := next[o5+uint32(text[k+s5])]
			r6 := next[o6+uint32(text[k+s6])]
			r7 := next[o7+uint32(text[k+s7])]
			o0, o1, o2, o3 = r0&^acceptBit, r1&^acceptBit, r2&^acceptBit, r3&^acceptBit
			o4, o5, o6, o7 = r4&^acceptBit, r5&^acceptBit, r6&^acceptBit, r7&^acceptBit
			k++
			if (r0|r1|r2|r3|r4|r5|r6|r7)&acceptBit != 0 {
				break
			}
		}
		// Cold path: at least one cursor sits on an accepting state.
		// accept[] is empty for the others, so no per-cursor test is
		// needed.
		mask.orIn(&accept[o0>>stateShift])
		mask.orIn(&accept[o1>>stateShift])
		mask.orIn(&accept[o2>>stateShift])
		mask.orIn(&accept[o3>>stateShift])
		mask.orIn(&accept[o4>>stateShift])
		mask.orIn(&accept[o5>>stateShift])
		mask.orIn(&accept[o6>>stateShift])
		mask.orIn(&accept[o7>>stateShift])
	}

	a.scanFrom(o0, text, k, min(size+ov, n), &mask)
	a.scanFrom(o1, text, size+k, min(s2+ov, n), &mask)
	a.scanFrom(o2, text, s2+k, min(s3+ov, n), &mask)
	a.scanFrom(o3, text, s3+k, min(s4+ov, n), &mask)
	a.scanFrom(o4, text, s4+k, min(s5+ov, n), &mask)
	a.scanFrom(o5, text, s5+k, min(s6+ov, n), &mask)
	a.scanFrom(o6, text, s6+k, min(s7+ov, n), &mask)
	a.scanFrom(o7, text, s7+k, n, &mask)
	return mask
}

// scanFrom continues a scan from state offset off over
// text[i:limit], OR-ing accept hits into mask. Used for the short
// shard tails left over by [acAutomaton.scanSharded].
func (a *acAutomaton) scanFrom(off uint32, text string, i, limit int, mask *kwMask) {
	next, accept := a.next, a.accept
	for ; i < limit; i++ {
		raw := next[off+uint32(text[i])]
		off = raw &^ acceptBit
		if raw&acceptBit != 0 {
			mask.orIn(&accept[off>>stateShift])
		}
	}
}
