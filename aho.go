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
// ASCII upper-case bytes are folded on the fly so callers don't need
// to lower-case the input.
type acAutomaton struct {
	// next is the dense (state, byte) → state table laid out as
	// next[state*256 + byte]. Storing it flat keeps every transition
	// one indirection away from a register.
	next []int32
	// accept[s] records which patterns match in state s, already
	// merged with patterns reachable via fail links so the scan loop
	// never has to walk them.
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

	return &acAutomaton{next: next, accept: accept}
}

// scan returns a kwMask of every pattern that occurs at least once
// in text. Bytes 'A'..'Z' are folded to 'a'..'z' on the fly.
func (a *acAutomaton) scan(text string) (mask kwMask) {
	// Hoist slice headers into locals so the compiler can prove the
	// (state, byte) index is in range once at function entry rather
	// than re-checking inside the hot loop.
	next, accept := a.next, a.accept
	s := int32(0)
	for i := range len(text) {
		c := text[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		s = next[int(s)*256+int(c)]
		ap := &accept[s]
		mask[0] |= ap[0]
		mask[1] |= ap[1]
		mask[2] |= ap[2]
		mask[3] |= ap[3]
	}
	return mask
}
