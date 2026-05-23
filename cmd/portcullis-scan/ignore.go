package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ignoreMatcher decides whether a path should be skipped during the
// walk. Patterns use a small gitignore-flavoured glob syntax:
//
//   - "*"  matches any run of non-separator characters
//   - "?"  matches a single non-separator character
//   - "**" matches any run of characters, including separators
//   - "[...]" character class (passed through to the regexp engine)
//
// A pattern containing "/" is anchored to the scan root and matched
// against the slash-separated relative path; otherwise it matches
// the basename of every entry. A trailing "/" restricts the rule to
// directories. A "X/**" rule also prunes "X" itself so its subtree
// is not walked.
type ignoreMatcher struct {
	rules []ignoreRule
}

type ignoreRule struct {
	re       *regexp.Regexp
	pathMode bool // match against rel path; otherwise basename
	dirOnly  bool
}

func newIgnoreMatcher(patterns []string) (*ignoreMatcher, error) {
	m := &ignoreMatcher{}
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		dirOnly := strings.HasSuffix(p, "/")
		p = strings.TrimSuffix(p, "/")
		p = strings.TrimPrefix(p, "/")
		if p == "" {
			continue
		}
		pathMode := strings.Contains(p, "/")
		re, err := compileGlob(p)
		if err != nil {
			return nil, fmt.Errorf("invalid ignore pattern %q: %w", raw, err)
		}
		m.rules = append(m.rules, ignoreRule{re: re, pathMode: pathMode, dirOnly: dirOnly})

		// "X/**" prunes everything *inside* X. Add a sibling rule
		// that matches X itself so the walker can SkipDir early.
		if parent, ok := strings.CutSuffix(p, "/**"); ok && parent != "" {
			parentRe, err := compileGlob(parent)
			if err != nil {
				return nil, fmt.Errorf("invalid ignore pattern %q: %w", raw, err)
			}
			// Inherit the original rule's anchoring so a path-mode
			// pattern like "secrets/**" doesn't degrade into a
			// basename rule that prunes every "secrets" directory.
			m.rules = append(m.rules, ignoreRule{
				re:       parentRe,
				pathMode: pathMode,
				dirOnly:  true,
			})
		}
	}
	return m, nil
}

// matches reports whether the entry (rel path, basename) is ignored.
// rel must use forward slashes.
func (m *ignoreMatcher) matches(rel, base string, isDir bool) bool {
	if m == nil || len(m.rules) == 0 {
		return false
	}
	for _, r := range m.rules {
		if r.dirOnly && !isDir {
			continue
		}
		target := base
		if r.pathMode {
			target = rel
		}
		if r.re.MatchString(target) {
			return true
		}
	}
	return false
}

// compileGlob translates a glob pattern into an anchored regexp.
// "**" matches any sequence of characters (including "/"); "*" and
// "?" stay within a single path segment.
func compileGlob(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); {
		c := pattern[i]
		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				// "**/X" → any (possibly empty) run of leading dirs.
				if i+2 < len(pattern) && pattern[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 3
					continue
				}
				b.WriteString(".*")
				i += 2
				continue
			}
			b.WriteString("[^/]*")
			i++
		case '?':
			b.WriteString("[^/]")
			i++
		case '[':
			j := i + 1
			for j < len(pattern) && pattern[j] != ']' {
				j++
			}
			if j >= len(pattern) {
				return nil, errors.New("unmatched '['")
			}
			b.WriteString(pattern[i : j+1])
			i = j + 1
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
			i++
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// stringSliceFlag collects repeated -flag VALUE invocations.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}
