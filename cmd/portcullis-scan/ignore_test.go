package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunIgnoresBasenameGlob(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "leaky.go"),
		[]byte("token := \""+githubPAT+"\"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "leaky_test.go"),
		[]byte("token := \""+githubPAT+"\"\n"), 0o644))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-ignore", "*_test.go", root}, &stdout, &stderr)

	assert.Equal(t, exitFound, code)
	assert.Empty(t, stderr.String())
	out := stdout.String()
	assert.Contains(t, out, "leaky.go:")
	assert.NotContains(t, out, "leaky_test.go")
}

func TestRunIgnoresDirectoryTree(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "vendor", "x"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "vendor", "x", "v.go"),
		[]byte(githubPAT), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.go"),
		[]byte(githubPAT), 0o644))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-ignore", "vendor/**", root}, &stdout, &stderr)

	assert.Equal(t, exitFound, code)
	assert.Empty(t, stderr.String())
	out := stdout.String()
	assert.Contains(t, out, "main.go")
	assert.NotContains(t, out, "vendor")
}

func TestRunIgnoreFlagIsRepeatable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "node_modules"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "node_modules", "n.js"),
		[]byte(githubPAT), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "leaky_test.go"),
		[]byte(githubPAT), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.go"),
		[]byte(githubPAT), 0o644))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-ignore", "*_test.go", "-ignore", "node_modules/", root}, &stdout, &stderr)

	assert.Equal(t, exitFound, code)
	assert.Empty(t, stderr.String())
	out := stdout.String()
	assert.Contains(t, out, "main.go")
	assert.NotContains(t, out, "node_modules")
	assert.NotContains(t, out, "leaky_test.go")
}

func TestRunIgnoresAnchoredPathPattern(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "a", "secrets"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "secrets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "a", "secrets", "f.txt"),
		[]byte(githubPAT), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "secrets", "g.txt"),
		[]byte(githubPAT), 0o644))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-ignore", "secrets/**", root}, &stdout, &stderr)

	assert.Equal(t, exitFound, code)
	out := stdout.String()
	assert.Contains(t, out, filepath.Join("a", "secrets", "f.txt"))
	assert.NotContains(t, out, filepath.Join("secrets", "g.txt"))
}

func TestRunRejectsInvalidIgnorePattern(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := run([]string{"-ignore", "[bad", t.TempDir()}, &stdout, &stderr)

	assert.Equal(t, exitInvalid, code)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "invalid ignore pattern")
}

func TestIgnoreMatcher(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		patterns []string
		rel      string
		base     string
		isDir    bool
		want     bool
	}{
		{"basename star", []string{"*_test.go"}, "pkg/x_test.go", "x_test.go", false, true},
		{"basename star negative", []string{"*_test.go"}, "pkg/x.go", "x.go", false, false},
		{"path glob", []string{"vendor/**"}, "vendor/a/b.go", "b.go", false, true},
		{"path glob prunes parent", []string{"vendor/**"}, "vendor", "vendor", true, true},
		{"path glob keeps siblings", []string{"vendor/**"}, "src/a.go", "a.go", false, false},
		{"dir-only on file", []string{"node_modules/"}, "node_modules", "node_modules", false, false},
		{"dir-only on dir", []string{"node_modules/"}, "node_modules", "node_modules", true, true},
		{"double star prefix", []string{"**/foo.txt"}, "a/b/foo.txt", "foo.txt", false, true},
		{"double star prefix at root", []string{"**/foo.txt"}, "foo.txt", "foo.txt", false, true},
		{"single star is single segment", []string{"a/*.go"}, "a/b/c.go", "c.go", false, false},
		{"question mark", []string{"?.go"}, "a.go", "a.go", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := newIgnoreMatcher(tc.patterns)
			require.NoError(t, err)
			assert.Equal(t, tc.want, m.matches(tc.rel, tc.base, tc.isDir))
		})
	}
}

func TestIgnoreMatcherEmpty(t *testing.T) {
	t.Parallel()
	m, err := newIgnoreMatcher(nil)
	require.NoError(t, err)
	assert.False(t, m.matches("a/b.go", "b.go", false))
	assert.False(t, m.matches("", "", false))
}

func TestIgnoreMatcherTrimsBlankPatterns(t *testing.T) {
	t.Parallel()
	m, err := newIgnoreMatcher([]string{"", "  ", "/"})
	require.NoError(t, err)
	assert.False(t, m.matches("foo", "foo", false))
}
