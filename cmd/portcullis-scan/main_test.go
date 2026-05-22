package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Token shaped like a real GitHub PAT. Split across concatenation so
// the literal value never appears on a single source line.
const githubPAT = "ghp_" + "cxLeRrvbJfmYdUtr70xnNE3Q7Gvli43s19PD"

func TestRunPrintsEachSecretFound(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "clean.txt"), []byte("nothing to see"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "leaky.env"),
		[]byte("FIRST="+githubPAT+"\nSECOND="+githubPAT+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "nested.txt"),
		[]byte("config: "+githubPAT), 0o644))

	var stdout, stderr bytes.Buffer
	code := run([]string{root}, &stdout, &stderr)

	assert.Equal(t, exitFound, code)
	assert.Empty(t, stderr.String())

	out := stdout.String()
	assert.Contains(t, out, "leaky.env:1:7: "+githubPAT)
	assert.Contains(t, out, "leaky.env:2:8: "+githubPAT)
	assert.Contains(t, out, filepath.Join("sub", "nested.txt")+":1:9: "+githubPAT)
	assert.NotContains(t, out, "clean.txt")
	assert.Equal(t, 3, strings.Count(out, "\n"))
}

func TestRunReturnsZeroWhenNoSecrets(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "b.txt"), []byte("world"), 0o644))

	var stdout, stderr bytes.Buffer
	code := run([]string{root}, &stdout, &stderr)

	assert.Equal(t, exitClean, code)
	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())
}

func TestRunHandlesSingleFileTarget(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	leaky := filepath.Join(dir, "leaky.txt")
	require.NoError(t, os.WriteFile(leaky, []byte(githubPAT), 0o644))

	var stdout, stderr bytes.Buffer
	code := run([]string{leaky}, &stdout, &stderr)

	assert.Equal(t, exitFound, code)
	assert.Equal(t, leaky+":1:1: "+githubPAT+"\n", stdout.String())
}

func TestRunSkipsFilesAboveMaxSize(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "big.txt"),
		[]byte(githubPAT+strings.Repeat("x", 1024)), 0o644))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-max-size=64", root}, &stdout, &stderr)

	assert.Equal(t, exitClean, code)
	assert.Empty(t, stdout.String())
}

func TestRunRejectsMissingArguments(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)

	assert.Equal(t, exitInvalid, code)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "usage:")
}

func TestRunReportsMissingRoot(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := run([]string{filepath.Join(t.TempDir(), "does-not-exist")}, &stdout, &stderr)

	assert.Equal(t, exitInvalid, code)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "portcullis-scan:")
}

func TestRunSanitisesMultilineSecrets(t *testing.T) {
	t.Parallel()

	pem := "-----BEGIN PRIVATE KEY-----\nABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/==\n-----END PRIVATE KEY-----"
	root := t.TempDir()
	path := filepath.Join(root, "key.pem")
	require.NoError(t, os.WriteFile(path, []byte(pem), 0o644))

	var stdout, stderr bytes.Buffer
	code := run([]string{root}, &stdout, &stderr)

	assert.Equal(t, exitFound, code)
	out := stdout.String()
	assert.Equal(t, 1, strings.Count(out, "\n"), "value must not introduce extra newlines: %q", out)
	assert.NotContains(t, strings.TrimSuffix(out, "\n"), "\n")
}

// TestRunOutputIsDeterministic pins the contract that two runs over
// the same tree must produce byte-identical output, regardless of
// worker count or scheduling. The collector reorders worker results
// into walker (lexical) order so concurrency is invisible to the
// caller — a property scripts and CI diffs depend on.
func TestRunOutputIsDeterministic(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		require.NoError(t, os.WriteFile(
			filepath.Join(root, name+".env"),
			[]byte("TOKEN="+githubPAT+"\n"),
			0o644,
		))
	}

	runOnce := func(workers string) string {
		var stdout, stderr bytes.Buffer
		code := run([]string{"-workers=" + workers, root}, &stdout, &stderr)
		require.Equal(t, exitFound, code)
		require.Empty(t, stderr.String())
		return stdout.String()
	}

	want := runOnce("1")
	require.NotEmpty(t, want)

	// Many workers: scheduling can finish files in any order, but
	// the collector must hand them back in walker order anyway.
	for range 8 {
		assert.Equal(t, want, runOnce("8"),
			"output must be byte-identical across runs / worker counts")
	}
}
