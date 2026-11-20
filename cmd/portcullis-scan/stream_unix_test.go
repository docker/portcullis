//go:build unix && !aix && !solaris

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFIFO returns the path of a FIFO that yields content to its first
// reader. A FIFO stands in for any target whose size stat can't know
// up front, such as the pipe behind `portcullis-scan <(git diff)`.
func newFIFO(t *testing.T, content string) string {
	t.Helper()

	fifo := filepath.Join(t.TempDir(), "stream")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	written := make(chan error, 1)
	go func() {
		// Blocks until the scanner opens the FIFO.
		written <- os.WriteFile(fifo, []byte(content), 0o600)
	}()
	t.Cleanup(func() {
		select {
		case err := <-written:
			assert.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("the scanner never opened the FIFO")
		}
	})
	return fifo
}

// TestRunScansStreamTarget: stat reports a pipe as 0 bytes long, which
// must not be taken to mean there is nothing to scan. -max-size applies
// to what the pipe actually delivers.
func TestRunScansStreamTarget(t *testing.T) {
	t.Parallel()

	const content = "TOKEN=" + githubPAT + "\n"
	atLimit := "-max-size=" + strconv.Itoa(len(content))

	for _, tc := range []struct {
		name    string
		flags   []string
		content string
		found   bool
	}{
		{"default", nil, content, true},
		{"binary", []string{"-binary"}, content, true},
		{"at max size", []string{atLimit}, content, true},
		{"at max size, binary", []string{atLimit, "-binary"}, content, true},
		{"above max size", []string{atLimit}, content + "\n", false},
		{"above max size, binary", []string{atLimit, "-binary"}, content + "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fifo := newFIFO(t, tc.content)

			var stdout, stderr bytes.Buffer
			code := run(append(tc.flags, fifo), &stdout, &stderr)

			assert.Empty(t, stderr.String())
			if tc.found {
				assert.Equal(t, exitFound, code)
				assert.Equal(t, fifo+":1:7: "+githubPAT+"\n", stdout.String())
			} else {
				assert.Equal(t, exitClean, code)
				assert.Empty(t, stdout.String())
			}
		})
	}
}
