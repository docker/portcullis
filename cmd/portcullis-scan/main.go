// Command portcullis-scan walks a directory tree and prints every
// secret occurrence found in regular files, as detected by
// [portcullis.Find].
//
// Output is grep-like, one match per line:
//
//	<path>:<line>:<col>: <value>
//
// Paths are relative to the scan root. Newlines and carriage returns
// inside a matched value are collapsed to spaces so each match
// remains on a single line; this only affects display, not detection.
// Files are scanned in parallel; matches inside a single file stay
// in left-to-right order, but cross-file output order is not
// guaranteed.
//
// Usage:
//
//	portcullis-scan [flags] <path>
//
// Flags:
//
//	-max-size    skip files larger than this many bytes (default 10 MiB).
//	-workers     parallel worker count (default GOMAXPROCS).
//
// Exit codes:
//
//	0  scan completed; no secrets found.
//	1  scan completed; at least one secret was found.
//	2  invocation error (bad flags, unreadable root, etc.).
package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/docker/portcullis"
)

const (
	exitClean   = 0
	exitFound   = 1
	exitInvalid = 2

	defaultMaxSize int64 = 10 << 20 // 10 MiB
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("portcullis-scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintf(stderr, "usage: portcullis-scan [flags] <path>\n\n")
		flags.PrintDefaults()
	}

	maxSize := flags.Int64("max-size", defaultMaxSize, "skip files larger than this many bytes (0 disables the limit)")
	workers := flags.Int("workers", runtime.GOMAXPROCS(0), "parallel worker count")

	if err := flags.Parse(args); err != nil {
		return exitInvalid
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return exitInvalid
	}
	if *workers < 1 {
		*workers = 1
	}
	root := flags.Arg(0)

	found, err := scan(root, *maxSize, *workers, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "portcullis-scan: %v\n", err)
		return exitInvalid
	}
	if found {
		return exitFound
	}
	return exitClean
}

// scan walks root and writes one line per detected secret. It
// returns true if at least one secret was found.
//
// Files are processed by `workers` goroutines fed from a channel.
// Regex matching dominates the cost (>80% of CPU on real
// repositories) and is single-threaded per call, so giving each core
// its own file pays for itself trivially. Output for a single file
// stays contiguous because one file is owned by one worker; the
// cross-file order is whatever the workers happen to finish in.
func scan(root string, maxSize int64, workers int, out, errOut io.Writer) (bool, error) {
	info, err := os.Stat(root)
	if err != nil {
		return false, err
	}

	// Single-file target: no need to spin up the pool.
	if !info.IsDir() {
		return scanFile(root, root, maxSize, out, errOut)
	}

	paths := make(chan string, workers*4)
	// One slot per file emits 0..n lines; buffering matches `paths`
	// so a slow stdout doesn't stall the workers.
	results := make(chan []byte, workers*4)

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for path := range paths {
				if buf := scanFileBytes(path, root, maxSize, errOut); buf != nil {
					results <- buf
				}
			}
		})
	}

	// Walker: push every regular file's path into the queue and
	// close the queue when done so workers can drain.
	walkErrCh := make(chan error, 1)
	go func() {
		defer close(paths)
		walkErrCh <- filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				fmt.Fprintf(errOut, "portcullis-scan: %s: %v\n", path, err)
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			paths <- path
			return nil
		})
	}()

	// Collector: close `results` once all workers are done.
	go func() {
		wg.Wait()
		close(results)
	}()

	var found bool
	for buf := range results {
		found = true
		if _, err := out.Write(buf); err != nil {
			// Drain so producers don't block forever.
			go func() {
				for range results {
				}
			}()
			return found, err
		}
	}
	return found, <-walkErrCh
}

// scanFile is the single-file fast path used when the CLI target is
// a file rather than a directory.
func scanFile(path, root string, maxSize int64, out, errOut io.Writer) (bool, error) {
	buf := scanFileBytes(path, root, maxSize, errOut)
	if buf == nil {
		return false, nil
	}
	_, err := out.Write(buf)
	return true, err
}

// scanFileBytes reads path, runs [portcullis.Find] on its contents,
// and returns a pre-formatted output chunk (one `path:line:col: value`
// line per match, all in one allocation). It returns nil if there
// are no matches or the file was skipped.
func scanFileBytes(path, root string, maxSize int64, errOut io.Writer) []byte {
	data, ok, err := readIfSmall(path, maxSize)
	if err != nil {
		fmt.Fprintf(errOut, "portcullis-scan: %s: %v\n", path, err)
		return nil
	}
	if !ok {
		return nil
	}
	matches := portcullis.Find(string(data))
	if len(matches) == 0 {
		return nil
	}
	display := path
	if rel, relErr := filepath.Rel(root, path); relErr == nil && rel != "." {
		display = rel
	}
	var b strings.Builder
	for _, m := range matches {
		line, col := lineCol(data, m.Start)
		fmt.Fprintf(&b, "%s:%d:%d: %s\n", display, line, col, sanitizeValue(m.Value))
	}
	return []byte(b.String())
}

// readIfSmall reads path's contents unless it exceeds maxSize, in
// which case ok is false and data is nil.
func readIfSmall(path string, maxSize int64) (data []byte, ok bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if maxSize > 0 && st.Size() > maxSize {
		return nil, false, nil
	}
	data, err = io.ReadAll(f)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// lineCol returns the 1-based line and column for offset within data.
// Column counts bytes since the last newline.
func lineCol(data []byte, offset int) (line, col int) {
	if offset > len(data) {
		offset = len(data)
	}
	line = 1
	last := -1
	for i := range offset {
		if data[i] == '\n' {
			line++
			last = i
		}
	}
	return line, offset - last
}

// sanitizeValue collapses CR / LF in v so a multi-line match (e.g. a
// PEM block) stays on a single output line.
func sanitizeValue(v string) string {
	if !strings.ContainsAny(v, "\r\n") {
		return v
	}
	r := strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")
	return r.Replace(v)
}
