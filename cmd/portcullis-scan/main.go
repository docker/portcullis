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
// Files are scanned in parallel; output order matches the walker's
// lexical order, so two runs over the same tree produce identical
// output regardless of worker count or scheduling.
//
// Usage:
//
//	portcullis-scan [flags] <path>
//
// Flags:
//
//	-max-size    skip files larger than this many bytes (default 10 MiB).
//	-workers     parallel worker count (default GOMAXPROCS).
//	-ignore      glob pattern to skip; repeatable. Patterns containing
//	             '/' are anchored to the scan root, others match
//	             basenames. '**' matches any run of characters,
//	             including separators. Trailing '/' restricts the
//	             rule to directories. Examples: -ignore '*_test.go'
//	             -ignore 'vendor/**' -ignore 'node_modules/'
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
	var ignore stringSliceFlag
	flags.Var(&ignore, "ignore", "glob pattern to skip (repeatable); e.g. '*_test.go' or 'vendor/**'")

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

	matcher, err := newIgnoreMatcher(ignore)
	if err != nil {
		fmt.Fprintf(stderr, "portcullis-scan: %v\n", err)
		return exitInvalid
	}

	found, err := scan(root, *maxSize, *workers, matcher, stdout, stderr)
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
// its own file pays for itself trivially. Output order matches the
// walker's lexical order: the walker tags each file with a sequence
// number, workers preserve it, and the collector reorders results
// before writing so the output is deterministic across runs.
func scan(root string, maxSize int64, workers int, ignore *ignoreMatcher, out, errOut io.Writer) (bool, error) {
	info, err := os.Stat(root)
	if err != nil {
		return false, err
	}

	// Single-file target: no need to spin up the pool.
	if !info.IsDir() {
		return scanFile(root, root, maxSize, out, errOut)
	}

	type job struct {
		seq  int
		path string
	}
	type result struct {
		seq int
		buf []byte // nil when the file produced no matches
	}

	jobs := make(chan job, workers*4)
	results := make(chan result, workers*4)

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for j := range jobs {
				results <- result{seq: j.seq, buf: scanFileBytes(j.path, root, maxSize, errOut)}
			}
		})
	}

	// Walker: emit a job per regular file and close the queue when
	// done so workers can drain.
	walkErrCh := make(chan error, 1)
	go func() {
		defer close(jobs)
		seq := 0
		walkErrCh <- filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				fmt.Fprintf(errOut, "portcullis-scan: %s: %v\n", path, err)
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if path != root && ignore != nil {
				rel, relErr := filepath.Rel(root, path)
				if relErr == nil {
					rel = filepath.ToSlash(rel)
					if ignore.matches(rel, d.Name(), d.IsDir()) {
						if d.IsDir() {
							return filepath.SkipDir
						}
						return nil
					}
				}
			}
			if !d.Type().IsRegular() {
				return nil
			}
			jobs <- job{seq: seq, path: path}
			seq++
			return nil
		})
	}()

	// Reaper: close `results` once all workers drain.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collector: emit chunks in walker (sequence) order. Out-of-order
	// results are stashed in a small reorder buffer keyed by seq;
	// each contiguous run is flushed as soon as the missing prefix
	// arrives.
	pending := make(map[int][]byte)
	nextSeq := 0
	var found bool
	write := func(buf []byte) error {
		if len(buf) == 0 {
			return nil
		}
		found = true
		_, err := out.Write(buf)
		return err
	}
	for r := range results {
		if r.seq != nextSeq {
			pending[r.seq] = r.buf
			continue
		}
		if err := write(r.buf); err != nil {
			return found, err
		}
		nextSeq++
		for {
			buf, ok := pending[nextSeq]
			if !ok {
				break
			}
			delete(pending, nextSeq)
			if err := write(buf); err != nil {
				return found, err
			}
			nextSeq++
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
