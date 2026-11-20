// Package portcullis detects and redacts API tokens, cloud
// credentials, and other secret material in arbitrary text.
//
// [Contains] reports whether any rule matches the input; [Find]
// returns the detected secret spans, the longest of those that
// overlap; [Redact] replaces every detected span with [Marker]
// while preserving the surrounding text. All three are safe for
// concurrent use, and [Redact] is idempotent.
//
// # Performance
//
// Detection runs in O(len(text)) per rule via Go's RE2-based
// [regexp] engine, gated by an Aho–Corasick keyword pre-filter so
// clean inputs typically don't compile or run any regex, and then
// allocate nothing. On a secret-bearing input [Redact] allocates
// for the matches it finds and the redacted copy.
//
// # Caller responsibilities
//
// portcullis intentionally does not cap input size: callers process
// inputs of widely different shapes (a chat message, a tool's
// stdout, a multi-megabyte log buffer) and can pick the right
// upper bound for their context. If the input is attacker-controlled
// and unbounded — e.g. an HTTP request body relayed through an
// untrusted intermediary — wrap the call site with the appropriate
// size limit before invoking [Redact] / [Contains].
//
// # Provenance
//
// The default ruleset is derived from the MIT-licensed
// github.com/docker/mcp-gateway/pkg/secretsscan package, which
// adapted it from github.com/aquasecurity/trivy/pkg/fanal/secret,
// extended with additional patterns for modern AI providers,
// payment processors, and infrastructure tokens.
package portcullis
