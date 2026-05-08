# portcullis

[![Go Reference](https://pkg.go.dev/badge/github.com/docker/portcullis.svg)](https://pkg.go.dev/github.com/docker/portcullis)

A tiny Go library that detects and redacts API tokens, cloud
credentials, and other secret material in arbitrary text.

```go
import "github.com/docker/portcullis"

clean := portcullis.Redact("Run this with token=ghp_cxLeRrvbJfmYdUtr70xnNE3Q7Gvli43s19PD please.")
// → "Run this with token=[REDACTED] please."

portcullis.Contains("not a secret")                                   // false
portcullis.Contains("token=ghp_cxLeRrvbJfmYdUtr70xnNE3Q7Gvli43s19PD") // true
```

## Why

LLM agents, log pipelines, error reporters, and anything else that
echoes user-controlled or tool-produced text back into a third party
need to scrub credentials before they leak. `portcullis` is the
extracted, dependency-free core of the redactor used by
[`docker-agent`](https://github.com/docker/docker-agent), built around
two design constraints:

- **Cheap on clean input.** A single Aho–Corasick pass over the input
  yields a bitset of every keyword present, after which each rule's
  keyword check collapses to two `AND` instructions. Most messages
  never pay for a regex.
- **Idempotent.** The default marker `[REDACTED]` is chosen so it does
  not match any built-in rule; redacting an already-redacted string is
  a no-op, and pipelines that scrub at multiple stages don't amplify.

## Install

```sh
go get github.com/docker/portcullis
```

Requires Go 1.22+.

## API

The public surface is intentionally tiny:

```go
const Marker = "[REDACTED]"

func Contains(text string) bool   // detect
func Redact(text string) string   // scrub
```

Both functions are safe for concurrent use. The compiled rule set and
its Aho–Corasick automaton are built once on first call and shared
across goroutines.

## What it detects

The built-in catalogue covers ~140 patterns spanning:

- Cloud providers — AWS, GCP service accounts, Azure Storage,
  DigitalOcean, Tencent, Alibaba.
- Source forges — GitHub (PAT / OAuth / app / fine-grained / refresh),
  GitLab, Bitbucket, Docker Hub (PAT / OAT), JFrog, Sonar.
- LLM / AI providers — OpenAI, Anthropic, Google (AIza), xAI / Grok,
  Cohere, Groq, Perplexity, Replicate, OpenRouter, Hugging Face.
- Payment processors — Stripe (publishable / secret / restricted /
  webhook), Razorpay, Adyen, Plaid, Square.
- Communication & ops — Slack (legacy & rotating), Discord (bot &
  webhook), Telegram, Twilio, SendGrid, Mailgun, Mailchimp.
- Infra & tooling — HashiCorp Vault (service / batch / recovery),
  Terraform Cloud, Tailscale, Doppler, 1Password service accounts,
  Vercel, Netlify, Render, Fly.io, Cloudflare Origin CA, Akamai,
  PlanetScale, Supabase, MongoDB / Postgres connection-string passwords,
  PEM private keys, JWTs, and more.

Connection-string rules (MongoDB, Postgres, Azure Storage) redact only
the password / key span so log readers can still tell which host or
account was being addressed.

## Development

The project is driven by [`gogo`](https://github.com/dgageot/gogo),
a small task runner. Install it once:

```sh
go install github.com/dgageot/gogo@latest
```

Then, from the repository root:

```sh
gogo            # default: lint + test
gogo test       # go test ./...
gogo test-race  # go test -race ./...
gogo bench      # go test -bench=. -benchmem -run=^$ ./...
gogo lint       # golangci-lint run + go.mod tidy check
gogo format     # golangci-lint fmt
gogo tidy       # go mod tidy
gogo -l         # list every task with its description
```

The linter configuration lives in [`.golangci.yml`](./.golangci.yml).
The matching CI workflow runs lint + race-enabled tests against the
go.mod floor (Go 1.22) and the latest stable Go release on every PR
— see [`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

## Performance

On a typical clean input the cost is dominated by a single linear scan
over the bytes; the regex engine is never invoked. With a secret, only
the rules whose keywords are present run. Both functions allocate
only when text actually changes.

On an Apple M4 Max scrubbing a 9000-byte clean payload and a
secret-bearing 1.5 KB payload:

On an Apple M4 Max scrubbing a 9000-byte clean payload and a
secret-bearing 1.5 KB payload:

```
BenchmarkAhoScanCleanInput-16        132150     18097 ns/op   497.31 MB/s     0 B/op    0 allocs/op
BenchmarkRedactCleanInput-16         133822     18071 ns/op                   0 B/op    0 allocs/op
BenchmarkContainsCleanInput-16       131232     18105 ns/op                   0 B/op    0 allocs/op
BenchmarkRedactWithSecret-16         538251      4408 ns/op                1826 B/op    3 allocs/op
BenchmarkContainsWithSecret-16       676144      3510 ns/op                   0 B/op    0 allocs/op
```

The AC scan dominates the clean-input path — `Redact` and `Contains`
add no measurable overhead on top of it because the rule loop
short-circuits on an empty keyword mask. `Contains` allocates zero
bytes even on a secret-bearing input: it only needs the regex
`MatchString`, which uses pooled state machines internally.

## Provenance

The default ruleset is derived from the MIT-licensed
[`github.com/docker/mcp-gateway/pkg/secretsscan`](https://github.com/docker/mcp-gateway)
package, which adapted it from
[`github.com/aquasecurity/trivy/pkg/fanal/secret`](https://github.com/aquasecurity/trivy),
extended with additional patterns for modern AI providers, payment
processors, and infrastructure tokens.

## License

Apache-2.0. See [LICENSE](./LICENSE).
