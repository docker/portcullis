# portcullis

[![Go Reference](https://pkg.go.dev/badge/github.com/docker/portcullis.svg)](https://pkg.go.dev/github.com/docker/portcullis)

A tiny Go library that detects and redacts API tokens, cloud
credentials, and other secret material in arbitrary text.

```go
import "github.com/docker/portcullis"

clean := portcullis.Redact("Run this with AWS_ACCESS_KEY_ID=AKIARZPUZDIKQEXAMPLE please.")
// → "Run this with AWS_ACCESS_KEY_ID=[REDACTED] please."

portcullis.Contains("not a secret")                           // false
portcullis.Contains("AWS_ACCESS_KEY_ID=AKIARZPUZDIKQEXAMPLE") // true
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

## API

The public surface is intentionally tiny:

```go
const Marker = "[REDACTED]"

func Contains(text string) bool   // detect
func Redact(text string) string   // scrub
func Find(text string) []Match    // locate

// Same as above for callers holding a []byte, without copying it.
// Each Match.Value then aliases b: leave b alone while they are in use.
func ContainsBytes(b []byte) bool
func FindBytes(b []byte) []Match

type Match struct {
	Start, End int    // byte offsets into the input
	Value      string // the input between them
}
```

All of them are safe for concurrent use. The compiled rule set and
its Aho–Corasick automaton are built once on first call and shared
across goroutines.

## Command line

`portcullis-scan` runs the same detection over a file or a directory
tree and prints one `path:line:col: value` line per secret:

```sh
go install github.com/docker/portcullis/cmd/portcullis-scan@latest

portcullis-scan -ignore 'vendor/**' -ignore '*_test.go' .
```

It exits with 0 when nothing was found, 1 when a secret was found and
2 on a usage error or an unreadable file, so it can gate a CI job.
Its output holds the secrets themselves: where logs are kept, discard
it and go by the exit status. Binary files and files over 10 MiB are
skipped unless `-binary` and `-max-size` say otherwise.

## What it detects

The built-in catalogue covers ~240 patterns spanning:

- Cloud providers — AWS, GCP service accounts, Azure Storage,
  Azure AD client secrets, DigitalOcean, Yandex,
  Akamai, Cloudflare Origin CA.
- Source forges & CI — GitHub (PAT / OAuth / app / fine-grained /
  refresh), GitLab (full token family incl. `glimt-` /
  `glagent-` / `glsoat-` / routable variants), Bitbucket,
  Docker Hub (PAT / OAT), JFrog (key + reference token), Sonar,
  Buildkite, CircleCI, Harness (`pat.` / `sat.`), Authress.
- LLM / AI providers — OpenAI, Anthropic, DeepSeek, Google (AIza),
  xAI / Grok, Cohere, Groq, Perplexity, Replicate, OpenRouter,
  Hugging Face (user `hf_` + organisation `api_org_`),
  AssemblyAI, Deepgram, NVIDIA NIM (`nvapi-`),
  LangSmith (`lsv2_pt_` / `lsv2_sk_`), Pinecone (`pcsk_`).
- Payment processors — Stripe (secret / restricted /
  webhook), Razorpay, Plaid, Square (`sq0atp-` / `sq0csp-`),
  Braintree.
- Communication & ops — Slack (legacy, rotating, webhooks,
  workflow webhooks), Discord (bot & webhook), Telegram, Twilio,
  SendGrid, Mailgun, Mailchimp, Sendinblue, Microsoft Teams
  webhooks, PubNub (publish + subscribe), Tines / Zapier webhooks.
- SaaS & developer tools — Figma, Contentful, HubSpot, LaunchDarkly
  (incl. `sdk-` keys), Doppler (full family), 1Password, Vercel,
  Netlify, Render, Notion, Linear, Trello, ClickUp, Okta, ngrok,
  Cisco Meraki, SettleMint, Fly.io macaroons, Heroku v1/v2,
  OpenShift `sha256~` tokens, Voiceflow, Deno Deploy, Bitbucket
  app passwords (`ATBB`), CircleCI v2 (`CCIPAT_`), Endor Labs,
  Rootly, Sourcegraph Cody, Stripe payment-intent client secrets,
  Nightfall DLP, Ramp, Octopus Deploy, Stytch.
- Infra, web3, databases & PII — HashiCorp Vault (service / batch /
  recovery), Terraform Cloud, Tailscale, PlanetScale, Supabase,
  MongoDB / Postgres / MySQL / Redis / AMQP connection-string
  passwords, Sidekiq Pro/Enterprise gem-server URLs,
  Alchemy / Etherscan / Moralis (web3), payment cards (Luhn-checked),
  IBANs (mod-97-checked), US SSNs, Logz.io, PEM private keys, JWTs,
  and more.

Connection-string rules (MongoDB, Postgres, MySQL, Redis, AMQP, Azure
Storage) redact only the password / key span so log readers can still
tell which host or account was being addressed.

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
The matching CI workflow runs lint + race-enabled tests using the
Go version specified in go.mod (Go 1.27.4) on every PR
— see [`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

## Performance

An input with none of the rules' keywords and none of the shapes the
PII rules start from (nine or more digits in a row, single dashes or
spaces aside, or two letters right before two digits) never reaches a
regex and, once the rule set is built, allocates nothing. Its cost is
that of scanning the bytes for keywords (Aho–Corasick), then for
those shapes. Otherwise only the rules whose keyword or shape is
present run their regex.

On an Apple M4 Max scrubbing a 9000-byte clean payload and a
secret-bearing 1.5 KB payload:

```
BenchmarkAhoScanCleanInput-16        427100      2832 ns/op  3177.96 MB/s     0 B/op    0 allocs/op
BenchmarkAhoScanWithKeyword-16      1760301       683.8 ns/op 2288.76 MB/s     0 B/op    0 allocs/op
BenchmarkRedactCleanInput-16         200227      6089 ns/op                    0 B/op    0 allocs/op
BenchmarkContainsCleanInput-16       203072      6016 ns/op                    0 B/op    0 allocs/op
BenchmarkRedactWithSecret-16         418003      2835 ns/op                 1717 B/op    7 allocs/op
BenchmarkContainsWithSecret-16       745269      1609 ns/op                  129 B/op    5 allocs/op
```

`Contains` returns on the first rule that matches, so on a
secret-bearing input it usually skips the shape scan and the rest of
the catalogue. `Redact` has to visit every rule, and allocates for
the matches it finds and the redacted copy.

## Provenance

The default ruleset is derived from the MIT-licensed
[`github.com/docker/mcp-gateway/pkg/secretsscan`](https://github.com/docker/mcp-gateway)
package, which adapted it from
[`github.com/aquasecurity/trivy/pkg/fanal/secret`](https://github.com/aquasecurity/trivy),
extended with additional patterns for modern AI providers, payment
processors, and infrastructure tokens.

## License

Apache-2.0. See [LICENSE](./LICENSE).
