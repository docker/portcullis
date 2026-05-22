# portcullis

[![Go Reference](https://pkg.go.dev/badge/github.com/docker/portcullis.svg)](https://pkg.go.dev/github.com/docker/portcullis)

A tiny Go library that detects and redacts API tokens, cloud
credentials, and other secret material in arbitrary text.

```go
import "github.com/docker/portcullis"

clean := portcullis.Redact("Run this with token=ghp_1234567890abcdef1234567890abcdef1234 please.")
// → "Run this with token=[REDACTED] please."

portcullis.Contains("not a secret")                                   // false
portcullis.Contains("token=ghp_1234567890abcdef1234567890abcdef1234") // true
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

The built-in catalogue covers ~245 patterns spanning:

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
  webhook), Razorpay, Plaid, Braintree.
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
  Nightfall DLP, Ramp.
- Infra, web3 & databases — HashiCorp Vault (service / batch /
  recovery), Terraform Cloud, Tailscale, PlanetScale, Supabase,
  MongoDB / Postgres / MySQL / Redis / AMQP connection-string
  passwords, Sidekiq Pro/Enterprise gem-server URLs,
  Alchemy / Etherscan / Moralis (web3), Logz.io,
  PEM private keys, JWTs, and more.

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

```
BenchmarkAhoScanCleanInput-16        257198      4823 ns/op  1865.95 MB/s     0 B/op    0 allocs/op
BenchmarkAhoScanWithKeyword-16      1251084       956.0 ns/op 1636.96 MB/s     0 B/op    0 allocs/op
BenchmarkRedactCleanInput-16         228036      4803 ns/op                    0 B/op    0 allocs/op
BenchmarkContainsCleanInput-16       233336      4782 ns/op                    0 B/op    0 allocs/op
BenchmarkRedactWithSecret-16         565590      2094 ns/op                 1585 B/op    2 allocs/op
BenchmarkContainsWithSecret-16       912943      1312 ns/op                    0 B/op    0 allocs/op
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
