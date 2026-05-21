// The rules in this file are derived from the MIT-licensed
// github.com/docker/mcp-gateway/pkg/secretsscan package, which itself
// copied the patterns from
// github.com/aquasecurity/trivy/pkg/fanal/secret/builtin-rules.go.
//
// Copyright (c) 2025 Docker (MIT). Re-licensed here under Apache-2.0
// per the license-compatibility allowances of the MIT License.

package portcullis

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

const (
	quote   = `["']?`
	connect = `\s*(:|=>|=)?\s*`
	aws     = `aws_?`
)

// rule pairs a regular expression with a keyword shortlist. A rule
// matches when the (lower-cased) input contains any of the keywords
// AND the (case-sensitive) expression matches; the keyword filter is
// what keeps detection fast for typical inputs.
type rule struct {
	expression string
	keywords   []string
}

// asSecretGroup wraps a `?P<secret>…` fragment in a plain group so
// the named subgroup is syntactically valid. Earlier revisions also
// prepended a `[^0-9a-zA-Z]|^` anchor and appended a
// whitespace/punctuation/end-of-input anchor (collectively a
// "word boundary" requirement) so a rule only fired when the secret
// stood alone in the input. Those anchors caused detection to miss
// secrets embedded directly inside larger tokens — e.g.
// `BEFOREghp_…AFTER`, `KEY=AKIA…`, `…EXAMPLEAFTER` — even though the
// recognisable prefix and exact-length payload were both present.
//
// Detection now ignores the surrounding characters entirely. Each
// rule's payload is tightly constrained (fixed-length character
// classes, explicit token shapes) so removing the boundary check
// does not broaden the regex enough to cause super-linear matching:
// Go's RE2-based engine still scans the input in O(len(text)) per
// rule, and the keyword pre-filter in [Redact] keeps the regex hot
// path off most inputs.
func asSecretGroup(str string) string {
	return fmt.Sprintf("(%s)", str)
}

// contextual builds a vendor-anchored rule that matches when a known
// vendor word appears within ~50 chars of an `=` / `:` / `=>` / etc.
// assignment, followed by a value of the given shape. Only the value
// span (the named `?P<secret>` subgroup) is redacted, so log readers
// still see the assignment context (`SNYK_TOKEN=[REDACTED]`).
//
// The frame matches the gitleaks default-rule template: a lazy
// 50-char run of \w/./- before the vendor word, then up to 20 chars
// of additional context (e.g. `_API_KEY`), then any of the standard
// assignment operators, then optionally quotes / whitespace, then
// the value, then a terminator (whitespace, quote, semicolon,
// literal `\n`/`\r`, or end of input). Vendor words are case-folded
// by the leading `(?i)` flag.
//
// Body patterns must use plain (non-named) groups; the helper adds
// the outer `?P<secret>…` wrapper itself.
func contextual(vendor, body string) string {
	return `(?i)[\w.-]{0,50}?(?:` + vendor + `)(?:[ \t\w.-]{0,20})[\s'"]{0,3}` +
		`(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}` +
		`(?P<secret>` + body + `)(?:[\x60'"\s;]|\\[nr]|$)`
}

// rules is the source-form catalogue, kept verbatim from upstream so
// future updates apply cleanly. [compiledRuleSet] resolves it into
// the regex-compiled form actually used at scan time.
//
//nolint:funlen // single-source-of-truth for the ruleset
var rules = sync.OnceValue(func() []rule {
	return []rule{
		{
			// aws-access-key-id. Prefix list mirrors the gitleaks
			// default rule: `ABIA` is the STS bearer token prefix and
			// `ACCA` is the context-specific (vended) credential
			// prefix; both grant the same level of access as a
			// regular access key while the session is valid.
			expression: asSecretGroup(`(?P<secret>(A3T[A-Z0-9]|AKIA|AGPA|AidA|AROA|AIPA|ANPA|ANVA|ASIA|ABIA|ACCA)[A-Z0-9]{16})` + quote),
			keywords:   []string{"AKIA", "AGPA", "AidA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA", "ABIA", "ACCA"},
		},
		{
			// aws-secret-access-key
			expression: fmt.Sprintf(`(?i)%s%s(sec(ret)?)?_?(access)?_?key%s%s%s(?P<secret>[A-Za-z0-9\/\+=]{40})%s`, quote, aws, quote, connect, quote, quote),
			keywords:   []string{"key"},
		},
		{
			// github-pat
			expression: asSecretGroup(`?P<secret>ghp_[0-9a-zA-Z]{36}`),
			keywords:   []string{"ghp_"},
		},
		{
			// github-oauth
			expression: asSecretGroup(`?P<secret>gho_[0-9a-zA-Z]{36}`),
			keywords:   []string{"gho_"},
		},
		{
			// github-app-token
			expression: asSecretGroup(`?P<secret>(ghu|ghs)_[0-9a-zA-Z]{36}`),
			keywords:   []string{"ghu_", "ghs_"},
		},
		{
			// github-refresh-token
			expression: asSecretGroup(`?P<secret>ghr_[0-9a-zA-Z]{76}`),
			keywords:   []string{"ghr_"},
		},
		{
			// github-fine-grained-pat
			expression: `github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`,
			keywords:   []string{"github_pat_"},
		},
		{
			// gitlab-pat
			expression: asSecretGroup(`?P<secret>glpat-[0-9a-zA-Z\-\_]{20}`),
			keywords:   []string{"glpat-"},
		},
		{
			// hugging-face-access-token
			expression: asSecretGroup(`?P<secret>hf_[A-Za-z0-9]{34,40}`),
			keywords:   []string{"hf_"},
		},
		{
			// private-key
			expression: `(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY( BLOCK)?\s*?-----[\s]*?(?P<secret>[A-Za-z0-9=+/\\\r\n][A-Za-z0-9=+/\\\s]+)[\s]*?-----\s*?END[ A-Z0-9_-]*? PRIVATE KEY( BLOCK)?\s*?-----`,
			keywords:   []string{"-----"},
		},
		{
			// shopify-token
			expression: `shp(ss|at|ca|pa)_[a-fA-F0-9]{32}`,
			keywords:   []string{"shpss_", "shpat_", "shpca_", "shppa_"},
		},
		{
			// slack-access-token
			expression: asSecretGroup(`?P<secret>xox[baprs]-([0-9a-zA-Z]{10,48})`),
			keywords:   []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
		},
		{
			// stripe-publishable-token. Stripe added the `prod` env tag
			// alongside `test` / `live` in 2024; widening the alternation
			// keeps the keyword pre-filter cheap (one extra literal) and
			// stops production-mode publishable keys from leaking through.
			expression: asSecretGroup(`?P<secret>(?i)pk_(test|live|prod)_[0-9a-z]{10,32}`),
			keywords:   []string{"pk_test_", "pk_live_", "pk_prod_"},
		},
		{
			// stripe-secret-token (see the publishable rule above for the
			// `prod` extension rationale).
			expression: asSecretGroup(`?P<secret>(?i)sk_(test|live|prod)_[0-9a-z]{10,32}`),
			keywords:   []string{"sk_test_", "sk_live_", "sk_prod_"},
		},
		{
			// pypi-upload-token
			expression: `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`,
			keywords:   []string{"pypi-AgEIcHlwaS5vcmc"},
		},
		{
			// gcp-service-account
			expression: `\"type\": \"service_account\"`,
			keywords:   []string{"\"type\": \"service_account\""},
		},
		{
			// heroku-api-key
			expression: ` (?i)(?P<key>heroku[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['\"]`,
			keywords:   []string{"heroku"},
		},
		{
			// slack-web-hook
			expression: `https:\/\/hooks.slack.com\/services\/[A-Za-z0-9+\/]{44,48}`,
			keywords:   []string{"hooks.slack.com"},
		},
		{
			// twilio-api-key
			expression: `SK[0-9a-fA-F]{32}`,
			keywords:   []string{"SK"},
		},
		{
			// age-secret-key
			expression: `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`,
			keywords:   []string{"AGE-SECRET-KEY-1"},
		},
		{
			// facebook-token
			expression: `(?i)(?P<key>facebook[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`,
			keywords:   []string{"facebook"},
		},
		{
			// twitter-token
			expression: `(?i)(?P<key>twitter[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{35,44})['\"]`,
			keywords:   []string{"twitter"},
		},
		{
			// adobe-client-id
			expression: `(?i)(?P<key>adobe[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`,
			keywords:   []string{"adobe"},
		},
		{
			// adobe-client-secret
			expression: `(p8e-)(?i)[a-z0-9]{32}`,
			keywords:   []string{"p8e-"},
		},
		{
			// alibaba-access-key-id
			expression: `(?P<secret>(LTAI)(?i)[a-z0-9]{20})`,
			keywords:   []string{"LTAI"},
		},
		{
			// alibaba-secret-key
			expression: `(?i)(?P<key>alibaba[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{30})['\"]`,
			keywords:   []string{"alibaba"},
		},
		{
			// asana-client-id
			expression: `(?i)(?P<key>asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[0-9]{16})['\"]`,
			keywords:   []string{"asana"},
		},
		{
			// asana-client-secret
			expression: `(?i)(?P<key>asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{32})['\"]`,
			keywords:   []string{"asana"},
		},
		{
			// atlassian-api-token
			expression: `(?i)(?P<key>atlassian[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{24})['\"]`,
			keywords:   []string{"atlassian"},
		},
		{
			// bitbucket-client-id
			expression: `(?i)(?P<key>bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{32})['\"]`,
			keywords:   []string{"bitbucket"},
		},
		{
			// bitbucket-client-secret
			expression: `(?i)(?P<key>bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9_\-]{64})['\"]`,
			keywords:   []string{"bitbucket"},
		},
		{
			// beamer-api-token
			expression: `(?i)(?P<key>beamer[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>b_[a-z0-9=_\-]{44})['\"]`,
			keywords:   []string{"beamer"},
		},
		{
			// clojars-api-token
			expression: `(CLOJARS_)(?i)[a-z0-9]{60}`,
			keywords:   []string{"CLOJARS_"},
		},
		{
			// contentful-delivery-api-token
			expression: `(?i)(?P<key>contentful[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9\-=_]{43})['\"]`,
			keywords:   []string{"contentful"},
		},
		{
			// databricks-api-token
			expression: `dapi[a-h0-9]{32}`,
			keywords:   []string{"dapi"},
		},
		{
			// discord-api-token
			expression: `(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{64})['\"]`,
			keywords:   []string{"discord"},
		},
		{
			// discord-client-id
			expression: `(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[0-9]{18})['\"]`,
			keywords:   []string{"discord"},
		},
		{
			// discord-client-secret
			expression: `(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9=_\-]{32})['\"]`,
			keywords:   []string{"discord"},
		},
		{
			// doppler-api-token. Personal tokens are `dp.pt.<43 chars>`;
			// the prefix is unique to Doppler so quotes aren't required.
			expression: `(dp\.pt\.)(?i)[a-z0-9]{43}`,
			keywords:   []string{"dp.pt."},
		},
		{
			// dropbox-api-secret
			expression: `(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{15})['\"]`,
			keywords:   []string{"dropbox"},
		},
		{
			// dropbox-short-lived-api-token
			expression: `(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](sl\.[a-z0-9\-=_]{135})['\"]`,
			keywords:   []string{"dropbox"},
		},
		{
			// dropbox-long-lived-api-token
			expression: `(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"][a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}['\"]`,
			keywords:   []string{"dropbox"},
		},
		{
			// duffel-api-token
			expression: `['\"]duffel_(test|live)_(?i)[a-z0-9_-]{43}['\"]`,
			keywords:   []string{"duffel_test_", "duffel_live_"},
		},
		{
			// dynatrace-api-token. `dt0c01.` is the documented version
			// prefix; combined with the fixed 24+64 hex body it doesn't
			// need quote anchoring to stay specific.
			expression: `dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`,
			keywords:   []string{"dt0c01."},
		},
		{
			// easypost-api-token. `EZAK` (production) / `EZTK` (test)
			// prefixes plus the fixed 54-char body are specific enough
			// that surrounding quotes aren't required.
			expression: `EZ[AT]K(?i)[a-z0-9]{54}`,
			keywords:   []string{"EZAK", "EZTK"},
		},
		{
			// fastly-api-token
			expression: `(?i)(?P<key>fastly[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9\-=_]{32})['\"]`,
			keywords:   []string{"fastly"},
		},
		{
			// finicity-client-secret
			expression: `(?i)(?P<key>finicity[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{20})['\"]`,
			keywords:   []string{"finicity"},
		},
		{
			// finicity-api-token
			expression: `(?i)(?P<key>finicity[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`,
			keywords:   []string{"finicity"},
		},
		{
			// flutterwave-public-key
			expression: asSecretGroup(`?P<secret>FLW(PUB|SEC)K_TEST-(?i)[a-h0-9]{32}-X`),
			keywords:   []string{"FLWSECK_TEST-", "FLWPUBK_TEST-"},
		},
		{
			// flutterwave-enc-key
			expression: asSecretGroup(`?P<secret>FLWSECK_TEST[a-h0-9]{12}`),
			keywords:   []string{"FLWSECK_TEST"},
		},
		{
			// frameio-api-token
			expression: `fio-u-(?i)[a-z0-9\-_=]{64}`,
			keywords:   []string{"fio-u-"},
		},
		{
			// gocardless-api-token
			expression: `['\"]live_(?i)[a-z0-9\-_=]{40}['\"]`,
			keywords:   []string{"live_"},
		},
		{
			// grafana-api-token
			expression: `['\"]?eyJrIjoi(?i)[a-z0-9\-_=]{72,92}['\"]?`,
			keywords:   []string{"eyJrIjoi"},
		},
		{
			// hashicorp-tf-api-token. The `<14 chars>.atlasv1.<body>`
			// shape is documented and unique to Terraform Cloud, so the
			// quote anchors that the upstream rule used aren't needed.
			expression: `(?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}`,
			keywords:   []string{"atlasv1."},
		},
		{
			// hubspot-api-token
			expression: `(?i)(?P<key>hubspot[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]`,
			keywords:   []string{"hubspot"},
		},
		{
			// intercom-api-token
			expression: `(?i)(?P<key>intercom[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9=_]{60})['\"]`,
			keywords:   []string{"intercom"},
		},
		{
			// intercom-client-secret
			expression: `(?i)(?P<key>intercom[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]`,
			keywords:   []string{"intercom"},
		},
		{
			// ionic-api-token
			expression: `(?i)(ionic[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](ion_[a-z0-9]{42})['\"]`,
			keywords:   []string{"ionic"},
		},
		{
			// jwt-token
			expression: `ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?`,
			keywords:   []string{".eyJ"},
		},
		{
			// linear-api-token
			expression: `lin_api_(?i)[a-z0-9]{40}`,
			keywords:   []string{"lin_api_"},
		},
		{
			// linear-client-secret
			expression: `(?i)(?P<key>linear[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]`,
			keywords:   []string{"linear"},
		},
		{
			// lob-api-key
			expression: `(?i)(?P<key>lob[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(live|test)_[a-f0-9]{35})['\"]`,
			keywords:   []string{"lob"},
		},
		{
			// lob-pub-api-key
			expression: `(?i)(?P<key>lob[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(test|live)_pub_[a-f0-9]{31})['\"]`,
			keywords:   []string{"lob"},
		},
		{
			// mailchimp-api-key
			expression: `(?i)(?P<key>mailchimp[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32}-us20)['\"]`,
			keywords:   []string{"mailchimp"},
		},
		{
			// mailgun-token
			expression: `(?i)(?P<key>mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(pub)?key-[a-f0-9]{32})['\"]`,
			keywords:   []string{"mailgun"},
		},
		{
			// mailgun-signing-key
			expression: `(?i)(?P<key>mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})['\"]`,
			keywords:   []string{"mailgun"},
		},
		{
			// mapbox-api-token
			expression: `(?i)(pk\.[a-z0-9]{60}\.[a-z0-9]{22})`,
			keywords:   []string{"pk."},
		},
		{
			// messagebird-api-token
			expression: `(?i)(?P<key>messagebird[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{25})['\"]`,
			keywords:   []string{"messagebird"},
		},
		{
			// messagebird-client-id
			expression: `(?i)(?P<key>messagebird[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]`,
			keywords:   []string{"messagebird"},
		},
		{
			// new-relic-user-api-key. `NRAK-` is the documented prefix;
			// combined with the fixed 27-char body it stays specific
			// without the surrounding quotes.
			expression: `NRAK-[A-Z0-9]{27}`,
			keywords:   []string{"NRAK-"},
		},
		{
			// new-relic-user-api-id
			expression: `(?i)(?P<key>newrelic[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[A-Z0-9]{64})['\"]`,
			keywords:   []string{"newrelic"},
		},
		{
			// new-relic-browser-api-token. `NRJS-` is the documented
			// prefix; the fixed 19-char body keeps the rule specific.
			expression: `NRJS-[a-f0-9]{19}`,
			keywords:   []string{"NRJS-"},
		},
		{
			// npm-access-token. The `npm_` prefix + fixed 36-char body is
			// unique enough that we don't anchor on surrounding quotes —
			// this catches CLI output (`npm token list`) and `.npmrc`
			// shapes (`//registry.npmjs.org/:_authToken=npm_…`) alongside
			// the JSON/YAML config form the upstream rule expected.
			expression: `npm_(?i)[a-z0-9]{36}`,
			keywords:   []string{"npm_"},
		},
		{
			// planetscale-password
			expression: `pscale_pw_(?i)[a-z0-9\-_\.]{43}`,
			keywords:   []string{"pscale_pw_"},
		},
		{
			// planetscale-api-token
			expression: `pscale_tkn_(?i)[a-z0-9\-_\.]{43}`,
			keywords:   []string{"pscale_tkn_"},
		},
		{
			// private-packagist-token
			expression: `packagist_[ou][ru]t_(?i)[a-f0-9]{68}`,
			keywords:   []string{"packagist_uut_", "packagist_ort_", "packagist_out_"},
		},
		{
			// postman-api-token
			expression: `PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`,
			keywords:   []string{"PMAK-"},
		},
		{
			// pulumi-api-token
			expression: `pul-[a-f0-9]{40}`,
			keywords:   []string{"pul-"},
		},
		{
			// rubygems-api-token
			expression: `rubygems_[a-f0-9]{48}`,
			keywords:   []string{"rubygems_"},
		},
		{
			// sendgrid-api-token
			expression: `SG\.(?i)[a-z0-9_\-\.]{66}`,
			keywords:   []string{"SG."},
		},
		{
			// sendinblue-api-token
			expression: `xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16}`,
			keywords:   []string{"xkeysib-"},
		},
		{
			// shippo-api-token
			expression: `shippo_(live|test)_[a-f0-9]{40}`,
			keywords:   []string{"shippo_live_", "shippo_test_"},
		},
		{
			// linkedin-client-secret
			expression: `(?i)(?P<key>linkedin[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z]{16})['\"]`,
			keywords:   []string{"linkedin"},
		},
		{
			// linkedin-client-id
			expression: `(?i)(?P<key>linkedin[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{14})['\"]`,
			keywords:   []string{"linkedin"},
		},
		{
			// twitch-api-token
			expression: `(?i)(?P<key>twitch[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{30})['\"]`,
			keywords:   []string{"twitch"},
		},
		{
			// typeform-api-token
			expression: `(?i)(?P<key>typeform[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}(?P<secret>tfp_[a-z0-9\-_\.=]{59})`,
			keywords:   []string{"typeform"},
		},
		{
			// dockerconfig-secret
			expression: `(?i)(\.(dockerconfigjson|dockercfg):\s*\|*\s*(?P<secret>(ey|ew)+[A-Za-z0-9\/\+=]+))`,
			keywords:   []string{"dockerc"},
		},
		{
			// docker-hub-personal-access-token. The `dckr_pat_` prefix
			// is followed by a strictly alphanumeric 27-char body —
			// per Docker's PAT issuance, no dashes / dots / underscores
			// appear in the body, so the char class stays tight.
			expression: `dckr_pat_[A-Za-z0-9]{27}`,
			keywords:   []string{"dckr_pat_"},
		},
		{
			// docker-hub-organization-access-token. Issued from the
			// Docker Hub admin console for organization-scoped API
			// access; same `<prefix>_<27 alnum>` shape as the PAT but
			// with the `dckr_oat_` prefix.
			expression: `dckr_oat_[A-Za-z0-9]{27}`,
			keywords:   []string{"dckr_oat_"},
		},

		// --- Patterns added on top of the upstream Trivy / mcp-gateway
		// catalogue. Each one targets a credential format whose prefix
		// is unique enough to keep the keyword pre-filter cheap and the
		// regex's false-positive rate low.

		{
			// openai-api-key. Every modern OpenAI key (project keys
			// `sk-proj-…`, service-account keys `sk-svcacct-…`, admin
			// keys `sk-admin-…`, and the original `sk-…` keys reissued
			// after May 2024) embeds the literal substring "T3BlbkFJ"
			// (base64 for "OpenAI") between two long alphanumeric runs.
			// That marker keeps both the keyword filter and the regex
			// extremely specific.
			expression: `sk-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}`,
			keywords:   []string{"T3BlbkFJ"},
		},
		{
			// anthropic-api-key. Claude keys follow
			// `sk-ant-(api|sid|admin)NN-<base64url>` and are ~108 chars
			// long; the trailing "AA" is the standard base64 padding.
			// `admin01` keys grant org-wide management access (key issuance,
			// usage limits) so leakage is at least as serious as a regular
			// `api01` key.
			expression: `sk-ant-(api|sid|admin)\d{2}-[A-Za-z0-9_-]{93}AA`,
			keywords:   []string{"sk-ant-"},
		},
		{
			// google-api-key. Used by Maps, Cloud, Firebase, Gemini and
			// most other Google REST APIs. The `AIza` prefix is fixed.
			expression: `AIza[0-9A-Za-z_-]{35}`,
			keywords:   []string{"AIza"},
		},
		{
			// google-oauth-client-secret. Issued in the Google Cloud
			// Console for OAuth 2.0 clients; always 35 chars total.
			expression: `GOCSPX-[A-Za-z0-9_-]{28}`,
			keywords:   []string{"GOCSPX-"},
		},
		{
			// digitalocean-token. v1 personal-access tokens (`dop_v1_`),
			// OAuth tokens (`doo_v1_`), and OAuth refresh tokens
			// (`dor_v1_`) all share the 71-char total shape: 7-char
			// prefix + 64 lowercase hex.
			expression: `do[opr]_v1_[a-f0-9]{64}`,
			keywords:   []string{"dop_v1_", "doo_v1_", "dor_v1_"},
		},
		{
			// stripe-webhook-signing-secret. Used to verify incoming
			// webhook payloads; leakage lets attackers forge events.
			expression: `whsec_[A-Za-z0-9]{32,}`,
			keywords:   []string{"whsec_"},
		},
		{
			// jfrog-artifactory-api-key. Distinct from access tokens;
			// the `AKCp` prefix is documented and the body is between
			// 69 and 73 alphanumeric characters depending on when the
			// key was issued.
			expression: `AKCp[A-Za-z0-9]{69,73}`,
			keywords:   []string{"AKCp"},
		},
		{
			// tencent-cloud-secret-id. Tencent's analogue of an AWS
			// access-key-id, used by the COS / CVM / etc. APIs.
			expression: `AKID[A-Za-z0-9]{32}`,
			keywords:   []string{"AKID"},
		},
		{
			// sentry-user-auth-token. The `sntrys_` prefix is followed
			// by a base64url-encoded JWT-style payload that always
			// starts with `eyJ` (the base64 of `{"`).
			expression: `sntrys_eyJ[A-Za-z0-9+/=_-]{40,}`,
			keywords:   []string{"sntrys_"},
		},
		{
			// stripe-restricted-key. Restricted API keys (introduced
			// alongside the publishable / secret keys) follow the same
			// `<prefix>_<env>_<body>` shape as `pk_` / `sk_`. Leakage of
			// a restricted key still grants the scoped Stripe permissions
			// it was issued with, so it must be redacted. The `prod` env
			// tag was added in 2024 alongside the `test` / `live` modes.
			expression: `(?i)rk_(test|live|prod)_[0-9a-z]{10,32}`,
			keywords:   []string{"rk_test_", "rk_live_", "rk_prod_"},
		},
		{
			// notion-integration-token. The `ntn_` prefix is the modern
			// (post-2023) format for internal-integration tokens; the
			// 46-character body is fixed.
			expression: `ntn_[A-Za-z0-9]{46}`,
			keywords:   []string{"ntn_"},
		},
		{
			// gitlab-pipeline-trigger-token. `glptt-` is the documented
			// prefix for trigger tokens; body is 40 lowercase hex.
			expression: `glptt-[a-f0-9]{40}`,
			keywords:   []string{"glptt-"},
		},
		{
			// vault-service-token. HashiCorp Vault service tokens issued
			// by recent Vault versions carry the `hvs.` prefix and a
			// base64url body whose length varies with the policies /
			// metadata encoded inside the CBOR payload. The lower bound
			// of 90 chars covers a default-policy token; the upper bound
			// of 200 covers tokens carrying multiple policies and
			// namespace metadata (matching the looser bound Trivy uses
			// for similar Vault formats).
			expression: `hvs\.[A-Za-z0-9_-]{90,200}`,
			keywords:   []string{"hvs."},
		},
		{
			// slack-rotating-token. Modern Slack OAuth issues refresh
			// tokens (`xoxe-…`) and rotating bot/user tokens
			// (`xoxe.xoxb-…` / `xoxe.xoxp-…`) whose bodies include dashes
			// and dots — a shape the legacy `slack-access-token` rule
			// (locked to `xox[baprs]-`) does not cover.
			//
			// The body class `[A-Za-z0-9.-]` happens to overlap with
			// neighbouring URL / hostname text (e.g. `api.slack.com`)
			// so we cap the quantifier at 300 — comfortably above the
			// longest observed Slack rotating-token body — to keep an
			// adjacent dotted identifier from being swallowed into the
			// redaction span when the token isn't separated from it by
			// whitespace or punctuation.
			expression: `xoxe(\.xox[bp])?-[A-Za-z0-9.-]{40,300}`,
			keywords:   []string{"xoxe-", "xoxe.xox"},
		},
		{
			// replicate-api-token. Replicate keys carry the `r8_`
			// prefix; the fixed 37-char body keeps the rule specific.
			expression: `r8_[A-Za-z0-9]{37}`,
			keywords:   []string{"r8_"},
		},
		{
			// square-access-token. Square production / sandbox access
			// tokens carry the `EAAA` prefix and a 60-character body.
			expression: `EAAA[A-Za-z0-9_-]{60}`,
			keywords:   []string{"EAAA"},
		},
		{
			// atlassian-api-token (Cloud). Atlassian Cloud API tokens
			// carry the very distinctive `ATATT3xFfGF0` prefix followed
			// by a long base64url body and an 8-char hex CRC. The
			// existing `atlassian-api-token` rule only catches values
			// preceded by an `atlassian` keyword — this rule fills the
			// gap for bare leakage in CLI output / logs.
			expression: `ATATT3xFfGF0[A-Za-z0-9_=-]{180,250}`,
			keywords:   []string{"ATATT3xFfGF0"},
		},

		// --- Second batch of additions, focused on credentials whose
		// shapes are documented by the issuing vendor and whose
		// prefixes (or framing structure) are unique enough to keep
		// the keyword pre-filter useful and the false-positive rate
		// low. Each rule cites the format it targets in its comment.

		{
			// discord-bot-token. Three-part dotted format issued for bot
			// applications: `<base64 snowflake>.<6-char timestamp>.<27+
			// char HMAC>`. The first segment is the bot's user-ID base64
			// encoded; current Discord IDs (2018 onwards) base64 to a
			// leading `MT`/`Mz`/`ND`/`NT`/`Nz`/`OD` byte pair, which we
			// list as keywords so the AC pre-filter still skips inputs
			// without a plausible token prefix. The structural shape
			// (M-or-N-or-O-prefixed body, two literal dots, fixed segment
			// widths) keeps the regex itself specific.
			expression: `[MNO][A-Za-z\d_-]{23,25}\.[\w-]{6,7}\.[\w-]{27,38}`,
			keywords:   []string{"MT", "Mz", "ND", "NT", "Nz", "OD"},
		},
		{
			// discord-webhook-url. The URL itself is a bearer credential:
			// anyone holding it can post arbitrary content to the channel.
			// `discord.com/api/webhooks/<channel id>/<token>` (and the
			// `discordapp.com` legacy alias plus the `canary.`/`ptb.`
			// release-channel hosts) is the documented shape.
			expression: `https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+`,
			keywords:   []string{"discord.com/api/webhooks", "discordapp.com/api/webhooks"},
		},
		{
			// telegram-bot-token. BotFather issues tokens shaped
			// `<8-10 digit bot id>:AA<33 char base64url>`; the literal
			// `:AA` byte pair starts the second segment for every token
			// the BotFather has ever issued.
			expression: `\d{8,10}:AA[A-Za-z0-9_-]{33}`,
			keywords:   []string{":AA"},
		},
		{
			// flyio-macaroon. Fly.io API tokens are macaroons whose
			// printable form always starts with the literal `FlyV1 fm2_`
			// prefix followed by a long base64url body. The space inside
			// the prefix is part of the token (Fly's CLI emits it
			// verbatim). Capping the body at 400 chars stops the regex
			// from swallowing arbitrary trailing text when the token is
			// not separated from following content by whitespace.
			expression: `FlyV1 fm2_[A-Za-z0-9_=-]{40,400}`,
			keywords:   []string{"FlyV1 fm2_"},
		},
		{
			// groq-api-key. Groq Cloud API keys carry the `gsk_` prefix
			// followed by a fixed 52-character alphanumeric body.
			expression: `gsk_[A-Za-z0-9]{52}`,
			keywords:   []string{"gsk_"},
		},
		{
			// perplexity-api-key. Perplexity API keys carry the `pplx-`
			// prefix followed by a 48-56 char alphanumeric body (length
			// has shifted slightly between issuance epochs).
			expression: `pplx-[A-Za-z0-9]{48,56}`,
			keywords:   []string{"pplx-"},
		},
		{
			// xai-api-key. xAI / Grok API keys carry the `xai-` prefix
			// followed by an 80-character alphanumeric body.
			expression: `xai-[A-Za-z0-9]{80}`,
			keywords:   []string{"xai-"},
		},
		{
			// cohere-api-key. Cohere's modern API keys carry the `co_`
			// prefix and a 40-char alphanumeric body. Older trial keys
			// without the prefix are unfortunately too generic to
			// match without a `cohere` keyword anchor.
			expression: `co_[A-Za-z0-9]{40}`,
			keywords:   []string{"co_"},
		},
		{
			// buildkite-agent-token. Agent registration tokens carry the
			// `bkua_` prefix and a 40-character alphanumeric body. Leakage
			// lets attackers register fake agents in a Buildkite cluster.
			expression: `bkua_[a-zA-Z0-9]{40}`,
			keywords:   []string{"bkua_"},
		},
		{
			// circleci-project-token. Project-scoped CircleCI API tokens
			// carry the `CCIPRJ_` prefix followed by `<vcs-org>_<token>`.
			// User-scoped personal tokens are 40-char hex without a
			// prefix and are too generic to match safely on their own.
			expression: `CCIPRJ_[A-Za-z0-9_-]+_[A-Za-z0-9_-]{32,}`,
			keywords:   []string{"CCIPRJ_"},
		},
		{
			// cloudinary-url. Cloudinary SDK credentials are passed as a
			// single URL whose userinfo segment carries the API key and
			// secret. The `cloudinary://` scheme is unique to this
			// product so we redact the whole URL.
			expression: `cloudinary://\d+:[A-Za-z0-9_-]+@[A-Za-z0-9_-]+`,
			keywords:   []string{"cloudinary://"},
		},
		{
			// mongodb-connection-string. The userinfo of a `mongodb://` /
			// `mongodb+srv://` URI carries the database password. We
			// preserve the scheme + username + host so log readers can
			// still tell which cluster was being addressed, and only
			// scrub the password span. The 200-char upper bound stops
			// the regex from consuming arbitrary trailing content if a
			// connection string is missing the `@` terminator.
			expression: `mongodb(?:\+srv)?://[^\s:/?#@]+:(?P<secret>[^\s@]{1,200})@`,
			keywords:   []string{"mongodb://", "mongodb+srv://"},
		},
		{
			// postgres-connection-string. Same shape as the MongoDB rule:
			// only the URI password is redacted so the surrounding
			// `postgresql://user@host/db` framing stays readable.
			expression: `postgres(?:ql)?://[^\s:/?#@]+:(?P<secret>[^\s@]{1,200})@`,
			keywords:   []string{"postgres://", "postgresql://"},
		},
		{
			// azure-storage-connection-string. The `AccountKey=` field is
			// the actual secret; the surrounding `DefaultEndpointsProtocol`
			// / `AccountName` framing is only metadata. The base64 value
			// is typically 88 chars (44-byte key) but we accept anything
			// from 20 chars upwards to cover shorter SAS-signing keys.
			expression: `DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=(?P<secret>[A-Za-z0-9+/=]{20,})`,
			keywords:   []string{"DefaultEndpointsProtocol="},
		},
		{
			// mapbox-secret-key. Mapbox publishable keys (`pk.<60>.<22>`)
			// are already covered; secret keys share the same shape with
			// the `sk.` prefix and grant write access to the Mapbox
			// account.
			expression: `(?i)sk\.[a-z0-9]{60}\.[a-z0-9]{22}`,
			keywords:   []string{"sk."},
		},
		{
			// vault-batch-token. HashiCorp Vault batch tokens follow the
			// same `<prefix>.<base64url body>` shape as service tokens
			// but use the `hvb.` prefix.
			expression: `hvb\.[A-Za-z0-9_-]{90,200}`,
			keywords:   []string{"hvb."},
		},
		{
			// vault-recovery-token. Recovery tokens are issued during
			// initialisation of an auto-unsealed Vault and carry the
			// `hvr.` prefix; full root-equivalent if leaked.
			expression: `hvr\.[A-Za-z0-9_-]{90,200}`,
			keywords:   []string{"hvr."},
		},
		{
			// netlify-pat. Netlify personal access tokens carry the
			// `nfp_` prefix and a 40-character alphanumeric body.
			expression: `nfp_[A-Za-z0-9]{40}`,
			keywords:   []string{"nfp_"},
		},
		{
			// asana-pat. Asana personal access tokens are shaped
			// `1/<numeric workspace id>:<32 hex>`. The numeric workspace
			// id is at least 14 digits in practice, which keeps the rule
			// from firing on innocuous `1/<short>` substrings (page
			// numbers, fractions, paths). The existing `asana-*` rules
			// only fire when the literal word `asana` appears nearby; this
			// rule fills the gap for bare leakage in CLI output / logs.
			expression: `1/\d{14,}:[a-f0-9]{32}`,
			keywords:   []string{"1/"},
		},
		{
			// cloudflare-origin-ca-key. Cloudflare's Origin CA keys are
			// printed as `v1.0-<32 hex>-<146 base64>` and grant the
			// ability to issue certificates for any zone in the account.
			expression: `v1\.0-[a-f0-9]{32}-[A-Za-z0-9+/=]{146}`,
			keywords:   []string{"v1.0-"},
		},

		// --- Third batch of additions: vendor-prefixed credentials
		// confirmed against gitleaks default rules and vendor docs.
		// Each format embeds a unique prefix that keeps the keyword
		// pre-filter cheap and the regex tight enough to match without
		// surrounding-context anchors.

		{
			// 1password-service-account-token. Service-account tokens
			// always start with `ops_eyJ` — the `eyJ` is the base64
			// prefix of `{"`, since the body is a JWT-style envelope
			// over a 1Password macaroon. The literal `ops_eyJ` keyword
			// keeps the AC pre-filter extremely selective. The 1000-char
			// upper bound covers the longest 1Password tokens observed
			// in the wild (and is RE2's hard cap on a single quantifier)
			// while preventing the regex from absorbing arbitrary
			// trailing alphanumeric content if a token is not
			// whitespace-terminated.
			expression: `ops_eyJ[A-Za-z0-9+/=_-]{250,1000}`,
			keywords:   []string{"ops_eyJ"},
		},
		{
			// openrouter-api-key. OpenRouter (LLM router) keys carry
			// the documented `sk-or-v1-` prefix followed by a 64-char
			// lowercase-hex body.
			expression: `sk-or-v1-[a-f0-9]{64}`,
			keywords:   []string{"sk-or-v1-"},
		},
		{
			// sonar-token. SonarQube / SonarCloud user (`squ_`),
			// project (`sqp_`), and global-analysis (`sqa_`) tokens
			// share a 40-char hex body. The prefix is mandatory —
			// gitleaks' upstream rule treats it as optional, but doing
			// so flags any 40-char hex blob and is too noisy for our
			// agent-output use case.
			expression: `(squ|sqp|sqa)_[a-f0-9]{40}`,
			keywords:   []string{"squ_", "sqp_", "sqa_"},
		},
		{
			// pinecone-api-key. Pinecone vector-DB keys carry the
			// `pckey_` prefix; the body is a `<label>_<token>` pair of
			// base64url-ish segments. Both segments are bounded so the
			// regex can't swallow neighbouring identifiers when a key
			// abuts other text without a separator.
			expression: `pckey_[A-Za-z0-9]{1,40}_[A-Za-z0-9_-]{24,80}`,
			keywords:   []string{"pckey_"},
		},
		{
			// supabase-secret-key. The 2024 `sb_publishable_` /
			// `sb_secret_` rotation introduced prefixed keys; only the
			// secret variant bypasses Row-Level Security and is worth
			// redacting. Body is base64url-ish, observed at ~56 chars;
			// the 80-char ceiling keeps the regex from absorbing trailing
			// text when the key isn't whitespace-terminated.
			expression: `sb_secret_[A-Za-z0-9_-]{40,80}`,
			keywords:   []string{"sb_secret_"},
		},
		{
			// tailscale-auth-key. Used to enroll new nodes into a
			// Tailnet without an interactive login. The `tskey-auth-`
			// prefix is documented; the body is a `<id>-<secret>` pair
			// of alphanumeric segments. Both segments are bounded so
			// the regex can't swallow adjacent text.
			expression: `tskey-auth-[A-Za-z0-9]{10,30}-[A-Za-z0-9]{20,80}`,
			keywords:   []string{"tskey-auth-"},
		},
		{
			// tailscale-api-access-token. Grants programmatic access
			// to the Tailscale control plane (devices, ACLs, keys).
			// Same `<id>-<secret>` body shape as the auth-key form
			// with the same upper bounds.
			expression: `tskey-api-[A-Za-z0-9]{10,30}-[A-Za-z0-9]{20,80}`,
			keywords:   []string{"tskey-api-"},
		},
		{
			// vercel-token. The 2023 token-format change introduced
			// three prefixed shapes that share a common alphanumeric
			// body: `vcp_` (personal access tokens), `vck_` (CLI /
			// deploy tokens), and `vci_` (integration tokens). Real
			// tokens are 24 chars; the 80-char ceiling stops the regex
			// from absorbing trailing text when the token isn't
			// whitespace-terminated.
			expression: `vc[kpi]_[A-Za-z0-9]{20,80}`,
			keywords:   []string{"vcp_", "vck_", "vci_"},
		},

		// --- Fourth batch of additions: payment processors, AI / data
		// platforms, and infra tokens. Each entry is anchored on a
		// vendor-issued prefix that is documented in vendor docs or
		// gitleaks default rules. Body lengths are tuned tight enough
		// to keep the false-positive rate low without missing real
		// tokens (we err on the conservative side rather than allow
		// open-ended quantifiers that could swallow neighbouring text).

		{
			// razorpay-key-id. Razorpay payment-API public key IDs are
			// shaped `rzp_(test|live)_<14 alnum>`. The matching account
			// secret is opaque (no prefix) so we can only redact the
			// key-id span, but leakage of the pair lets an attacker
			// authenticate against the Razorpay API — still worth
			// scrubbing the half we can identify.
			expression: `rzp_(test|live)_[A-Za-z0-9]{14}`,
			keywords:   []string{"rzp_test_", "rzp_live_"},
		},
		{
			// adyen-api-key. Adyen merchant API keys carry the `AQE`
			// prefix followed by a long base64 body (typically 200+
			// chars including `=` padding). The 100-char floor and
			// 400-char ceiling cover every observed shape while
			// preventing the regex from absorbing arbitrary trailing
			// alphanumeric content if a key isn't whitespace-terminated.
			expression: `AQE[A-Za-z0-9+/=]{100,400}`,
			keywords:   []string{"AQE"},
		},
		{
			// plaid-access-token. Plaid item access tokens have the
			// shape `access-(sandbox|development|production)-<UUID>`.
			// The environment segment plus the strict UUID body keeps
			// the rule extremely specific.
			expression: `access-(sandbox|development|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,
			keywords:   []string{"access-sandbox-", "access-development-", "access-production-"},
		},
		{
			// posthog-personal-api-token. PostHog issues personal API
			// tokens shaped `phx_<43 alnum>`. The body length is fixed
			// per their issuance, so the regex stays tight.
			expression: `phx_[A-Za-z0-9]{43}`,
			keywords:   []string{"phx_"},
		},
		{
			// render-api-key. Render's REST-API tokens carry the `rnd_`
			// prefix and a ~32-char alphanumeric body — leakage grants
			// full account access (deployments, env vars, services).
			// The 80-char ceiling stops the regex from absorbing trailing
			// text when the token isn't whitespace-terminated.
			expression: `rnd_[A-Za-z0-9_-]{30,80}`,
			keywords:   []string{"rnd_"},
		},
		{
			// honeycomb-api-key. Honeycomb v2 keys carry distinctive
			// prefixes — `hcaik_` for ingest keys (high blast: write
			// telemetry) and `hcaic_` for configuration keys (read /
			// modify dataset settings). Both share a 58-char
			// alphanumeric body.
			expression: `hca(ik|ic)_[A-Za-z0-9]{58}`,
			keywords:   []string{"hcaik_", "hcaic_"},
		},
		{
			// akamai-edgegrid-client-token. Akamai EdgeGrid API client
			// tokens follow the `akab-<16 alnum>-<16 alnum>` shape
			// documented for `.edgerc` config files.
			expression: `akab-[a-z0-9]{16}-[a-z0-9]{16}`,
			keywords:   []string{"akab-"},
		},
		{
			// adafruit-io-key. Adafruit IO keys carry the `aio_` prefix
			// and a 28-character alphanumeric body — leakage allows
			// reading / writing IoT feeds attached to the account.
			expression: `aio_[A-Za-z0-9]{28}`,
			keywords:   []string{"aio_"},
		},

		{
			// 1password-secret-key. The user-side "Secret Key" combined
			// with the master password to derive the account-encryption
			// key for 1Password vaults. Format is
			// `A3-<6 alnum>-(<11 alnum>|<6 alnum>-<5 alnum>)-<5>-<5>-<5>`,
			// all uppercase. Leakage of the Secret Key alone isn't
			// sufficient to unlock a vault (the master password is
			// still required), but it's part of a recovery pair that
			// must remain confidential and is treated as a secret in
			// every 1Password compliance regime.
			expression: `A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`,
			keywords:   []string{"A3-"},
		},

		// --- Fifth batch of additions: extra credentials cross-checked
		// against the canonical gitleaks default ruleset and the
		// associated vendor docs. Each entry targets a vendor-prefixed
		// shape that's specific enough to keep the keyword pre-filter
		// cheap and the regex's false-positive rate low.

		// GitLab token family. The platform issues a long list of
		// short-prefixed tokens beyond `glpat-` / `glptt-` (the two
		// already covered by the rules above): each one grants a
		// distinct slice of project / runner / SCIM authority and is
		// emitted by `glab` / API responses without surrounding
		// quotes. Bodies are bounded by GitLab's documented issuance
		// shapes; using `[0-9a-zA-Z_-]` keeps the regex aligned with
		// gitleaks and matches every body byte GitLab is known to
		// emit.
		{
			// gitlab-cicd-job-token. `glcbt-` prefix; body is a short
			// project identifier, an underscore, then a 20-char body.
			expression: `glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`,
			keywords:   []string{"glcbt-"},
		},
		{
			// gitlab-deploy-token. `gldt-` prefix + 20-char body.
			expression: `gldt-[0-9a-zA-Z_-]{20}`,
			keywords:   []string{"gldt-"},
		},
		{
			// gitlab-feature-flag-client-token. `glffct-` prefix.
			expression: `glffct-[0-9a-zA-Z_-]{20}`,
			keywords:   []string{"glffct-"},
		},
		{
			// gitlab-feed-token. `glft-` prefix; user-scoped read access
			// to the user's GitLab activity feeds.
			expression: `glft-[0-9a-zA-Z_-]{20}`,
			keywords:   []string{"glft-"},
		},
		{
			// gitlab-kubernetes-agent-token. `glagent-` prefix and a
			// 50-char body — used by the `kas` agent to authenticate
			// against a GitLab control plane.
			expression: `glagent-[0-9a-zA-Z_-]{50}`,
			keywords:   []string{"glagent-"},
		},
		{
			// gitlab-oauth-app-secret. `gloas-` prefix and a 64-char
			// body — leakage of an OAuth app secret lets attackers
			// impersonate the application during the OAuth dance.
			expression: `gloas-[0-9a-zA-Z_-]{64}`,
			keywords:   []string{"gloas-"},
		},
		{
			// gitlab-runner-registration-token. The `GR1348941` prefix
			// (uppercase, fixed) is documented for runner registration
			// tokens; the trailing 20-char body uses the same charset
			// as the rest of the GitLab tokens.
			expression: `GR1348941[0-9a-zA-Z_-]{20}`,
			keywords:   []string{"GR1348941"},
		},
		{
			// gitlab-runner-authentication-token. `glrt-` prefix; same
			// 20-char body charset as the deploy / feed token shapes.
			expression: `glrt-[0-9a-zA-Z_-]{20}`,
			keywords:   []string{"glrt-"},
		},
		{
			// gitlab-scim-token. `glsoat-` prefix; grants SCIM
			// (user-provisioning) access at the group / instance level.
			expression: `glsoat-[0-9a-zA-Z_-]{20}`,
			keywords:   []string{"glsoat-"},
		},
		{
			// gitlab-pat-routable. The 2024 routable PAT format extends
			// the legacy `glpat-<20>` shape with a longer (27-300 char)
			// body and an appended `.<2-char prefix><7-char hex>`
			// checksum/routing suffix. The legacy `gitlab-pat` rule above
			// only matches the first 20 chars of the body, leaving the
			// rest visible — this rule covers the full routable token in
			// one redaction.
			expression: `glpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{9}`,
			keywords:   []string{"glpat-"},
		},

		// LLM-provider key formats added since the previous batches.

		{
			// aws-bedrock-long-lived-api-key. The 2024 Bedrock
			// programmatic-access keys carry the `ABSK` prefix followed
			// by a 109-269 char base64 body (lengths vary with the
			// embedded scope / metadata, plus optional `=` padding).
			expression: `ABSK[A-Za-z0-9+/]{109,269}={0,2}`,
			keywords:   []string{"ABSK"},
		},
		{
			// aws-bedrock-short-lived-api-key. Short-lived Bedrock keys
			// embed the literal `bedrock-api-key-` prefix followed by a
			// fixed `YmVkcm9jay5hbWF6b25hd3MuY29t` segment (base64 of
			// `bedrock.amazonaws.com`) and then the actual body. The
			// distinctive base64 marker keeps the keyword filter
			// extremely selective.
			expression: `bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t[A-Za-z0-9+/=_-]{20,400}`,
			keywords:   []string{"bedrock-api-key-"},
		},

		// Cloud / PaaS credentials.

		{
			// heroku-api-key-v2. Heroku's 2024 token format superseded
			// the legacy `[0-9A-F]{8}-…` UUID shape (which the existing
			// `heroku-api-key` rule still matches when prefixed with
			// the `heroku` keyword). The new tokens carry an `HRKU-AA`
			// prefix + 58-char base64url body and are emitted bare by
			// the Heroku CLI / API responses.
			expression: `HRKU-AA[0-9a-zA-Z_-]{58}`,
			keywords:   []string{"HRKU-AA"},
		},
		{
			// azure-ad-client-secret. Azure AD / Entra ID v2 client
			// secrets always embed a `<3 chars>dQ~` infix between the
			// 3-char header and the 31-34 char body. The keyword `q~`
			// stays selective enough on real-world text (the digit-Q-
			// tilde sequence is rare outside this format) for the AC
			// pre-filter to remain useful.
			expression: `[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}`,
			keywords:   []string{"Q~"},
		},
		{
			// openshift-user-token. OpenShift / OKD user OAuth tokens
			// carry the literal `sha256~` prefix and a 43-char
			// base64url body. Leakage grants full kubeconfig-equivalent
			// access until the token expires.
			expression: `sha256~[A-Za-z0-9_-]{43}`,
			keywords:   []string{"sha256~"},
		},
		{
			// planetscale-oauth-token. The third PlanetScale token shape
			// (alongside `pscale_pw_` / `pscale_tkn_`) covers OAuth
			// flow-issued tokens and includes dots / equals signs from
			// base64url padding.
			expression: `pscale_oauth_[A-Za-z0-9_=.-]{32,80}`,
			keywords:   []string{"pscale_oauth_"},
		},

		// Observability tokens.

		{
			// grafana-cloud-api-token. The Grafana Cloud-issued tokens
			// (distinct from the legacy `eyJrIjoi…` HTTP-API tokens)
			// carry the `glc_` prefix and a 32-400 char base64 body
			// with optional `=` padding.
			expression: `glc_[A-Za-z0-9+/]{32,400}={0,3}`,
			keywords:   []string{"glc_"},
		},
		{
			// grafana-service-account-token. Service-account tokens use
			// the `glsa_<32 alnum>_<8 hex CRC>` shape — the trailing
			// 8-char hex CRC keeps the regex tight even though the body
			// itself is purely alphanumeric.
			expression: `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`,
			keywords:   []string{"glsa_"},
		},
		{
			// new-relic-insert-key. Used by data-ingest paths (Events /
			// Metric / Log APIs); distinct from the user-API (`NRAK-`)
			// and browser (`NRJS-`) keys already covered. Body is 32
			// hex characters with optional dashes (no fixed positions).
			expression: `NRII-[a-zA-Z0-9-]{32}`,
			keywords:   []string{"NRII-"},
		},
		{
			// sentry-user-token. The personal user-token format uses
			// the `sntryu_` prefix + 64-char lowercase hex body —
			// distinct from the org-scoped `sntrys_eyJ…` tokens already
			// covered.
			expression: `sntryu_[a-f0-9]{64}`,
			keywords:   []string{"sntryu_"},
		},

		// Communication / messaging webhooks.

		{
			// slack-app-token. App-level tokens (used for Slack's
			// Socket Mode) follow `xapp-<digit>-<workspace>-<int>-<hex>`.
			// The four-segment shape is distinct from the bot / user /
			// rotating tokens already covered by the slack-access /
			// slack-rotating rules.
			expression: `xapp-\d-[A-Z0-9]{8,16}-\d{8,16}-[a-fA-F0-9]{32,128}`,
			keywords:   []string{"xapp-"},
		},
		{
			// microsoft-teams-incoming-webhook. The full URL is itself a
			// bearer credential — anyone holding it can post arbitrary
			// content to the channel. The fixed `webhook.office.com`
			// host plus the strictly UUID-shaped path segments keep the
			// regex specific.
			expression: `https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-zA-Z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}`,
			keywords:   []string{"webhook.office.com"},
		},

		// CI / CD / DevOps platforms.

		{
			// jfrog-reference-token. Distinct from `AKCp` API keys —
			// reference tokens carry the literal `cmVmd` base64-prefix
			// (decoding to `refd`) followed by a 59-char alphanumeric
			// body. Leakage grants the same scope as a referenced
			// access token until the latter is revoked.
			expression: `cmVmd[A-Za-z0-9]{59}`,
			keywords:   []string{"cmVmd"},
		},
		{
			// infracost-api-token. Cost-estimation API tokens carry the
			// `ico-` prefix and a 32-char alphanumeric body.
			expression: `ico-[A-Za-z0-9]{32}`,
			keywords:   []string{"ico-"},
		},
		{
			// prefect-api-token. Prefect Cloud user tokens carry the
			// `pnu_` prefix and a 36-char alphanumeric body.
			expression: `pnu_[A-Za-z0-9]{36}`,
			keywords:   []string{"pnu_"},
		},
		{
			// readme-api-token. Readme.com (docs hosting) tokens carry
			// the `rdme_` prefix and a 70-char lowercase-alphanumeric
			// body.
			expression: `rdme_[a-z0-9]{70}`,
			keywords:   []string{"rdme_"},
		},
		{
			// maxmind-license-key. License keys for the GeoIP / GeoLite2
			// download feeds always end with the literal `_mmk` suffix
			// after a `<6 alnum>_<29 alnum>` body, which keeps the
			// keyword anchor cheap.
			expression: `[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk`,
			keywords:   []string{"_mmk"},
		},

		// Vendor-specific cloud / data / dev tokens with distinctive prefixes.

		{
			// clickhouse-cloud-api-secret-key. ClickHouse Cloud secret
			// keys are 42 chars total and start with the literal `4b1d`
			// marker (a vendor-defined leading 4 bytes), followed by a
			// 38-char alphanumeric body.
			expression: `4b1d[A-Za-z0-9]{38}`,
			keywords:   []string{"4b1d"},
		},
		{
			// yandex-cloud-api-key. Service-account API keys carry the
			// uppercase `AQVN` prefix + 35-38 char base64url body.
			expression: `AQVN[A-Za-z0-9_-]{35,38}`,
			keywords:   []string{"AQVN"},
		},
		{
			// facebook-page-access-token. Distinct from the legacy
			// contextual `facebook-token` rule above. Page access tokens
			// carry the `EAAM` (live) or `EAAC` (Marketing API) prefix
			// and a 100-400 char alphanumeric body. The 4th-letter
			// disambiguates against Square's `EAAA` access-token rule.
			expression: `EAA[MC][A-Za-z0-9]{100,400}`,
			keywords:   []string{"EAAM", "EAAC"},
		},
		{
			// sourcegraph-access-token. Sourcegraph (code-search) access
			// tokens carry the `sgp_` prefix and either a 40-char hex
			// body (legacy) or `<16-hex-or-`local`>_<40-hex>` (current).
			// We match both shapes in a single rule.
			expression: `sgp_(?:(?:[a-fA-F0-9]{16}|local)_)?[a-fA-F0-9]{40}`,
			keywords:   []string{"sgp_"},
		},
		{
			// defined-networking-api-token. The Defined Networking
			// (Nebula control plane) tokens carry the `dnkey-` prefix
			// followed by a `<26 alnum>-<52 alnum>` body.
			expression: `dnkey-[A-Za-z0-9_=-]{26}-[A-Za-z0-9_=-]{52}`,
			keywords:   []string{"dnkey-"},
		},
		{
			// scalingo-api-token. Scalingo PaaS API tokens carry the
			// region-anchored `tk-us-` prefix and a 48-char body. Other
			// regions (`tk-eu-`, `tk-osc-…`) follow the same shape; we
			// list every region prefix gitleaks documents.
			expression: `tk-(?:us|eu|osc-fr1|osc-secnum-fr1)-[A-Za-z0-9_-]{48}`,
			keywords:   []string{"tk-us-", "tk-eu-", "tk-osc-"},
		},

		// --- Sixth batch of additions: high-value contextual rules
		// for vendors whose tokens carry NO unique prefix and can
		// therefore only be detected when their vendor name appears
		// nearby. Each rule is generated by the [contextual] helper,
		// which expands to gitleaks' default-rule frame: a lazy 50-char
		// vendor-word context, an assignment operator, then the value
		// (the only span that gets redacted). The keyword pre-filter
		// ensures the regex doesn't run on inputs that don't mention
		// the vendor at all.

		{
			// datadog-access-token. 40-char hex API key for the Datadog
			// observability platform; high blast radius (account-wide
			// telemetry ingest + dashboard / monitor management).
			expression: contextual(`datadog`, `[a-z0-9]{40}`),
			keywords:   []string{"datadog"},
		},
		{
			// snyk-api-token. UUID-shaped API token for Snyk security
			// scanning; leakage exposes vulnerability findings and the
			// ability to disable scans.
			expression: contextual(`snyk`, `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
			keywords:   []string{"snyk"},
		},
		{
			// launchdarkly-access-token. Feature-flag platform; leakage
			// lets attackers toggle production flags.
			expression: contextual(`launchdarkly`, `[a-z0-9=_\-]{40}`),
			keywords:   []string{"launchdarkly"},
		},
		{
			// cloudflare-api-key. The current 40-char alphanumeric API
			// key (distinct from the legacy 37-hex global key below and
			// from the prefixed origin-CA key already covered).
			expression: contextual(`cloudflare`, `[a-z0-9_-]{40}`),
			keywords:   []string{"cloudflare"},
		},
		{
			// cloudflare-global-api-key. Legacy 37-hex global API key —
			// full account access; deprecated in favour of scoped keys
			// but still widely deployed in older configurations.
			expression: contextual(`cloudflare`, `[a-f0-9]{37}`),
			keywords:   []string{"cloudflare"},
		},
		{
			// confluent-access-token. Short 16-char access token issued
			// by Confluent Cloud (managed Kafka). Pair with the secret
			// rule below for full credential coverage.
			expression: contextual(`confluent`, `[a-z0-9]{16}`),
			keywords:   []string{"confluent"},
		},
		{
			// confluent-secret-key. 64-char secret half of a Confluent
			// Cloud API credential pair.
			expression: contextual(`confluent`, `[a-z0-9]{64}`),
			keywords:   []string{"confluent"},
		},
		{
			// looker-client-id. 20-char alphanumeric client ID for the
			// Looker (Google Cloud) BI platform API.
			expression: contextual(`looker`, `[a-z0-9]{20}`),
			keywords:   []string{"looker"},
		},
		{
			// looker-client-secret. 24-char alphanumeric client secret;
			// pairs with the client-id above.
			expression: contextual(`looker`, `[a-z0-9]{24}`),
			keywords:   []string{"looker"},
		},
		{
			// mattermost-access-token. 26-char alphanumeric personal
			// access token for the Mattermost chat platform.
			expression: contextual(`mattermost`, `[a-z0-9]{26}`),
			keywords:   []string{"mattermost"},
		},
		{
			// sumologic-access-token. 64-char alphanumeric access token
			// for the Sumo Logic log-management platform. The vendor
			// keyword `sumo` covers `sumo`, `Sumo`, and `SUMO` because
			// the AC pre-filter is case-folded.
			expression: contextual(`sumo`, `[a-z0-9]{64}`),
			keywords:   []string{"sumo"},
		},
		{
			// travisci-access-token. 22-char alphanumeric Travis CI
			// API token; matched on the shorter `travis` keyword.
			expression: contextual(`travis`, `[a-z0-9]{22}`),
			keywords:   []string{"travis"},
		},
		{
			// zendesk-secret-key. 40-char alphanumeric secret key for
			// the Zendesk customer-support platform.
			expression: contextual(`zendesk`, `[a-z0-9]{40}`),
			keywords:   []string{"zendesk"},
		},
		{
			// codecov-access-token. 32-char alphanumeric access token
			// for the Codecov coverage-report service.
			expression: contextual(`codecov`, `[a-z0-9]{32}`),
			keywords:   []string{"codecov"},
		},
		{
			// algolia-api-key. 32-char alphanumeric API key for the
			// Algolia search platform; admin keys allow index changes.
			expression: contextual(`algolia`, `[a-z0-9]{32}`),
			keywords:   []string{"algolia"},
		},
		{
			// airtable-api-key. Legacy 17-char alphanumeric Airtable
			// API key (the modern PAT format `pat<14>.<64hex>` is
			// covered separately when its prefix becomes detectable).
			expression: contextual(`airtable`, `[a-z0-9]{17}`),
			keywords:   []string{"airtable"},
		},
		{
			// sendbird-access-token. 40-char hex access token for the
			// SendBird in-app messaging platform.
			expression: contextual(`sendbird`, `[a-f0-9]{40}`),
			keywords:   []string{"sendbird"},
		},

		// --- Seventh batch of additions: patterns identified by
		// cross-referencing gitleaks, trufflehog, and detect-secrets
		// rule catalogues for vendor-prefixed credentials not yet
		// covered. Includes connection-string rules for popular
		// databases / message brokers that follow the same
		// password-only-redaction design as the existing MongoDB /
		// Postgres / Azure Storage rules.

		// Prefix-based rules.

		{
			// figma-personal-access-token. Figma REST-API personal
			// access tokens carry the `figd_` prefix and a 22-100
			// char alphanumeric body. Leakage grants full API access
			// to files, projects, and team resources.
			expression: `figd_[A-Za-z0-9_-]{22,100}`,
			keywords:   []string{"figd_"},
		},
		{
			// contentful-personal-access-token. The `CFPAT-` prefix
			// is documented for Contentful personal access tokens;
			// the body is 43 chars of base64url-ish content.
			expression: `CFPAT-[A-Za-z0-9_-]{43}`,
			keywords:   []string{"CFPAT-"},
		},
		{
			// doppler-extra-tokens. Doppler issues five additional
			// token types beyond the personal token (`dp.pt.`)
			// already covered: service (`dp.st.`), CLI (`dp.ct.`),
			// SCIM (`dp.scim.`), audit (`dp.audit.`), and service-
			// account (`dp.sa.`) tokens. All share the same 43-char
			// alphanumeric body.
			expression: `dp\.(st|ct|scim|audit|sa)\.(?i)[a-z0-9]{43}`,
			keywords:   []string{"dp.st.", "dp.ct.", "dp.scim.", "dp.audit.", "dp.sa."},
		},
		{
			// hubspot-private-app-token. HubSpot's 2023 Private App
			// Token format carries a data-center prefix (`na1` for
			// North America, `eu1` for the EU) followed by a UUID
			// body. The existing `hubspot-api-token` rule only fires
			// with the `hubspot` keyword nearby; this rule catches
			// bare tokens in CLI output / logs.
			expression: `pat-(?:na1|eu1)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,
			keywords:   []string{"pat-na1-", "pat-eu1-"},
		},
		{
			// launchdarkly-sdk-key. LaunchDarkly SDK keys follow the
			// `sdk-<UUID>` shape and are used to initialise server-
			// side SDKs. Leakage exposes feature-flag evaluation
			// logic and targeting rules. The existing contextual
			// `launchdarkly` rule requires the vendor name nearby;
			// this rule catches bare SDK keys.
			expression: `sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,
			keywords:   []string{"sdk-"},
		},
		{
			// braintree-access-token. Braintree (PayPal) access
			// tokens use `$`-delimited segments:
			// `access_token$<env>$<merchant_id>$<token>`. The literal
			// `$` makes the format highly distinctive.
			expression: `access_token\$(?:production|sandbox)\$[a-z0-9]{1,128}\$[a-f0-9]{25,36}`,
			keywords:   []string{"access_token$"},
		},
		{
			// azure-devops-pat. Azure DevOps personal access tokens
			// begin with the base64 bytes `oy2` followed by a 43-49
			// char base64url body. The same PAT authenticates Azure
			// DevOps REST APIs, NuGet feeds, and Azure Artifacts.
			expression: `oy2[A-Za-z0-9+/]{43,49}={0,2}`,
			keywords:   []string{"oy2"},
		},

		// Connection-string rules (password-only redaction).

		{
			// mysql-connection-string. Same design as the existing
			// MongoDB / Postgres rules: only the URI password is
			// redacted so the surrounding `mysql://user@host/db`
			// framing stays readable.
			expression: `mysql://[^\s:/?#@]+:(?P<secret>[^\s@]{1,200})@`,
			keywords:   []string{"mysql://"},
		},
		{
			// redis-connection-string. Redis URIs support both
			// `redis://user:password@host` (ACL) and the older
			// `redis://:password@host` (no username) forms. The
			// TLS variant uses the `rediss://` scheme. Only the
			// password span is redacted.
			expression: `rediss?://[^\s:/?#@]*:(?P<secret>[^\s@]{1,200})@`,
			keywords:   []string{"redis://", "rediss://"},
		},
		{
			// amqp-connection-string. RabbitMQ and other AMQP
			// brokers accept `amqp://user:password@host` URIs;
			// the TLS variant uses `amqps://`. Only the password
			// span is redacted.
			expression: `amqps?://[^\s:/?#@]+:(?P<secret>[^\s@]{1,200})@`,
			keywords:   []string{"amqp://", "amqps://"},
		},

		// --- Eighth batch: prefix-anchored vendor tokens cross-
		// checked against the gitleaks default ruleset.

		{
			// harness-api-key. Both Personal Access Tokens (`pat.`)
			// and Service Account Tokens (`sat.`) follow the same
			// three-segment shape; full Harness account access if
			// leaked. Source: gitleaks `harness-api-key` rule.
			expression: `(?:pat|sat)\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{20}`,
			keywords:   []string{"pat.", "sat."},
		},
		{
			// huggingface-organization-api-token. Legacy Hugging
			// Face org tokens carry the `api_org_` prefix and a
			// 34-char alphanumeric body. Still active alongside
			// the modern `hf_` user tokens already covered.
			expression: `api_org_[A-Za-z0-9]{34}`,
			keywords:   []string{"api_org_"},
		},
		{
			// settlemint-tokens. Three token families share the same
			// shape: personal (`sm_pat_`), application (`sm_aat_`),
			// and service (`sm_sat_`) access tokens, each with a
			// 16-char alphanumeric body. Source: gitleaks
			// `settlemint-{personal,application,service}-access-token`.
			expression: `sm_(?:pat|aat|sat)_[A-Za-z0-9]{16}`,
			keywords:   []string{"sm_pat_", "sm_aat_", "sm_sat_"},
		},
	}
})

// compiledRule is the runtime form of a [rule]: its keywords are
// folded into a [kwMask] over the catalogue's shared keyword index,
// and its regex is compiled lazily on first match. A clean input —
// the overwhelmingly common case — therefore never pays for
// compiling any of the ~175 expressions in the catalogue, only for
// the keyword bitset and the AC table.
type compiledRule struct {
	kwBits  kwMask
	compile func() (*regexp.Regexp, int) // memoised; returns (re, secretIdx)
}

// ruleSet bundles the runtime catalogue with the Aho–Corasick
// pre-filter built from its (de-duplicated) keyword set. They live
// behind a single [sync.OnceValue] so neither piece of state is
// constructed until the first scan that actually needs it; per-rule
// regex compilation is further deferred via
// [compiledRule.compile].
type ruleSet struct {
	rules []compiledRule
	ac    *acAutomaton
}

var compiledRuleSet = sync.OnceValue(func() *ruleSet {
	src := rules()

	// Assign an index to every distinct (lower-cased) keyword. Rules
	// share keywords like "discord" or "bitbucket" — deduplication
	// means the AC scans for them once and each rule's bitset refers
	// to the shared slot.
	kwIdx := make(map[string]int)
	var uniq []string
	for _, r := range src {
		for _, k := range r.keywords {
			lk := strings.ToLower(k)
			if _, ok := kwIdx[lk]; !ok {
				kwIdx[lk] = len(uniq)
				uniq = append(uniq, lk)
			}
		}
	}

	rules := make([]compiledRule, len(src))
	for i, r := range src {
		var bits kwMask
		for _, k := range r.keywords {
			bits.set(kwIdx[strings.ToLower(k)])
		}
		expr := r.expression // bind for the closure below
		rules[i] = compiledRule{
			kwBits: bits,
			compile: sync.OnceValues(func() (*regexp.Regexp, int) {
				re := regexp.MustCompile(expr)
				return re, re.SubexpIndex("secret")
			}),
		}
	}
	return &ruleSet{rules: rules, ac: buildAhoCorasick(uniq)}
})
