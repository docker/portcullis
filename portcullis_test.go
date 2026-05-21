package portcullis_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/portcullis"
)

// TestContainsRecognisesKnownTokens: parity guarantee with the
// upstream docker/mcp-gateway/pkg/secretsscan tests. Failing this
// test means we either dropped a rule or broke the keyword pre-filter.
func TestContainsRecognisesKnownTokens(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		text string
	}{
		{"github_pat", "ghp_cxLeRrvbJfmYdUtr70xnNE3Q7Gvli43s19PD"},
		{"docker_pat", "dckr_pat_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"docker_oat", "dckr_oat_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		// Patterns added on top of the upstream catalogue. Each value
		// is split across string concatenation so the verbatim token
		// never appears on a single source line in case downstream
		// tooling scans the test file itself.
		{"openai_project_key", "sk-proj-" + strings.Repeat("A", 25) + "T3Blbk" + "FJ" + strings.Repeat("B", 25)},
		{"anthropic_api_key", "sk-ant-" + "api03-" + strings.Repeat("X", 93) + "AA"},
		{"google_api_key", "AIza" + strings.Repeat("a", 35)},
		{"google_oauth_client_secret", "GOCSPX-" + strings.Repeat("a", 28)},
		{"digitalocean_pat", "dop_v1_" + strings.Repeat("a", 64)},
		{"stripe_webhook_signing_secret", "whsec_" + strings.Repeat("a", 40)},
		{"jfrog_api_key", "AKCp" + strings.Repeat("a", 73)},
		{"tencent_cloud_secret_id", "AKID" + strings.Repeat("a", 32)},
		{"sentry_user_auth_token", "sntrys_" + "eyJ" + strings.Repeat("a", 60)},
		{"stripe_restricted_key_test", "rk_test_" + strings.Repeat("a", 24)},
		{"stripe_restricted_key_live", "rk_live_" + strings.Repeat("a", 24)},
		{"notion_integration_token", "ntn_" + strings.Repeat("a", 46)},
		{"gitlab_pipeline_trigger_token", "glptt-" + strings.Repeat("a", 40)},
		{"vault_service_token", "hvs." + strings.Repeat("a", 95)},
		{"vault_service_token_long", "hvs." + strings.Repeat("a", 180)},
		{"slack_rotating_refresh_token", "xoxe-" + strings.Repeat("a", 60)},
		{"slack_rotating_user_token", "xoxe.xoxp-" + strings.Repeat("a", 50)},
		{"slack_rotating_bot_token", "xoxe.xoxb-" + strings.Repeat("a", 50)},
		{"slack_rotating_long_token", "xoxe.xoxp-" + strings.Repeat("a", 250)},
		{"replicate_api_token", "r8_" + strings.Repeat("a", 37)},
		{"square_access_token", "EAAA" + strings.Repeat("a", 60)},
		{"atlassian_cloud_api_token", "ATATT3xFfGF0" + strings.Repeat("a", 200)},
		{"digitalocean_oauth_token", "doo_v1_" + strings.Repeat("a", 64)},
		{"digitalocean_oauth_refresh", "dor_v1_" + strings.Repeat("a", 64)},
		// Second batch of additions (Discord / Telegram / Fly.io / LLM
		// providers / data-store URIs / Cloudflare Origin CA / etc.).
		{"discord_bot_token", "MTI" + strings.Repeat("a", 22) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 30)},
		{"discord_bot_token_n_prefix", "NDQ" + strings.Repeat("a", 22) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 30)},
		{"discord_webhook_url", "https://discord.com/api/webhooks/" + strings.Repeat("1", 18) + "/" + strings.Repeat("a", 60)},
		{"discord_webhook_legacy", "https://discordapp.com/api/webhooks/" + strings.Repeat("1", 18) + "/" + strings.Repeat("a", 60)},
		{"telegram_bot_token", strings.Repeat("1", 10) + ":AA" + strings.Repeat("a", 33)},
		{"flyio_macaroon", "FlyV1 " + "fm2_" + strings.Repeat("a", 80)},
		{"groq_api_key", "gsk_" + strings.Repeat("a", 52)},
		{"perplexity_api_key", "pplx-" + strings.Repeat("a", 48)},
		{"xai_api_key", "xai-" + strings.Repeat("a", 80)},
		{"cohere_api_key", "co_" + strings.Repeat("a", 40)},
		{"buildkite_agent_token", "bkua_" + strings.Repeat("a", 40)},
		{"circleci_project_token", "CCIPRJ_someorg_" + strings.Repeat("a", 40)},
		{"cloudinary_url", "cloudinary://" + strings.Repeat("1", 15) + ":" + strings.Repeat("a", 27) + "@" + strings.Repeat("b", 10)},
		{"mongodb_conn_string", "mongodb+srv://user:" + strings.Repeat("p", 24) + "@cluster.mongodb.net"},
		{"postgres_conn_string", "postgresql://user:" + strings.Repeat("p", 24) + "@db.example.com"},
		{"azure_storage_conn", "DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=" + strings.Repeat("a", 86) + "=="},
		{"mapbox_secret_key", "sk." + strings.Repeat("a", 60) + "." + strings.Repeat("b", 22)},
		{"vault_batch_token", "hvb." + strings.Repeat("a", 100)},
		{"vault_recovery_token", "hvr." + strings.Repeat("a", 100)},
		{"netlify_pat", "nfp_" + strings.Repeat("a", 40)},
		{"asana_pat", "1/" + strings.Repeat("1", 16) + ":" + strings.Repeat("a", 32)},
		{"cloudflare_origin_ca_key", "v1.0-" + strings.Repeat("a", 32) + "-" + strings.Repeat("b", 146)},
		// Third batch of additions — vendor-prefixed credentials
		// confirmed against gitleaks default rules and vendor docs.
		{"onepassword_service_account", "ops_eyJ" + strings.Repeat("a", 260)},
		{"openrouter_api_key", "sk-or-v1-" + strings.Repeat("a", 64)},
		{"sonar_user_token", "squ_" + strings.Repeat("a", 40)},
		{"sonar_project_token", "sqp_" + strings.Repeat("a", 40)},
		{"sonar_global_analysis_token", "sqa_" + strings.Repeat("a", 40)},
		{"pinecone_api_key", "pckey_" + "label_" + strings.Repeat("a", 32)},
		{"supabase_secret_key", "sb_secret_" + strings.Repeat("a", 48)},
		{"tailscale_auth_key", "tskey-auth-" + strings.Repeat("a", 12) + "-" + strings.Repeat("b", 32)},
		{"tailscale_api_access_token", "tskey-api-" + strings.Repeat("a", 12) + "-" + strings.Repeat("b", 32)},
		{"vercel_personal_access_token", "vcp_" + strings.Repeat("a", 24)},
		{"vercel_cli_token", "vck_" + strings.Repeat("a", 24)},
		{"vercel_integration_token", "vci_" + strings.Repeat("a", 24)},
		// Fourth batch — payment processors, AI / data platforms, infra.
		{"razorpay_test_key_id", "rzp_test_" + strings.Repeat("a", 14)},
		{"razorpay_live_key_id", "rzp_live_" + strings.Repeat("a", 14)},
		{"adyen_api_key", "AQE" + strings.Repeat("a", 200)},
		{"plaid_access_token_sandbox", "access-sandbox-" + strings.Repeat("a", 8) + "-" + strings.Repeat("b", 4) + "-" + strings.Repeat("c", 4) + "-" + strings.Repeat("d", 4) + "-" + strings.Repeat("e", 12)},
		{"plaid_access_token_production", "access-production-" + strings.Repeat("f", 8) + "-" + strings.Repeat("a", 4) + "-" + strings.Repeat("b", 4) + "-" + strings.Repeat("c", 4) + "-" + strings.Repeat("d", 12)},
		{"posthog_personal_api_token", "phx_" + strings.Repeat("a", 43)},
		{"render_api_key", "rnd_" + strings.Repeat("a", 32)},
		{"honeycomb_ingest_key", "hcaik_" + strings.Repeat("a", 58)},
		{"honeycomb_config_key", "hcaic_" + strings.Repeat("a", 58)},
		{"akamai_edgegrid_client_token", "akab-" + strings.Repeat("a", 16) + "-" + strings.Repeat("b", 16)},
		{"adafruit_io_key", "aio_" + strings.Repeat("a", 28)},
		// Fifth batch — GitLab token family beyond glpat- / glptt-,
		// modern AWS Bedrock keys, Heroku v2, Azure AD, OpenShift,
		// Grafana / New Relic / Sentry / Slack / Teams / JFrog refs,
		// and a few PaaS / data tokens.
		{"gitlab_cicd_job_token", "glcbt-" + "abc" + "_" + strings.Repeat("a", 20)},
		{"gitlab_deploy_token", "gldt-" + strings.Repeat("a", 20)},
		{"gitlab_feature_flag_client_token", "glffct-" + strings.Repeat("a", 20)},
		{"gitlab_feed_token", "glft-" + strings.Repeat("a", 20)},
		{"gitlab_kubernetes_agent_token", "glagent-" + strings.Repeat("a", 50)},
		{"gitlab_oauth_app_secret", "gloas-" + strings.Repeat("a", 64)},
		{"gitlab_runner_registration_token", "GR1348941" + strings.Repeat("a", 20)},
		{"gitlab_runner_authentication_token", "glrt-" + strings.Repeat("a", 20)},
		{"gitlab_scim_token", "glsoat-" + strings.Repeat("a", 20)},
		{"gitlab_pat_routable", "glpat-" + strings.Repeat("a", 50) + ".aa1234567"},
		{"aws_bedrock_long_lived_key", "ABSK" + strings.Repeat("a", 200)},
		{"aws_bedrock_short_lived_key", "bedrock-api-key-" + "YmVkcm9jay5hbWF6b25hd3MuY29t" + strings.Repeat("a", 60)},
		{"heroku_api_key_v2", "HRKU-AA" + strings.Repeat("a", 58)},
		{"azure_ad_client_secret", "abc" + "1Q~" + strings.Repeat("a", 33)},
		{"openshift_user_token", "sha256~" + strings.Repeat("a", 43)},
		{"planetscale_oauth_token", "pscale_oauth_" + strings.Repeat("a", 40)},
		{"grafana_cloud_api_token", "glc_" + strings.Repeat("a", 60)},
		{"grafana_service_account_token", "glsa_" + strings.Repeat("a", 32) + "_" + strings.Repeat("f", 8)},
		{"new_relic_insert_key", "NRII-" + strings.Repeat("a", 32)},
		{"sentry_user_token", "sntryu_" + strings.Repeat("a", 64)},
		{"slack_app_level_token", "xapp-1-A" + strings.Repeat("B", 10) + "-" + strings.Repeat("1", 12) + "-" + strings.Repeat("a", 64)},
		{
			"microsoft_teams_webhook",
			"https://example.webhook.office.com/webhookb2/" +
				strings.Repeat("a", 8) + "-" + strings.Repeat("b", 4) + "-" + strings.Repeat("c", 4) + "-" + strings.Repeat("d", 4) + "-" + strings.Repeat("e", 12) +
				"@" +
				strings.Repeat("a", 8) + "-" + strings.Repeat("b", 4) + "-" + strings.Repeat("c", 4) + "-" + strings.Repeat("d", 4) + "-" + strings.Repeat("e", 12) +
				"/IncomingWebhook/" + strings.Repeat("a", 32) + "/" +
				strings.Repeat("a", 8) + "-" + strings.Repeat("b", 4) + "-" + strings.Repeat("c", 4) + "-" + strings.Repeat("d", 4) + "-" + strings.Repeat("e", 12),
		},
		{"jfrog_reference_token", "cmVmd" + strings.Repeat("a", 59)},
		{"infracost_api_token", "ico-" + strings.Repeat("a", 32)},
		{"prefect_api_token", "pnu_" + strings.Repeat("a", 36)},
		{"readme_api_token", "rdme_" + strings.Repeat("a", 70)},
		{"maxmind_license_key", strings.Repeat("a", 6) + "_" + strings.Repeat("b", 29) + "_mmk"},
		{"clickhouse_cloud_secret_key", "4b1d" + strings.Repeat("a", 38)},
		{"yandex_cloud_api_key", "AQVN" + strings.Repeat("a", 36)},
		{"facebook_page_access_token_marketing", "EAAM" + strings.Repeat("a", 200)},
		{"facebook_page_access_token_live", "EAAC" + strings.Repeat("a", 200)},
		{"sourcegraph_legacy", "sgp_" + strings.Repeat("a", 40)},
		{"sourcegraph_modern", "sgp_" + strings.Repeat("a", 16) + "_" + strings.Repeat("b", 40)},
		{"sourcegraph_local", "sgp_local_" + strings.Repeat("b", 40)},
		{"defined_networking_token", "dnkey-" + strings.Repeat("a", 26) + "-" + strings.Repeat("b", 52)},
		{"scalingo_api_token_us", "tk-us-" + strings.Repeat("a", 48)},
		{"scalingo_api_token_eu", "tk-eu-" + strings.Repeat("a", 48)},
		// Stripe `prod` env tag (added in 2024) for pk_, sk_ and rk_.
		{"stripe_publishable_prod", "pk_prod_" + strings.Repeat("a", 24)},
		{"stripe_secret_prod", "sk_prod_" + strings.Repeat("a", 24)},
		{"stripe_restricted_prod", "rk_prod_" + strings.Repeat("a", 24)},
		// Anthropic admin keys.
		{"anthropic_admin_key", "sk-ant-" + "admin01-" + strings.Repeat("X", 93) + "AA"},
		// 1Password user-side Secret Key (both documented body shapes).
		{"onepassword_secret_key_long", "A3-ABCDEF-GHIJKLMNOPQ-12345-67890-ZYXWV"},
		{"onepassword_secret_key_split", "A3-ABCDEF-GHIJKL-MNOPQ-12345-67890-ZYXWV"},
		// Sixth batch — vendor-anchored contextual rules. Tokens
		// here have no unique prefix; detection requires the vendor
		// word to appear within ~50 chars of an assignment operator.
		{"datadog_contextual", "DATADOG_API_KEY = " + strings.Repeat("a", 40)},
		{"snyk_contextual", `SNYK_TOKEN = "` + "12345678-1234-1234-1234-123456789012" + `"`},
		{"launchdarkly_contextual", `launchdarkly_sdk_key: "` + strings.Repeat("a", 40) + `"`},
		{"cloudflare_api_key_contextual", `cloudflare_api_key=` + strings.Repeat("a", 40)},
		{"cloudflare_global_api_key_contextual", `CLOUDFLARE_GLOBAL_KEY=` + strings.Repeat("f", 37)},
		{"confluent_access_token_contextual", `CONFLUENT_API_KEY=` + strings.Repeat("a", 16)},
		{"confluent_secret_key_contextual", `CONFLUENT_SECRET=` + strings.Repeat("a", 64)},
		{"looker_client_id_contextual", `looker_client_id=` + strings.Repeat("a", 20)},
		{"looker_client_secret_contextual", `looker_client_secret=` + strings.Repeat("a", 24)},
		{"mattermost_contextual", `mattermost_token=` + strings.Repeat("a", 26)},
		{"sumologic_contextual", `SUMO_ACCESS_KEY=` + strings.Repeat("a", 64)},
		{"travisci_contextual", `TRAVIS_TOKEN=` + strings.Repeat("a", 22)},
		{"zendesk_contextual", `zendesk_secret=` + strings.Repeat("a", 40)},
		{"codecov_contextual", `CODECOV_TOKEN=` + strings.Repeat("a", 32)},
		{"algolia_contextual", `algolia_admin_key=` + strings.Repeat("a", 32)},
		{"airtable_contextual", `airtable_api_key=` + strings.Repeat("a", 17)},
		{"sendbird_contextual", `sendbird_token=` + strings.Repeat("a", 40)},
		// Seventh batch — patterns from gitleaks / trufflehog / detect-secrets.
		{"figma_pat", "figd_" + strings.Repeat("a", 40)},
		{"contentful_pat", "CFPAT-" + strings.Repeat("a", 43)},
		{"doppler_service_token", "dp.st." + strings.Repeat("a", 43)},
		{"doppler_cli_token", "dp.ct." + strings.Repeat("a", 43)},
		{"doppler_scim_token", "dp.scim." + strings.Repeat("a", 43)},
		{"doppler_audit_token", "dp.audit." + strings.Repeat("a", 43)},
		{"doppler_service_account_token", "dp.sa." + strings.Repeat("a", 43)},
		{"hubspot_private_app_token_na1", "pat-na1-" + "12345678-1234-1234-1234-123456789012"},
		{"hubspot_private_app_token_eu1", "pat-eu1-" + "abcdef01-2345-6789-abcd-ef0123456789"},
		{"launchdarkly_sdk_key", "sdk-" + "12345678-1234-1234-1234-123456789012"},
		{"braintree_access_token_production", "access_token$production$" + strings.Repeat("a", 16) + "$" + strings.Repeat("f", 32)},
		{"braintree_access_token_sandbox", "access_token$sandbox$" + strings.Repeat("b", 8) + "$" + strings.Repeat("e", 28)},
		{"azure_devops_pat", "oy2" + strings.Repeat("A", 46)},
		{"mysql_conn_string", "mysql://myuser:" + strings.Repeat("s", 24) + "@db.example.com"},
		{"redis_conn_string", "redis://default:" + strings.Repeat("p", 24) + "@redis.example.com:6379"},
		{"redis_conn_string_no_user", "redis://:" + strings.Repeat("p", 24) + "@redis.example.com:6379"},
		{"rediss_conn_string", "rediss://user:" + strings.Repeat("p", 24) + "@redis.example.com:6380"},
		{"amqp_conn_string", "amqp://guest:" + strings.Repeat("p", 24) + "@rabbit.example.com"},
		{"amqps_conn_string", "amqps://user:" + strings.Repeat("p", 24) + "@rabbit.example.com:5671"},
		// Eighth batch — gitleaks parity additions cross-checked
		// against the gitleaks default ruleset.
		{"aws_access_key_abia", "ABIA" + strings.Repeat("A", 16)},
		{"aws_access_key_acca", "ACCA" + strings.Repeat("A", 16)},
		{"harness_pat", "pat." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 24) + "." + strings.Repeat("c", 20)},
		{"harness_sat", "sat." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 24) + "." + strings.Repeat("c", 20)},
		{"huggingface_org_token", "api_org_" + strings.Repeat("a", 34)},
		{"settlemint_personal_token", "sm_pat_" + strings.Repeat("a", 16)},
		{"settlemint_application_token", "sm_aat_" + strings.Repeat("a", 16)},
		{"settlemint_service_token", "sm_sat_" + strings.Repeat("a", 16)},
		{"gitlab_incoming_mail_token", "glimt-" + strings.Repeat("a", 25)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Truef(t, portcullis.Contains(tc.text), "must detect %s", tc.name)
			out := portcullis.Redact(tc.text)
			assert.NotContainsf(t, out, tc.text, "raw secret must be gone after Redact: %q", out)
			assert.Containsf(t, out, portcullis.Marker,
				"redaction marker must appear in %q", out)
		})
	}
}

// TestRedactDetectsBareUnquotedSecrets exercises the rules whose
// expressions used to require surrounding `'` / `"` characters
// (copied from upstream Trivy, where the scanner is aimed at JSON /
// YAML config files). The agent's leak vectors are different: tool
// output, CLI shells, and chat content where credentials routinely
// appear unquoted (`echo $NPM_TOKEN`, `vault token lookup`, log
// dumps). Each rule below has a unique-enough prefix to stay
// specific without the quote anchor — this test pins that property
// so a future refactor doesn't accidentally re-introduce the
// quote-only matching.
func TestRedactDetectsBareUnquotedSecrets(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		token string
	}{
		{"npm_access_token_bare", "npm_" + strings.Repeat("a", 36)},
		{"dynatrace_api_token_bare", "dt0c01." + strings.Repeat("a", 24) + "." + strings.Repeat("b", 64)},
		{"doppler_personal_token_bare", "dp.pt." + strings.Repeat("a", 43)},
		{"easypost_production_token_bare", "EZAK" + strings.Repeat("a", 54)},
		{"easypost_test_token_bare", "EZTK" + strings.Repeat("a", 54)},
		{"hashicorp_terraform_token_bare", strings.Repeat("a", 14) + ".atlasv1." + strings.Repeat("b", 64)},
		{"new_relic_user_api_key_bare", "NRAK-" + strings.Repeat("A", 27)},
		{"new_relic_browser_api_token_bare", "NRJS-" + strings.Repeat("a", 19)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// The same value emitted bare (CLI / log) and quoted
			// (config file) must both be redacted.
			for _, in := range []string{tc.token, `"` + tc.token + `"`, `'` + tc.token + `'`} {
				assert.Truef(t, portcullis.Contains(in),
					"must detect %s in %q", tc.name, in)
				out := portcullis.Redact(in)
				assert.NotContainsf(t, out, tc.token,
					"raw secret must be gone after Redact: %q", out)
				assert.Containsf(t, out, portcullis.Marker,
					"redaction marker must appear in %q", out)
			}
		})
	}
}

// TestRedactDoesNotSwallowAdjacentTextAfterSlackRotatingToken pins
// the upper bound on the slack-rotating-token rule. The body class
// overlaps with hostnames / dotted identifiers, so without an upper
// quantifier bound a Slack token followed (without separator) by an
// `api.slack.com`-style URL would silently consume the URL into the
// redaction span. The upper bound of 300 is comfortably above the
// longest observed Slack rotating-token body, so a real secret is
// still fully redacted, but text well past that length stops being
// part of the same match.
func TestRedactDoesNotSwallowAdjacentTextAfterSlackRotatingToken(t *testing.T) {
	t.Parallel()

	// 320 chars is past the {40,300} cap, so the regex must split
	// the input into a redacted prefix and a literal trailing
	// suffix. The trailing dotted hostname is exactly the kind of
	// content that an open-ended quantifier would over-consume.
	token := "xoxe-" + strings.Repeat("a", 320)
	input := token + ".api.slack.com"

	out := portcullis.Redact(input)

	assert.Containsf(t, out, portcullis.Marker,
		"a Slack rotating token must still be redacted: %q", out)
	assert.Containsf(t, out, "api.slack.com",
		"adjacent hostname must NOT be swallowed by the rotating-token regex: %q", out)
}

// TestRedactDoesNotSwallowAdjacentTextAfterPrefixedTokens pins the
// upper bounds of the rules whose bodies share a character class
// with arbitrary trailing text. Without an explicit ceiling on the
// body quantifier, a token directly abutting alphanumeric content
// would have all of the trailing text silently consumed into the
// redaction span. Each subtest below uses a suffix long enough to
// overflow the rule's body cap and asserts that the overflow is
// preserved — i.e. an upper bound exists and is enforced. (Short
// alphanumeric identifiers concatenated to a token without any
// separator may still be consumed up to the cap; the realistic leak
// vector is rare in practice and the alternative — leaving secrets
// partially redacted — is worse.)
func TestRedactDoesNotSwallowAdjacentTextAfterPrefixedTokens(t *testing.T) {
	t.Parallel()

	// Each token below is intentionally longer than the rule's
	// upper bound so the regex must split the input into a redacted
	// prefix and a literal trailing suffix. The marker `STOPHERE` is
	// alphanumeric (so it would be consumed by an unbounded quantifier)
	// but is positioned past the body cap to confirm the cap is real.
	cases := []struct {
		name  string
		token string
	}{
		// Body cap 80 — use 90 chars to overflow.
		{"vercel_personal", "vcp_" + strings.Repeat("a", 90)},
		{"vercel_cli", "vck_" + strings.Repeat("b", 90)},
		{"vercel_integration", "vci_" + strings.Repeat("c", 90)},
		// Supabase body cap 80 — use 90 chars.
		{"supabase_secret", "sb_secret_" + strings.Repeat("d", 90)},
		// Render body cap 80 — use 90 chars.
		{"render_api_key", "rnd_" + strings.Repeat("e", 90)},
		// 1Password body cap 1000 — use 1100 chars.
		{"onepassword_service_account", "ops_eyJ" + strings.Repeat("f", 1100)},
		// Pinecone second segment cap 80 — use 90 chars.
		{"pinecone_api_key", "pckey_label_" + strings.Repeat("g", 90)},
		// Tailscale second segment cap 80 — use 90 chars.
		{"tailscale_auth_key", "tskey-auth-" + strings.Repeat("h", 12) + "-" + strings.Repeat("i", 90)},
		{"tailscale_api_token", "tskey-api-" + strings.Repeat("j", 12) + "-" + strings.Repeat("k", 90)},
	}
	const suffix = " and the rest of the line"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := tc.token + suffix
			out := portcullis.Redact(input)

			assert.Containsf(t, out, portcullis.Marker,
				"%s must still be redacted: %q", tc.name, out)
			assert.Containsf(t, out, suffix,
				"adjacent text past the body cap must NOT be swallowed by %s: %q",
				tc.name, out)
		})
	}
}

// TestContainsIgnoresHarmlessText: pure digit strings, plain English,
// and the empty string must never trip detection.
func TestContainsIgnoresHarmlessText(t *testing.T) {
	t.Parallel()

	cases := []string{
		"",
		"1234567890",
		"hello world",
		"please summarise the README",
		// "key" is a keyword for aws-secret-access-key, but the regex
		// requires a 40-char base64-ish span next to "aws_*key=" so a
		// bare mention must not trip detection.
		"the api key is documented in README",
	}
	for _, in := range cases {
		assert.Falsef(t, portcullis.Contains(in), "must not flag %q", in)
	}
}

// TestRedactReplacesSecretSpan: the secret material is replaced by
// [portcullis.Marker] while the surrounding text (including the
// keyword that triggered the match) is preserved. We don't assert
// the exact match boundary because the rule's leading-context group
// may consume the preceding space — only the secret value must
// disappear.
func TestRedactReplacesSecretSpan(t *testing.T) {
	t.Parallel()

	const ghp = "ghp_cxLeRrvbJfmYdUtr70xnNE3Q7Gvli43s19PD"
	in := "Run this with token=" + ghp + " and you're set"

	out := portcullis.Redact(in)

	assert.Containsf(t, out, portcullis.Marker, "redaction marker must appear: %q", out)
	assert.NotContainsf(t, out, ghp, "raw secret must be gone: %q", out)
	assert.Contains(t, out, "Run this with token=", "non-secret prefix preserved")
	assert.Contains(t, out, "and you're set", "non-secret suffix preserved")
}

// TestRedactIsIdempotent: passing already-redacted text through
// Redact again leaves it untouched.
func TestRedactIsIdempotent(t *testing.T) {
	t.Parallel()

	once := portcullis.Redact("dckr_pat_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAA in logs")
	twice := portcullis.Redact(once)

	assert.Equal(t, once, twice)
	assert.False(t, portcullis.Contains(once),
		"redacted output must no longer trip Contains")
}

// TestRedactPreservesNonMatchingText: text without secrets must pass
// through untouched (catches a regression where a too-broad rule
// inserts a marker into innocent content).
func TestRedactPreservesNonMatchingText(t *testing.T) {
	t.Parallel()

	cases := []string{
		"",
		"1234567890",
		"please refactor the helper into its own file",
	}
	for _, in := range cases {
		assert.Equalf(t, in, portcullis.Redact(in), "must not modify %q", in)
	}
}

// TestRedactHandlesMultipleSecretsInOneInput: two distinct secrets in
// the same string must both be replaced, and nothing in between
// should leak out (regression test for the cursor-rebuild loop).
func TestRedactHandlesMultipleSecretsInOneInput(t *testing.T) {
	t.Parallel()

	const a = "ghp_cxLeRrvbJfmYdUtr70xnNE3Q7Gvli43s19PD"
	const b = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	in := "first " + a + " and second " + b + " end"

	out := portcullis.Redact(in)

	require.NotContains(t, out, a)
	require.NotContains(t, out, b)
	assert.Equal(t, 2, strings.Count(out, portcullis.Marker),
		"both secrets must be redacted: %q", out)
	assert.Contains(t, out, "first ")
	assert.Contains(t, out, " and second ")
	assert.Contains(t, out, " end")
}

// TestMarkerIsNotASecret locks in the safety property that makes
// [portcullis.Redact] idempotent and the keyword pre-filter hoist in
// [portcullis.Redact] sound: the literal Marker must not match any
// detection rule. If a future rule were added whose keyword overlapped
// "[REDACTED]", redaction would either recurse forever or amplify the
// marker on every pass, and any downstream pipeline that calls Redact
// twice would silently corrupt content.
func TestMarkerIsNotASecret(t *testing.T) {
	t.Parallel()

	assert.False(t, portcullis.Contains(portcullis.Marker),
		"the redaction marker must not match any rule")
	assert.Equal(t, portcullis.Marker,
		portcullis.Redact(portcullis.Marker),
		"redacting the marker must be a no-op")

	// Embedded in arbitrary surrounding text the marker still must not
	// match — some rules only fire mid-string after a non-word boundary.
	assert.Equal(t, "prefix "+portcullis.Marker+" suffix",
		portcullis.Redact("prefix "+portcullis.Marker+" suffix"))
}

// TestRedactDetectsSecretsAcrossWordBoundaries exercises the change
// that dropped the leading and trailing word-boundary anchors from
// the rule expressions. Before the change, only secrets that stood
// next to whitespace, punctuation, or the start/end of the input were
// detected; values pasted directly into a larger token ("FOO=ghp_…"
// without the trailing space, "BEFOREghp_…AFTER") leaked through.
// Each subtest pins one of those previously-leaking shapes — the
// exact same secret value embedded in different contexts must always
// be redacted out.
func TestRedactDetectsSecretsAcrossWordBoundaries(t *testing.T) {
	t.Parallel()

	// Split the literal secret values across string concatenation so
	// the verbatim token never appears on a single source line; that
	// keeps secret-scanners (including ours) happy on the test file
	// itself while still exercising the real ruleset.
	ghp := "ghp_" + "cxLeRrvbJfmYdUtr70xnNE3Q7Gvli43s19PD"
	awsAccessKey := "AKIA" + "IOSFODNN7EXAMPLE"
	dockerPAT := "dckr_pat_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAA"

	cases := []struct {
		name   string
		secret string
		input  string
	}{
		{"github-pat alone", ghp, ghp},
		{"github-pat with leading alphanumerics", ghp, "BEFORE" + ghp},
		{"github-pat with trailing alphanumerics", ghp, ghp + "AFTER"},
		{"github-pat embedded in a larger token", ghp, "BEFORE" + ghp + "AFTER"},
		{"github-pat after KEY=", ghp, "KEY=" + ghp},
		{"github-pat after KEY= and inline word", ghp, "KEY=" + ghp + "AFTER"},
		{"aws-access-key alone", awsAccessKey, awsAccessKey},
		{"aws-access-key with leading alphanumerics", awsAccessKey, "BEFORE" + awsAccessKey},
		{"aws-access-key with trailing alphanumerics", awsAccessKey, awsAccessKey + "AFTER"},
		{"aws-access-key embedded in a larger token", awsAccessKey, "BEFORE" + awsAccessKey + "AFTER"},
		{"docker-pat with leading alphanumerics", dockerPAT, "BEFORE" + dockerPAT},
		{"docker-pat embedded in a larger token", dockerPAT, "BEFORE" + dockerPAT + "AFTER"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Truef(t, portcullis.Contains(tc.input),
				"must detect secret in %q", tc.input)
			out := portcullis.Redact(tc.input)
			assert.NotContainsf(t, out, tc.secret,
				"raw secret must be gone after Redact: %q", out)
			assert.Containsf(t, out, portcullis.Marker,
				"redaction marker must appear in %q", out)
		})
	}
}

// TestRedactScalesLinearly is a guard-rail against accidentally
// reintroducing a quadratic algorithm when iterating on Redact
// (e.g. retrying every rule from each character offset). With the
// keyword pre-filter and Go's RE2-based regexp engine the cost is
// O(len(text) · len(rules)), so doubling the input must roughly
// double the wall time — not quadruple it. We deliberately check a
// generous ceiling (8×) to stay reliable under noisy CI; a true
// quadratic regression on a 16× size delta would blow well past it.
func TestRedactScalesLinearly(t *testing.T) {
	t.Parallel()

	// Warm caches (rule compilation, regex DFA) so the first sample
	// doesn't pay a one-time tax that skews the ratio.
	_ = portcullis.Redact("warmup")

	measure := func(text string) time.Duration {
		const iters = 50
		start := time.Now()
		for range iters {
			_ = portcullis.Redact(text)
		}
		return time.Since(start) / iters
	}

	// Realistic cleanish payload: prose with a couple of secret-like
	// keywords sprinkled in so the keyword pre-filter sometimes lets
	// rules through to their regex.
	unit := "the quick brown fox key=" + "abcdefghijklmnop" +
		" jumps over the lazy dog with token=" + "ghp_xxx" + ". "
	small := strings.Repeat(unit, 64)
	large := strings.Repeat(unit, 1024) // 16× small

	dSmall := measure(small)
	dLarge := measure(large)

	// Allow up to 128× — quadratic would be ~256× on a 16× delta and
	// the headroom keeps the test stable when the host is loaded.
	const growthCeiling = 128
	if dSmall == 0 {
		t.Skip("clock too coarse to measure small input")
	}
	ratio := float64(dLarge) / float64(dSmall)
	assert.Lessf(t, ratio, float64(growthCeiling),
		"Redact must not be quadratic: 16× input took %.1f× the time (small=%v, large=%v)",
		ratio, dSmall, dLarge)
}
