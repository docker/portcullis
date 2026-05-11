package portcullis_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/docker/portcullis"
)

// TestNoisyKeywordsFalsePositives verifies that common text patterns
// containing the noisy keywords don't trigger false positives.
func TestNoisyKeywordsFalsePositives(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		text string
	}{
		// :AA keyword - should NOT match times or other contexts
		{"time_with_AA", "Meeting at 12:00 AA tomorrow"},
		{"AA_abbreviation", "The AA battery is dead"},
		{"AA_in_text", "AA is a common abbreviation"},

		// sk. keyword - should NOT match common English words
		{"ask_sentence", "I ask. Can you help?"},
		{"disk_sentence", "The disk. is full"},
		{"risk_sentence", "The risk. is high"},

		// 1/ keyword - should NOT match simple fractions or paths
		{"simple_fraction", "1/2 cup of sugar"},
		{"short_path", "1/home/user"},
		{"date_like", "1/1/2024"},

		// v1.0- keyword - should NOT match version strings without the full pattern
		{"version_string", "v1.0-beta"},
		{"version_release", "v1.0-rc1"},

		// Vendor names mentioned in prose without an assignment must
		// not trigger the contextual rules added in the sixth batch.
		// Each rule's regex requires `<vendor>...=...<value>` shape;
		// a bare mention should slip through the keyword filter and
		// the regex without matching.
		{"datadog_in_prose", "We monitor the cluster with Datadog dashboards."},
		{"snyk_in_prose", "Snyk found three high-severity issues this week."},
		{"cloudflare_in_prose", "Cloudflare DDOS protection is enabled."},
		{"travis_in_prose", "Travis CI is now archived; we moved to GitHub Actions."},
		{"sumo_in_prose", "sumo wrestling is a Japanese sport."},
		{"airtable_in_prose", "Airtable bases are like spreadsheets."},

		// New seventh-batch keywords that could be noisy.
		{"sdk_in_prose", "Install the android-sdk-tools package."},
		{"mysql_without_password", "mysql://localhost:3306/mydb"},
		{"redis_without_password", "redis://localhost:6379"},
		{"amqp_without_password", "amqp://localhost:5672"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := portcullis.Contains(tc.text)
			assert.Falsef(t, result, "should not detect secret in: %q", tc.text)
		})
	}
}

// TestDiscordTokenPrefixes verifies all documented Discord bot token prefixes.
func TestDiscordTokenPrefixes(t *testing.T) {
	t.Parallel()

	// Test all documented prefixes
	prefixes := []string{"MT", "Mz", "ND", "NT", "Nz", "OD"}

	for _, prefix := range prefixes {
		t.Run("prefix_"+prefix, func(t *testing.T) {
			t.Parallel()
			token := prefix + strings.Repeat("A", 22) + "." + strings.Repeat("B", 6) + "." + strings.Repeat("C", 30)
			assert.Truef(t, portcullis.Contains(token),
				"should detect Discord token with prefix %s", prefix)
		})
	}
}

// TestConnectionStringContextPreservation verifies that MongoDB, Postgres,
// and Azure Storage connection strings only redact the password/key portion.
func TestConnectionStringContextPreservation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		input       string
		mustHave    []string
		mustNotHave string
	}{
		{
			name:        "mongodb_preserves_user_and_host",
			input:       "mongodb://myuser:secretpassword123@cluster.mongodb.net/mydb",
			mustHave:    []string{"mongodb://", "myuser", "@cluster.mongodb.net"},
			mustNotHave: "secretpassword123",
		},
		{
			name:        "postgres_preserves_user_and_host",
			input:       "postgresql://dbuser:secretpass456@db.example.com:5432/mydb",
			mustHave:    []string{"postgresql://", "dbuser", "@db.example.com"},
			mustNotHave: "secretpass456",
		},
		{
			name:        "azure_storage_preserves_account_name",
			input:       "DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=" + strings.Repeat("a", 86) + "==",
			mustHave:    []string{"DefaultEndpointsProtocol=https", "AccountName=mystorage", "AccountKey="},
			mustNotHave: strings.Repeat("a", 86) + "==",
		},
		{
			name:        "mysql_preserves_user_and_host",
			input:       "mysql://appuser:secretpass789@db.example.com:3306/mydb",
			mustHave:    []string{"mysql://", "appuser", "@db.example.com"},
			mustNotHave: "secretpass789",
		},
		{
			name:        "redis_preserves_user_and_host",
			input:       "redis://default:redispass123@cache.example.com:6379/0",
			mustHave:    []string{"redis://", "default", "@cache.example.com"},
			mustNotHave: "redispass123",
		},
		{
			name:        "redis_no_user_preserves_host",
			input:       "redis://:redispass456@cache.example.com:6379",
			mustHave:    []string{"redis://", "@cache.example.com"},
			mustNotHave: "redispass456",
		},
		{
			name:        "amqp_preserves_user_and_host",
			input:       "amqp://guest:rabbitpass789@rabbit.example.com:5672/vhost",
			mustHave:    []string{"amqp://", "guest", "@rabbit.example.com"},
			mustNotHave: "rabbitpass789",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.True(t, portcullis.Contains(tc.input), "should detect secret")

			redacted := portcullis.Redact(tc.input)

			for _, must := range tc.mustHave {
				assert.Containsf(t, redacted, must,
					"redacted output should preserve: %s", must)
			}

			assert.NotContainsf(t, redacted, tc.mustNotHave,
				"redacted output must not contain secret: %s", tc.mustNotHave)
		})
	}
}
