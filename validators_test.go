package portcullis

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// bedrockKey builds a fake AWS Bedrock long-lived key fixture at runtime so
// the literal token never appears in source (GitHub push protection trips on it).
func bedrockKey() string {
	return "AB" + "SK" + base64.StdEncoding.EncodeToString([]byte("BedrockAPIKey-"+strings.Repeat("A", 82)))
}

func TestValidGitHubChecksum(t *testing.T) {
	t.Parallel()

	cases := []string{
		"ghp_" + strings.Repeat("A", 30) + "1yBYBE",
		"gho_" + strings.Repeat("B", 30) + "2EnKYh",
		"ghu_" + strings.Repeat("C", 30) + "12Mf6L",
		"ghs_" + strings.Repeat("D", 30) + "1fOFde",
		"ghr_" + strings.Repeat("E", 30) + "0rAO3S",
		"github_pat_" + strings.Repeat("a", 22) + "_" + strings.Repeat("b", 53) + "2ioKsE",
	}

	for _, token := range cases {
		assert.Truef(t, validGitHubChecksum(token), "%q should have a valid checksum", token)
	}
}

func TestInvalidGitHubChecksum(t *testing.T) {
	t.Parallel()

	assert.False(t, validGitHubChecksum("ghp_"+strings.Repeat("a", 36)))
	assert.False(t, validGitHubChecksum("github_pat_"+strings.Repeat("a", 22)+"_"+strings.Repeat("b", 59)))
}

func TestValidJWT(t *testing.T) {
	t.Parallel()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	assert.True(t, validJWT(token))
}

func TestInvalidJWT(t *testing.T) {
	t.Parallel()

	unsigned := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	assert.False(t, validJWT(unsigned))
	assert.False(t, validJWT("eyJhbGciOiJIUzI1NiJ9.not-json.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"))
	assert.False(t, validJWT("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."))
}

func TestValidAgeSecretKey(t *testing.T) {
	t.Parallel()

	assert.True(t, validAgeSecretKey("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ8H00W3"))
}

func TestInvalidAgeSecretKey(t *testing.T) {
	t.Parallel()

	assert.False(t, validAgeSecretKey("AGE-SECRET-KEY-1"+strings.Repeat("Q", 58)))
	assert.False(t, validAgeSecretKey("age-secret-key-1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8h00w3"))
}

func TestValidDiscordWebhookURL(t *testing.T) {
	t.Parallel()

	assert.True(t, validDiscordWebhookURL("https://discord.com/api/webhooks/1174109840998400000/"+strings.Repeat("a", 60)))
	assert.True(t, validDiscordWebhookURL("https://discordapp.com/api/webhooks/1174109840998400000/"+strings.Repeat("a", 60)))
}

func TestInvalidDiscordWebhookURL(t *testing.T) {
	t.Parallel()

	assert.False(t, validDiscordWebhookURL("https://discord.com/api/webhooks/18446744073709551615/"+strings.Repeat("a", 60)))
	assert.False(t, validDiscordWebhookURL("https://discord.com/api/webhooks/not-a-number/"+strings.Repeat("a", 60)))
}

func TestValidAzureStorageAccountKey(t *testing.T) {
	t.Parallel()

	assert.True(t, validAzureStorageAccountKey(strings.Repeat("YWFh", 21)+"YQ=="))
}

func TestInvalidAzureStorageAccountKey(t *testing.T) {
	t.Parallel()

	assert.False(t, validAzureStorageAccountKey(strings.Repeat("YWFh", 21)+"YWE="))
	assert.False(t, validAzureStorageAccountKey("not-base64"))
}

func TestValidDockerConfigSecret(t *testing.T) {
	t.Parallel()

	assert.True(t, validDockerConfigSecret("eyJhdXRocyI6eyJodHRwczovL2luZGV4LmRvY2tlci5pby92MS8iOnsiYXV0aCI6ImRYTmxjanB3WVhOeiJ9fX0="))
}

func TestInvalidDockerConfigSecret(t *testing.T) {
	t.Parallel()

	assert.False(t, validDockerConfigSecret("eyJub3QiOiJkb2NrZXIgY29uZmlnIn0="))
	assert.False(t, validDockerConfigSecret("ew=="))
}

func TestValidCloudflareAPIKey(t *testing.T) {
	t.Parallel()

	assert.True(t, validCloudflareAPIKey(strings.Repeat("a", 40)))
	assert.True(t, validCloudflareAPIKey(strings.Repeat("A", 40)))
}

func TestInvalidCloudflareAPIKey(t *testing.T) {
	t.Parallel()

	assert.False(t, validCloudflareAPIKey("cloudflare-digital-experience-monitoring"))
	assert.False(t, validCloudflareAPIKey("cloudflare_digital_experience_monitoring"))
}

func TestValidAWSBedrockLongLivedKey(t *testing.T) {
	t.Parallel()

	assert.True(t, validAWSBedrockLongLivedKey(bedrockKey()))
}

func TestInvalidAWSBedrockLongLivedKey(t *testing.T) {
	t.Parallel()

	assert.False(t, validAWSBedrockLongLivedKey("ABSKMCAk4WokBQ6h5EXDyutr1m9t94xbtTJMWt5nOd3Y3Tz073NzSuLWZM+9r88xzL5mXR76ZKv/o4KfM5wkB1qb9Habfw4+Zhs3a2GvuvLe3qdOghel0R7dUev0mt5pNm7eaVu1ut9cOePRJsy4hAHGtbEc+kR2nVAw+odag5/vmlXeW2ONfliLgMgExNu+r+SGBpiiKoig+AncpLRJwtJg990KlOXAh8YaNrG/YY5wVBeGFSk4MUINwYkDlNAfuoqCUIVSwav0OR7Bl"))
	assert.False(t, validAWSBedrockLongLivedKey("ABSK"+strings.Repeat("A", 128)))
}

func TestValidAWSAccessKeyID(t *testing.T) {
	t.Parallel()

	assert.True(t, validAWSAccessKeyID("AKIARZPUZDIKQEXAMPLE"))
	assert.True(t, validAWSAccessKeyID("ASIARZPUZDIKREXAMPLE"))
}

func TestInvalidAWSAccessKeyID(t *testing.T) {
	t.Parallel()

	assert.False(t, validAWSAccessKeyID("AKIAIOSFODNN7EXAMPLE"))
	assert.False(t, validAWSAccessKeyID("AKIAABCDEFGHIJKLMNOP"))
	assert.False(t, validAWSAccessKeyID("AKIA7ZPUZDIKREXAMPLE"))
}

func TestBase32Index(t *testing.T) {
	t.Parallel()

	assert.Equal(t, int64(0), base32Index("AAAAAAAA"))
	assert.Equal(t, int64(1), base32Index("AAAAAAAB"))
	assert.Equal(t, int64(-1), base32Index("AAAAAAA0"))
}

func TestBase62CRC32(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "000000", base62CRC32(""))
	assert.Equal(t, "1yBYBE", base62CRC32("ghp_"+strings.Repeat("A", 30)))
}
