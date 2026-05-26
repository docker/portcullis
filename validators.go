package portcullis

import (
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	githubChecksumLen = 6
	base62Alphabet    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	awsKeyIDAlphabet  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	bech32Alphabet    = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
)

// validGitHubChecksum verifies a GitHub token's trailing 6-char base62
// CRC32. GitHub computes the checksum over the random body that follows
// the prefix (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, or `github_pat_`),
// not over the prefix itself.
func validGitHubChecksum(token string) bool {
	body, ok := stripGitHubPrefix(token)
	if !ok || len(body) <= githubChecksumLen {
		return false
	}
	provided := body[len(body)-githubChecksumLen:]
	return provided == base62CRC32(body[:len(body)-githubChecksumLen])
}

var gitHubTokenPrefixes = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}

func stripGitHubPrefix(token string) (string, bool) {
	for _, p := range gitHubTokenPrefixes {
		if rest, ok := strings.CutPrefix(token, p); ok {
			return rest, true
		}
	}
	return "", false
}

// validGitHubStatelessToken accepts the post-2026 stateless GitHub
// App installation-token format: a `ghs_` prefix followed by a JWT.
// The legacy stateful format (random body + base62 CRC32 trailer) is
// still validated by [validGitHubChecksum] via the github-app-token
// rule; this one covers the new shape that GitHub is rolling out per
// their 2026 changelog (`X-GitHub-Stateless-S2S-Token`).
func validGitHubStatelessToken(token string) bool {
	rest, ok := strings.CutPrefix(token, "ghs_")
	return ok && validJWT(rest)
}

func validJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if !decodeJSON(parts[0], &header) || header.Alg == "" || strings.EqualFold(header.Alg, "none") {
		return false
	}

	var payload map[string]any
	if !decodeJSON(parts[1], &payload) || len(payload) == 0 {
		return false
	}
	return true
}

func decodeJSON(segment string, v any) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return false
	}
	return json.Unmarshal(decoded, v) == nil
}

func validAgeSecretKey(token string) bool {
	if strings.ToUpper(token) != token || !strings.HasPrefix(token, "AGE-SECRET-KEY-1") {
		return false
	}
	data, ok := bech32Decode(strings.ToLower(token), "age-secret-key-")
	if !ok {
		return false
	}
	decoded, ok := convertBits(data, 5, 8, false)
	return ok && len(decoded) == 32
}

func bech32Decode(s, expectedHRP string) ([]byte, bool) {
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) || s[:pos] != expectedHRP {
		return nil, false
	}
	data := make([]byte, len(s)-pos-1)
	for i, c := range s[pos+1:] {
		idx := strings.IndexRune(bech32Alphabet, c)
		if idx < 0 {
			return nil, false
		}
		data[i] = byte(idx)
	}
	if !validBech32Checksum(s[:pos], data) {
		return nil, false
	}
	return data[:len(data)-6], true
}

func validBech32Checksum(hrp string, data []byte) bool {
	return bech32Polymod(append(bech32HRPExpand(hrp), data...)) == 1
}

func bech32HRPExpand(hrp string) []byte {
	expanded := make([]byte, 0, len(hrp)*2+1)
	for _, c := range hrp {
		expanded = append(expanded, byte(c>>5))
	}
	expanded = append(expanded, 0)
	for _, c := range hrp {
		expanded = append(expanded, byte(c&31))
	}
	return expanded
}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i, generator := range []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3} {
			if (top>>i)&1 != 0 {
				chk ^= generator
			}
		}
	}
	return chk
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, bool) {
	var acc, bits uint
	maxv := uint((1 << to) - 1)
	maxAcc := uint((1 << (from + to - 1)) - 1)
	var ret []byte
	for _, value := range data {
		v := uint(value)
		if v>>from != 0 {
			return nil, false
		}
		acc = ((acc << from) | v) & maxAcc
		bits += from
		for bits >= to {
			bits -= to
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(to-bits))&maxv))
		}
	} else if bits >= from || ((acc<<(to-bits))&maxv) != 0 {
		return nil, false
	}
	return ret, true
}

func validDiscordWebhookURL(token string) bool {
	u, err := url.Parse(token)
	if err != nil {
		return false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "webhooks" || parts[3] == "" {
		return false
	}
	id, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return false
	}
	timestamp := time.UnixMilli(int64((id >> 22) + 1_420_070_400_000))
	now := time.Now()
	return !timestamp.Before(time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)) && !timestamp.After(now.Add(24*time.Hour))
}

func validAzureStorageAccountKey(token string) bool {
	decoded, err := base64.StdEncoding.DecodeString(token)
	return err == nil && len(decoded) == 64
}

func validDockerConfigSecret(token string) bool {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(decoded, &cfg); err != nil || len(cfg.Auths) == 0 {
		return false
	}
	for registry, auth := range cfg.Auths {
		if registry == "" || auth.Auth == "" {
			return false
		}
		if _, err := base64.StdEncoding.DecodeString(auth.Auth); err != nil {
			return false
		}
	}
	return true
}

func validCloudflareAPIKey(token string) bool {
	return !strings.ContainsAny(token, "-_")
}

func validAWSBedrockLongLivedKey(token string) bool {
	if len(token) != 132 || len(token)%4 != 0 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(token[4:])
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(decoded), "BedrockAPIKey-")
}

func validAWSAccessKeyID(token string) bool {
	if len(token) != 20 {
		return false
	}
	encoded := base32Index(token[4:12]) - base32Index("QAAAAAAA")
	if encoded < 0 {
		return false
	}
	accountID := encoded * 2
	if strings.IndexByte(awsKeyIDAlphabet, token[12]) >= strings.IndexByte(awsKeyIDAlphabet, 'Q') {
		accountID++
	}
	return accountID <= 999_999_999_999
}

func base32Index(s string) int64 {
	var n int64
	for _, c := range s {
		idx := strings.IndexRune(awsKeyIDAlphabet, c)
		if idx < 0 {
			return -1
		}
		n = n*32 + int64(idx)
	}
	return n
}

func base62CRC32(s string) string {
	var out [githubChecksumLen]byte
	checksum := uint64(crc32.ChecksumIEEE([]byte(s)))
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = base62Alphabet[checksum%62]
		checksum /= 62
	}
	return string(out[:])
}
