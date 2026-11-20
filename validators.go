package portcullis

import (
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
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
	if len(token) != 132 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(token[4:])
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(decoded), "BedrockAPIKey-")
}

// The keywordless PII rules (credit card, IBAN, SSN) can't hide
// behind the Aho–Corasick keyword pre-filter, so without a cheap gate
// their expensive regexes would run over every clean input. Each
// shape below is a necessary condition for its rule's regex to
// match — it may show up in inputs the regex ultimately rejects, but
// it is never missing from an input the regex would accept — so clean
// prose (which has no long digit runs) skips the regex entirely.
type shapes uint8

const (
	// shapeCard gates the card rule: its regex consumes at least 13
	// digits (a 4-digit issuer group plus 9+ more) in a run where
	// consecutive digits are split by at most one byte of its [-\s]
	// separator class.
	shapeCard shapes = 1 << iota
	// shapeSSN gates the SSN rule: its regex is 9 digits split by at
	// most single '-'/' ' separators.
	shapeSSN
	// shapeIBAN gates the IBAN rule on its mandatory country-code +
	// check-digit anchor: two ASCII letters immediately followed by
	// two ASCII digits.
	shapeIBAN

	allShapes = shapeCard | shapeSSN | shapeIBAN
)

// scanShapes reports every shape text contains, in a single pass.
// They all need a digit, so prose is skipped byte by byte without
// keeping any state and only the digit runs get a closer look.
func scanShapes(text string) (found shapes) {
	for i := 0; i < len(text); {
		for i < len(text) && !isASCIIDigit(text[i]) {
			i++
		}
		// text[i], if any, opens a digit run: the one place where
		// letters can sit right before digits.
		if i >= 2 && i+1 < len(text) && isASCIIDigit(text[i+1]) &&
			isASCIILetter(text[i-1]) && isASCIILetter(text[i-2]) {
			found |= shapeIBAN
		}
		// Count the digits that at most one separator byte splits
		// from the previous one. '-' and ' ' separate for both rules;
		// the rest of ASCII whitespace only does for cards, so it
		// starts the SSN count over.
		card, ssn := 0, 0
		for i < len(text) && isASCIIDigit(text[i]) {
			card++
			ssn++
			if card >= 13 {
				found |= shapeCard
			}
			if ssn >= 9 {
				found |= shapeSSN
			}
			i++
			if i < len(text) {
				switch text[i] {
				case '-', ' ':
					i++
				case '\t', '\n', '\r', '\v', '\f':
					ssn = 0
					i++
				}
			}
		}
		if found == allShapes {
			break
		}
	}
	return found
}

// lazyShapes runs [scanShapes] over an input at most once, and only
// if a keywordless rule is reached at all: [Contains] often returns
// on a keyworded rule before that.
type lazyShapes struct {
	scanned bool
	found   shapes
}

func (l *lazyShapes) has(text string, shape shapes) bool {
	if !l.scanned {
		l.found, l.scanned = scanShapes(text), true
	}
	return l.found&shape != 0
}

func isASCIIDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isASCIILetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func validLuhn(value string) bool {
	digits, total := 0, 0
	for i := len(value) - 1; i >= 0; i-- {
		c := value[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if digits%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		total += d
		digits++
		if digits > 19 {
			return false
		}
	}
	return digits >= 13 && total%10 == 0
}

// ibanLengths maps an ISO 3166 country code to the total IBAN length the
// ISO 13616 registry defines for it. The mod-97 checksum alone passes one
// random string in 97, so a 4-character-grouped hex ID (a UUID tail, say)
// would otherwise read as an IBAN about once per hundred tries.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
	"BG": 22, "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22,
	"CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20,
	"EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22,
	"GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
	"IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30,
	"KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
	"LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27,
	"MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
	"PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33,
	"SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
	"SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29,
	"VA": 22, "VG": 24, "XK": 20, "YE": 30,
}

// validIBAN accepts a value whose country code is a registered IBAN country,
// whose length is the one that country defines, and whose mod-97 checksum
// is 1.
func validIBAN(value string) bool {
	s := strings.ToUpper(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value))
	if want, ok := ibanLengths[s[:min(len(s), 2)]]; !ok || len(s) != want {
		return false
	}

	mod := 0
	for _, r := range s[4:] + s[:4] {
		switch {
		case r >= '0' && r <= '9':
			mod = (mod*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			mod = (mod*100 + int(r-'A'+10)) % 97
		default:
			return false
		}
	}
	return mod == 1
}

func validUSSSN(value string) bool {
	digits := make([]byte, 0, 9)
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits = append(digits, byte(r))
		}
	}
	if len(digits) != 9 {
		return false
	}
	area, _ := strconv.Atoi(string(digits[:3]))
	group, _ := strconv.Atoi(string(digits[3:5]))
	serial, _ := strconv.Atoi(string(digits[5:]))
	return area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
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
