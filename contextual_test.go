package portcullis

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContextualSecretSpans(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		vendor string
		secret string
	}{
		{"cloudflare", strings.Repeat("q", 40)},
		{"cloudflare", strings.Repeat("f", 37)},
		{"datadog", strings.Repeat("a", 40)},
		{"deepseek", "sk-" + strings.Repeat("a", 32)},
	} {
		for _, prefixLen := range []int{0, 1, 49, 50, 51, 100} {
			t.Run(fmt.Sprintf("%s/%d/%d", tc.vendor, len(tc.secret), prefixLen), func(t *testing.T) {
				t.Parallel()
				prefix := strings.Repeat("x", prefixLen)
				for _, frame := range []string{
					prefix + tc.vendor + "=" + tc.secret,
					"αβ " + prefix + strings.ToUpper(tc.vendor) + "_API_KEY='" + tc.secret + "'",
					prefix + tc.vendor + "=" + tc.secret + ";" + tc.vendor + "=" + tc.secret,
					prefix + tc.vendor + " invalid " + tc.vendor + "=" + tc.secret,
				} {
					var want []Match
					remaining, offset := frame, 0
					for {
						i := strings.Index(remaining, tc.secret)
						if i < 0 {
							break
						}
						start := offset + i
						want = append(want, Match{Start: start, End: start + len(tc.secret), Value: tc.secret})
						offset = start + len(tc.secret)
						remaining = frame[offset:]
					}
					assert.Equal(t, want, Find(frame))
					assert.True(t, Contains(frame))
					assert.Equal(t, strings.ReplaceAll(frame, tc.secret, Marker), Redact(frame))
				}
			})
		}
	}
}

func TestContextualSecretSelection(t *testing.T) {
	t.Parallel()

	first, second := strings.Repeat("q", 40), strings.Repeat("r", 40)
	for _, prefix := range []string{
		"", ".-", "\xff", "K", "cloudflare invalid ",
		"cloudflare" + strings.Repeat("x", 51),
		"cloudflare=cloudflare-digital-experience-monitoring;",
	} {
		input := prefix + "cloudflare=" + first + ";cloudflare=" + second
		startFirst, startSecond := strings.Index(input, first), strings.Index(input, second)
		assert.Equal(t, []Match{
			{Start: startFirst, End: startFirst + len(first), Value: first},
			{Start: startSecond, End: startSecond + len(second), Value: second},
		}, Find(input), "prefix %q", prefix)
		assert.True(t, Contains(input), "prefix %q", prefix)
		assert.Equal(t, prefix+"cloudflare="+Marker+";cloudflare="+Marker, Redact(input))
	}

	input := "SNYK=abcd"
	old := regexp.MustCompile(referenceContextual("snyk", "[a-z]{4}"))
	current := regexp.MustCompile(contextual("snyk", "[a-z]{4}"))
	require.NotEmpty(t, contextualSpans(old, input))
	assert.Equal(t, contextualSpans(old, input), contextualSpans(current, input))
}

func referenceContextual(vendor, body string) string {
	return `(?i)[\w.-]{0,50}?(?:` + vendor + `)(?:[ \t\w.-]{0,20})[\s'"]{0,3}` +
		`(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}` +
		`(?P<secret>` + body + `)(?:[\x60'"\s;]|\\[nr]|$)`
}

func contextualSpans(re *regexp.Regexp, text string) []Match {
	var spans []Match
	for _, indices := range re.FindAllStringSubmatchIndex(text, -1) {
		start, end := redactSpan(indices, re.SubexpIndex("secret"))
		spans = append(spans, Match{Start: start, End: end, Value: text[start:end]})
	}
	return spans
}

func FuzzContextualSecretSpans(f *testing.F) {
	for _, text := range []string{
		"", "cloudflare", "cloudflare=abcd", "ENV_CLOUDFLARE_KEY=abcd;cloudflare=efgh",
		"cloudflare cloudflare=abcd", "cloudflare=abcdcloudflare=efgh",
		"cloudflare=abcd;\ncloudflare=efgh", "écloudflare=abcd", "\xffcloudflare=abcd",
		strings.Repeat("x", 50) + "cloudflare=abcd",
		strings.Repeat("x", 51) + "cloudflare=abcd",
		"cloudflare" + strings.Repeat(".-", 25) + "cloudflare=abcd;cloudflare=efgh",
		"cloudflare" + strings.Repeat("x", 51) + "cloudflare=abcd;cloudflare=efgh",
		"cloudflare_" + strings.Repeat("x", 20) + "=abcd",
		"cloudflare_" + strings.Repeat("x", 21) + "=abcd",
	} {
		f.Add(text)
	}
	old := regexp.MustCompile(referenceContextual("cloudflare", "[a-z]{4}"))
	current := regexp.MustCompile(contextual("cloudflare", "[a-z]{4}"))
	f.Fuzz(func(t *testing.T, text string) {
		require.Equal(t, contextualSpans(old, text), contextualSpans(current, text))
	})
}

func BenchmarkContextualRedact(b *testing.B) {
	for _, size := range []int{1000, 10000, 300000} {
		for _, withSecret := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/secret=%t", size, withSecret), func(b *testing.B) {
				text := strings.Repeat("ordinary prose without credentials. ", size/36) + " cloudflare"
				if withSecret {
					text += "=" + strings.Repeat("q", 40)
				}
				_ = Redact(text)
				b.SetBytes(int64(len(text)))
				b.ReportAllocs()
				for b.Loop() {
					_ = Redact(text)
				}
			})
		}
	}
}
