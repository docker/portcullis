package portcullis

import (
	"hash/crc32"
	"strings"
)

const (
	githubChecksumLen = 6
	base62Alphabet    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	awsKeyIDAlphabet  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

func validGitHubChecksum(token string) bool {
	if len(token) <= githubChecksumLen {
		return false
	}

	provided := token[len(token)-githubChecksumLen:]
	checksumless := token[:len(token)-githubChecksumLen]
	return provided == base62CRC32(checksumless)
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
