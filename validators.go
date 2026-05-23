package portcullis

import "hash/crc32"

const (
	githubChecksumLen = 6
	base62Alphabet    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

func validGitHubChecksum(token string) bool {
	if len(token) <= githubChecksumLen {
		return false
	}

	provided := token[len(token)-githubChecksumLen:]
	checksumless := token[:len(token)-githubChecksumLen]
	return provided == base62CRC32(checksumless)
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
