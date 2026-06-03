package enpass

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ComputeTOTP returns the current RFC 6238 code for the given field value.
// The value may be a bare base32 secret (with optional whitespace, dashes,
// and missing padding) or an otpauth://totp/... URI carrying the secret and
// optional period/digits/algorithm parameters. Returns an error if the value
// can't be parsed as a TOTP secret.
func ComputeTOTP(value string, now time.Time) (string, error) {
	secret, period, digits, algo, err := parseTOTPValue(value)
	if err != nil {
		return "", err
	}

	key, err := base32.StdEncoding.DecodeString(normalizeBase32(secret))
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret: %w", err)
	}
	if len(key) == 0 {
		return "", fmt.Errorf("empty TOTP secret")
	}

	var newHash func() hash.Hash
	switch strings.ToUpper(algo) {
	case "SHA1":
		newHash = sha1.New
	case "SHA256":
		newHash = sha256.New
	case "SHA512":
		newHash = sha512.New
	default:
		return "", fmt.Errorf("unsupported TOTP algorithm: %s", algo)
	}

	counter := uint64(now.Unix()) / uint64(period)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(newHash, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod), nil
}

func parseTOTPValue(value string) (secret string, period, digits int, algo string, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, 0, "", fmt.Errorf("empty TOTP value")
	}

	period, digits, algo = 30, 6, "SHA1"

	if !strings.HasPrefix(strings.ToLower(value), "otpauth://") {
		return value, period, digits, algo, nil
	}

	u, perr := url.Parse(value)
	if perr != nil {
		return "", 0, 0, "", fmt.Errorf("invalid otpauth URI: %w", perr)
	}
	q := u.Query()
	secret = q.Get("secret")
	if secret == "" {
		return "", 0, 0, "", fmt.Errorf("otpauth URI has no secret")
	}
	if p := q.Get("period"); p != "" {
		if n, perr := strconv.Atoi(p); perr == nil && n > 0 {
			period = n
		}
	}
	if d := q.Get("digits"); d != "" {
		if n, perr := strconv.Atoi(d); perr == nil && n > 0 {
			digits = n
		}
	}
	if a := q.Get("algorithm"); a != "" {
		algo = a
	}
	return secret, period, digits, algo, nil
}

func normalizeBase32(secret string) string {
	secret = strings.ToUpper(secret)
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.ReplaceAll(secret, "-", "")
	if rem := len(secret) % 8; rem != 0 {
		secret += strings.Repeat("=", 8-rem)
	}
	return secret
}
