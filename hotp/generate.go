package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

func generateHOTP(secret []byte, counter uint64, digits int) string {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(counterBytes)
	hash := mac.Sum(nil)

	offset := hash[19] & 0x0f

	binaryCode := binary.BigEndian.Uint32(hash[offset : offset+4])
	binaryCode &= 0x7fffffff

	modulus := uint32(math.Pow10(digits))
	otp := binaryCode % modulus

	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, otp)
}

// Generate calculates a Time-Based One-Time Password per RFC 6238.
// The default timeStep(X) is 30 seconds.
func Generate(secret []byte, timeStep uint64, t time.Time, digits int) string {
	unixTime := uint64(t.Unix())

	T := unixTime / timeStep

	return generateHOTP(secret, T, digits)
}
