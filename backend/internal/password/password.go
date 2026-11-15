// Package password generates and validates database user passwords.
package password

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"unicode"
)

const (
	generatedLength = 24
	// MinLength and MaxLength bound user-supplied passwords.
	MinLength = 8
	MaxLength = 128
	// Letters and digits only, so generated passwords need no escaping in
	// connection URIs, shells or YAML.
	alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
)

// Generate returns a random password with upper and lower case letters
// and digits, as password policies such as SQL Server's require.
func Generate() (string, error) {
	for {
		password, err := random()
		if err != nil {
			return "", err
		}
		if hasEveryClass(password) {
			return password, nil
		}
	}
}

func random() (string, error) {
	max := big.NewInt(int64(len(alphabet)))
	out := make([]byte, generatedLength)
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}

func hasEveryClass(password string) bool {
	var upper, lower, digit bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		}
	}
	return upper && lower && digit
}

// Validate checks a user-supplied password.
func Validate(password string) error {
	if len(password) < MinLength || len(password) > MaxLength {
		return fmt.Errorf("password must be %d to %d characters long", MinLength, MaxLength)
	}
	for _, r := range password {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("password must not contain control characters")
		}
	}
	return nil
}
