package password

import (
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		p, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != generatedLength {
			t.Fatalf("length = %d, want %d", len(p), generatedLength)
		}
		for _, r := range p {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("unexpected character %q in %q", r, p)
			}
		}
		if seen[p] {
			t.Fatalf("duplicate password %q", p)
		}
		seen[p] = true
		if err := Validate(p); err != nil {
			t.Fatalf("generated password fails validation: %v", err)
		}
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]bool{
		"short":                          false,
		"exactly8":                       true,
		"with spaces & symbols !@#$%":    true,
		strings.Repeat("a", MaxLength):   true,
		strings.Repeat("a", MaxLength+1): false,
		"tab\tinside":                    false,
	}
	for in, ok := range cases {
		if err := Validate(in); (err == nil) != ok {
			t.Errorf("Validate(%q) error = %v, want ok=%v", in, err, ok)
		}
	}
}

// SQL Server's password policy rejects passwords missing a character
// class; about 1 in 40 random ones would.
func TestGenerateHasEveryClass(t *testing.T) {
	for range 2000 {
		p, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.ContainsAny(p, "ABCDEFGHJKLMNPQRSTUVWXYZ") || !strings.ContainsAny(p, "abcdefghijkmnopqrstuvwxyz") || !strings.ContainsAny(p, "23456789") {
			t.Fatalf("password %q lacks a character class", p)
		}
	}
}
