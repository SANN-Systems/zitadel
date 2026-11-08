package sannp4

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckPolicy(t *testing.T) {
	full := `{"org":"sann","journal":"journal","finalizer":"finalizer","kart":"kart","live":"live","deletion":"deletion"}`
	for _, tc := range []struct {
		name    string
		content *string
		ok      bool
	}{
		{"bootstrap", ptr(`{}`), true},
		{"full", ptr(full), true},
		{"missing file", nil, false},
		{"invalid json", ptr(`{"org":`), false},
		{"incomplete", ptr(`{"org":"sann","journal":"journal"}`), false},
		{"same journal and finalizer", ptr(`{"org":"sann","journal":"j","finalizer":"j","kart":"kart","live":"live","deletion":"deletion"}`), false},
		{"identities without org", ptr(`{"journal":"journal"}`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			if tc.content != nil {
				if err := os.WriteFile(path, []byte(*tc.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("SANN_P4_POLICY", path)
			if err := CheckPolicy(); (err == nil) != tc.ok {
				t.Fatalf("CheckPolicy() = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestCheckPolicyUnsetKeepsUpstream(t *testing.T) {
	t.Setenv("SANN_P4_POLICY", "")
	if err := CheckPolicy(); err != nil {
		t.Fatal(err)
	}
}

func ptr(s string) *string { return &s }
