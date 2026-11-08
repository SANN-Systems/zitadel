package start

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A configured but broken P4 policy must stop the start before any database or API work.
func TestStartStopsOnInvalidSannP4Policy(t *testing.T) {
	for _, policy := range []string{`{"org":"sann"}`, `null`, `{"organisation":"sann"}`} {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, []byte(policy), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SANN_P4_POLICY", path)
		err := startZitadel(context.Background(), &Config{}, "", nil)
		if err == nil || !strings.Contains(err.Error(), "SANN_P4_POLICY") {
			t.Fatalf("start must stop on policy %s, got %v", policy, err)
		}
	}
}
