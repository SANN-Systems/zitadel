package sannp4

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Policy is the operator-owned P4 policy. The IDs are service identities, not tokens.
type Policy struct {
	Org       string `json:"org"`
	Journal   string `json:"journal"`
	Finalizer string `json:"finalizer"`
	Kart      string `json:"kart"`
	Live      string `json:"live"`
	Deletion  string `json:"deletion"`
}

// LoadPolicy reads SANN_P4_POLICY. configured is false when the variable is unset (upstream behaviour).
// An empty policy is the isolated bootstrap state; a policy with an org must name every identity.
func LoadPolicy() (p Policy, configured bool, err error) {
	path := os.Getenv("SANN_P4_POLICY")
	if path == "" {
		return p, false, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return p, true, fmt.Errorf("SANN_P4_POLICY: %w", err)
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, true, fmt.Errorf("SANN_P4_POLICY: %w", err)
	}
	if p.Org == "" {
		if p != (Policy{}) {
			return p, true, errors.New("SANN_P4_POLICY: identities without org")
		}
		return p, true, nil
	}
	if p.Journal == "" || p.Finalizer == "" || p.Kart == "" || p.Live == "" || p.Deletion == "" {
		return p, true, errors.New("SANN_P4_POLICY: incomplete policy")
	}
	if p.Journal == p.Finalizer {
		return p, true, errors.New("SANN_P4_POLICY: journal and finalizer must differ")
	}
	return p, true, nil
}

// CheckPolicy is the startup health check: a configured but broken policy stops the start
// instead of surfacing later as denied writes.
func CheckPolicy() error {
	_, _, err := LoadPolicy()
	return err
}
