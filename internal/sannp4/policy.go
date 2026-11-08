package sannp4

import (
	"bytes"
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
// Only a literally empty object is the isolated bootstrap state. Anything else must be a complete
// policy without unknown fields; null, arrays and misspelled keys never switch the guard off.
func LoadPolicy() (p Policy, configured bool, err error) {
	path := os.Getenv("SANN_P4_POLICY")
	if path == "" {
		return p, false, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return p, true, fmt.Errorf("SANN_P4_POLICY: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return p, true, fmt.Errorf("SANN_P4_POLICY: %w", err)
	}
	if fields == nil {
		return p, true, errors.New("SANN_P4_POLICY: not an object")
	}
	if len(fields) == 0 {
		return p, true, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, true, fmt.Errorf("SANN_P4_POLICY: %w", err)
	}
	if p.Org == "" || p.Journal == "" || p.Finalizer == "" || p.Kart == "" || p.Live == "" || p.Deletion == "" {
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
