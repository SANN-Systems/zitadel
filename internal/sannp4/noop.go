package sannp4

import (
	"encoding/json"
	"os"

	"github.com/zitadel/zitadel/internal/zerrors"
)

// RejectContactNoop closes the command's early return without writing an event or consuming an order.
// A repeated finalization must fail even when the requested contact is already present.
func RejectContactNoop(org string) error {
	path := os.Getenv("SANN_P4_POLICY")
	if path == "" {
		return nil
	}
	var policy struct {
		Org string `json:"org"`
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &policy) != nil || policy.Org == org {
		return zerrors.ThrowPreconditionFailed(nil, "SANN-P4-NOOP", "Errors.NoChangesFound")
	}
	return nil
}
