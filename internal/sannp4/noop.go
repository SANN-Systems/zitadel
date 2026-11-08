package sannp4

import (
	"github.com/zitadel/zitadel/internal/zerrors"
)

// RejectContactNoop closes the command's early return without writing an event or consuming an order.
// A repeated finalization must fail even when the requested contact is already present.
func RejectContactNoop(org string) error {
	policy, configured, err := LoadPolicy()
	if !configured {
		return nil
	}
	if err != nil || policy.Org == org {
		return zerrors.ThrowPreconditionFailed(nil, "SANN-P4-NOOP", "Errors.NoChangesFound")
	}
	return nil
}
