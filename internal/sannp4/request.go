// Package sannp4 carries server-derived operation identity to the transactional contact guard.
package sannp4

import (
	"context"
	"encoding/json"
)

type requestKey struct{}
type Request struct {
	Method string
	Body   json.RawMessage
}

// WithRequest must only receive the authenticated server method and decoded request, never a header.
func WithRequest(ctx context.Context, method string, body []byte) context.Context {
	return context.WithValue(ctx, requestKey{}, Request{method, append(json.RawMessage(nil), body...)})
}

func FromContext(ctx context.Context) Request {
	r, _ := ctx.Value(requestKey{}).(Request)
	return r
}
