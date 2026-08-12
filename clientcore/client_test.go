package clientcore

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
)

func TestClassifyFallsBackOnlyForTransportOrMissingService(t *testing.T) {
	if !errors.Is(classify(connect.NewError(connect.CodeUnavailable, errors.New("offline"))), ErrLegacyFallback) {
		t.Fatal("unavailable must use compatibility fallback")
	}
	if !errors.Is(classify(connect.NewError(connect.CodeUnimplemented, errors.New("old server"))), ErrLegacyFallback) {
		t.Fatal("unimplemented must use compatibility fallback")
	}
	for _, code := range []connect.Code{connect.CodeUnauthenticated, connect.CodePermissionDenied, connect.CodeInvalidArgument, connect.CodeAborted, connect.CodeCanceled, connect.CodeDeadlineExceeded} {
		if errors.Is(classify(connect.NewError(code, errors.New("must not fallback"))), ErrLegacyFallback) {
			t.Fatalf("%s must not use compatibility fallback", code)
		}
	}
}

func TestConnectBaseURL(t *testing.T) {
	if _, err := connectBaseURL("https://panel.example.test/"); err != nil {
		t.Fatal(err)
	}
	if _, err := connectBaseURL("not-a-url"); err == nil {
		t.Fatal("expected invalid endpoint error")
	}
	if err := classify(context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation must remain visible")
	}
}
