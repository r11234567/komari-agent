package enrollment

import (
	"errors"

	"connectrpc.com/connect"
	commonv1 "github.com/r11234567/komari-proto/gen/go/komari/common/v1"
)

// CredentialRejectedError is created only by Refresh for explicit rejection
// or required recovery from the enrollment service. Transport status alone
// has no authority to stop credential renewal.
type CredentialRejectedError struct{ cause error }

func (e *CredentialRejectedError) Error() string { return e.cause.Error() }
func (e *CredentialRejectedError) Unwrap() error { return e.cause }

func refreshError(err error) error {
	var rpcError *connect.Error
	if !errors.As(err, &rpcError) || !connect.IsWireError(err) {
		return err
	}
	var expectedCode string
	switch rpcError.Code() {
	case connect.CodeUnauthenticated:
		expectedCode = "REFRESH_CREDENTIAL_REJECTED"
	case connect.CodeFailedPrecondition:
		expectedCode = "REFRESH_RECOVERY_REQUIRED"
	default:
		return err
	}
	for _, detail := range rpcError.Details() {
		message, decodeErr := detail.Value()
		if decodeErr != nil {
			continue
		}
		if rejected, ok := message.(*commonv1.ErrorDetail); ok && rejected.GetCode() == expectedCode {
			return &CredentialRejectedError{cause: err}
		}
	}
	return err
}
