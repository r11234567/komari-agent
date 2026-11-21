package enrollment

import (
	"errors"

	"connectrpc.com/connect"
	commonv1 "github.com/r11234567/komari-proto/gen/go/komari/common/v1"
)

// CredentialRejectedError is created only by Refresh after decoding the
// enrollment service's explicit application detail. A transport status, even a
// native Connect status from an ingress middleware, has no revocation authority.
type CredentialRejectedError struct{ cause error }

func (e *CredentialRejectedError) Error() string { return e.cause.Error() }
func (e *CredentialRejectedError) Unwrap() error { return e.cause }

func refreshError(err error) error {
	var rpcError *connect.Error
	if !errors.As(err, &rpcError) || rpcError.Code() != connect.CodeUnauthenticated || !connect.IsWireError(err) {
		return err
	}
	for _, detail := range rpcError.Details() {
		message, decodeErr := detail.Value()
		if decodeErr != nil {
			continue
		}
		if rejected, ok := message.(*commonv1.ErrorDetail); ok && rejected.Code == "REFRESH_CREDENTIAL_REJECTED" {
			return &CredentialRejectedError{cause: err}
		}
	}
	return err
}
