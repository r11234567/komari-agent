package requestheaders

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/komari-monitor/komari-agent/core/credentials"
)

// DPoPTransport signs HTTP requests using Ed25519 according to the Komari DPoP specification.
// It supports both Unary and Streaming requests.
type DPoPTransport struct {
	Base     http.RoundTripper
	Identity func() (credentials.Identity, bool)
	Token    func() string
	On401    func(ctx context.Context, oldToken string) error
}

// WrapWithDPoP wraps an http.Client with DPoP request signing and optional 401 refresh handling.
func WrapWithDPoP(httpClient *http.Client, identityProvider func() (credentials.Identity, bool), tokenProvider func() string, on401 func(ctx context.Context, oldToken string) error) *http.Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	transport := httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{
		Transport: &DPoPTransport{
			Base:     transport,
			Identity: identityProvider,
			Token:    tokenProvider,
			On401:    on401,
		},
		Timeout: httpClient.Timeout,
	}
}

// WrapWithStaticDPoP wraps an http.Client with DPoP request signing using a fixed identity.
func WrapWithStaticDPoP(httpClient *http.Client, identity credentials.Identity) *http.Client {
	return WrapWithDPoP(httpClient, func() (credentials.Identity, bool) {
		return identity, true
	}, func() string {
		return identity.AccessToken
	}, nil)
}

// RoundTrip signs the request with DPoP headers before passing it to the underlying transport.
func (d *DPoPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if d.Identity == nil {
		return d.Base.RoundTrip(req)
	}

	identity, ok := d.Identity()
	if !ok || identity.PrivateKey == "" {
		return d.Base.RoundTrip(req)
	}

	privKey, err := identity.SigningKey()
	if err != nil || len(privKey) != ed25519.PrivateKeySize {
		return d.Base.RoundTrip(req)
	}

	token := ""
	if d.Token != nil {
		token = d.Token()
	}
	if token == "" {
		auth := req.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if token == "" {
		token = identity.AccessToken
	}
	if token == "" {
		return d.Base.RoundTrip(req)
	}

	// Detect client-streaming body
	isStream := req.Body != nil && req.Body != http.NoBody && req.ContentLength < 0 && req.GetBody == nil

	var bodyBytes []byte
	if !isStream && req.Body != nil && req.Body != http.NoBody {
		var readErr error
		bodyBytes, readErr = io.ReadAll(req.Body)
		if readErr != nil {
			return nil, readErr
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	signRequest := func(curToken string) {
		tokenDigest := sha256.Sum256([]byte(curToken))
		tokenHash := hex.EncodeToString(tokenDigest[:])
		var bodyHash string
		if isStream {
			bodyDigest := sha256.Sum256(nil)
			bodyHash = hex.EncodeToString(bodyDigest[:])
			req.Header.Set("X-Komari-Body-Mode", "stream")
		} else {
			bodyDigest := sha256.Sum256(bodyBytes)
			bodyHash = hex.EncodeToString(bodyDigest[:])
		}
		tsStr := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := uuid.NewString()

		payload := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", req.Method, req.URL.Path, tsStr, nonce, tokenHash, bodyHash)
		sig := ed25519.Sign(privKey, []byte(payload))

		req.Header.Set("Authorization", "Bearer "+curToken)
		req.Header.Set("X-Komari-Signature", base64.StdEncoding.EncodeToString(sig))
		req.Header.Set("X-Komari-Timestamp", tsStr)
		req.Header.Set("X-Komari-Nonce", nonce)
	}

	signRequest(token)

	resp, err := d.Base.RoundTrip(req)
	if err == nil && resp.StatusCode == http.StatusUnauthorized && d.On401 != nil {
		if refreshErr := d.On401(req.Context(), token); refreshErr == nil {
			newToken := ""
			if d.Token != nil {
				newToken = d.Token()
			}
			if newToken != "" && newToken != token {
				_ = resp.Body.Close()
				signRequest(newToken)
				if !isStream && bodyBytes != nil {
					req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				}
				return d.Base.RoundTrip(req)
			}
		}
	}

	return resp, err
}
