package requestheaders

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/komari-monitor/komari-agent/core/credentials"
)

const (
	// DPoPTypHeader is the RFC 9449 JWT media type for DPoP proofs.
	DPoPTypHeader    = "dpop+jwt"
	maxCachedNonces  = 64
	maxDPoPNonceLen  = 256
	fileTransferPath = "/api/clients/transfer/"
)

// NonceStore caches server-provided DPoP-Nonce values per HTTP origin across
// unary and streaming transports.
type NonceStore struct {
	mu     sync.RWMutex
	nonces map[string]string
}

// NewNonceStore returns an empty origin-keyed DPoP-Nonce store.
func NewNonceStore() *NonceStore {
	return &NonceStore{nonces: make(map[string]string)}
}

func (s *NonceStore) Get(origin string) string {
	if s == nil || origin == "" {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nonces[origin]
}

func (s *NonceStore) Set(origin, nonce string) {
	if s == nil || origin == "" || !validDPoPNonce(nonce) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nonces == nil {
		s.nonces = make(map[string]string)
	}
	if len(s.nonces) >= maxCachedNonces {
		for k := range s.nonces {
			delete(s.nonces, k)
			break
		}
	}
	s.nonces[origin] = nonce
}

func validDPoPNonce(nonce string) bool {
	if len(nonce) == 0 || len(nonce) > maxDPoPNonceLen {
		return false
	}
	for i := 0; i < len(nonce); i++ {
		if nonce[i] <= 0x20 || nonce[i] >= 0x7f {
			return false
		}
	}
	return true
}

// DPoPTransport signs HTTP requests using EdDSA (Ed25519) RFC 9449 DPoP proof
// JWTs and handles DPoP-Nonce challenges as well as 401 token refreshes.
type DPoPTransport struct {
	Base           http.RoundTripper
	Identity       func() (credentials.Identity, bool)
	Token          func() string
	On401          func(ctx context.Context, oldToken string) error
	Nonces         *NonceStore
	BootstrapNonce bool

	nonceOnce     sync.Once
	fallbackNonce *NonceStore
}

func (d *DPoPTransport) nonceStore() *NonceStore {
	if d.Nonces != nil {
		return d.Nonces
	}
	d.nonceOnce.Do(func() {
		d.fallbackNonce = NewNonceStore()
	})
	return d.fallbackNonce
}

// WrapWithDPoP wraps an http.Client with RFC 9449 DPoP request signing and 401 retry handling.
func WrapWithDPoP(httpClient *http.Client, identityProvider func() (credentials.Identity, bool), tokenProvider func() string, on401 func(ctx context.Context, oldToken string) error) *http.Client {
	return WrapWithDPoPAndNonces(httpClient, identityProvider, tokenProvider, on401, nil)
}

// WrapWithDPoPAndNonces wraps an http.Client with a shared DPoP-Nonce cache.
func WrapWithDPoPAndNonces(httpClient *http.Client, identityProvider func() (credentials.Identity, bool), tokenProvider func() string, on401 func(ctx context.Context, oldToken string) error, nonces *NonceStore) *http.Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	transport := httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	wrapped := *httpClient
	wrapped.Transport = &DPoPTransport{
		Base: transport, Identity: identityProvider, Token: tokenProvider,
		On401: on401, Nonces: nonces,
	}
	wrapped.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 {
			origin, _ := requestOriginAndHTU(req)
			initial, _ := requestOriginAndHTU(via[0])
			if origin != initial || len(via) >= 10 {
				return http.ErrUseLastResponse
			}
		}
		if httpClient.CheckRedirect != nil {
			return httpClient.CheckRedirect(req, via)
		}
		return nil
	}
	return &wrapped
}

// WithNonceBootstrap lets an enrolled client obtain a nonce before sending a
// streaming body that cannot be replayed after an authentication challenge.
func WithNonceBootstrap(client *http.Client) *http.Client {
	if transport, ok := client.Transport.(*DPoPTransport); ok {
		transport.BootstrapNonce = true
	}
	return client
}

// WrapWithStaticDPoP wraps an http.Client with RFC 9449 DPoP request signing using a fixed identity.
func WrapWithStaticDPoP(httpClient *http.Client, identity credentials.Identity) *http.Client {
	return WrapWithDPoP(httpClient, func() (credentials.Identity, bool) {
		return identity, true
	}, func() string {
		return identity.AccessToken
	}, nil)
}

type dpopHeader struct {
	Typ string  `json:"typ"`
	Alg string  `json:"alg"`
	JWK dpopJWK `json:"jwk"`
}

type dpopJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath"`
	Nonce string `json:"nonce,omitempty"`
	BH    string `json:"bh,omitempty"`
	BM    string `json:"bm,omitempty"`
	QSH   string `json:"qsh,omitempty"`
}

func requestOriginAndHTU(target *http.Request) (origin string, htu string) {
	if target == nil || target.URL == nil {
		return "", ""
	}
	scheme := strings.ToLower(strings.TrimSpace(target.URL.Scheme))
	if scheme == "" {
		scheme = "https"
	}
	host := strings.ToLower(strings.TrimSpace(target.Host))
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(target.URL.Host))
	}
	path := target.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	origin = scheme + "://" + host
	return origin, origin + path
}

func buildDPoPProofJWT(privKey ed25519.PrivateKey, method, htu, rawQuery, accessToken, nonce, bodyHash string, isStream bool) (string, error) {
	pubKey := ed25519.PublicKey(privKey[ed25519.PrivateKeySize-ed25519.PublicKeySize:])
	headerBytes, err := json.Marshal(dpopHeader{
		Typ: DPoPTypHeader,
		Alg: "EdDSA",
		JWK: dpopJWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pubKey),
		},
	})
	if err != nil {
		return "", err
	}
	tokenDigest := sha256.Sum256([]byte(accessToken))
	claims := dpopClaims{
		JTI:   uuid.NewString(),
		HTM:   method,
		HTU:   htu,
		IAT:   time.Now().Unix(),
		ATH:   base64.RawURLEncoding.EncodeToString(tokenDigest[:]),
		Nonce: nonce,
		BH:    bodyHash,
	}
	if isStream {
		claims.BM = "stream"
	}
	if rawQuery != "" {
		queryDigest := sha256.Sum256([]byte(rawQuery))
		claims.QSH = base64.RawURLEncoding.EncodeToString(queryDigest[:])
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	sig := ed25519.Sign(privKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func isDPoPNonceChallenge(resp *http.Response, sentNonce string) bool {
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	nextNonce := strings.TrimSpace(resp.Header.Get("DPoP-Nonce"))
	if nextNonce == "" || nextNonce == sentNonce {
		return false
	}
	wwwAuth := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
	return strings.Contains(wwwAuth, "use_dpop_nonce")
}

func fetchStreamNonce(base http.RoundTripper, req *http.Request, agentID string) (string, error) {
	endpoint := *req.URL
	prefix, _, fileTransfer := strings.Cut(endpoint.Path, fileTransferPath)
	if !fileTransfer {
		prefix, _, _ = strings.Cut(endpoint.Path, "/komari.")
	}
	endpoint.Path = strings.TrimRight(prefix, "/") + "/ping"
	endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = "", "", ""
	endpoint.ForceQuery = false
	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()
	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	probe.Host = req.Host
	probe.Header.Set("X-Komari-Agent-Nonce-For", agentID)
	probe.Header.Set("Cache-Control", "no-cache")
	for _, header := range []string{"CF-Access-Client-Id", "CF-Access-Client-Secret"} {
		if value := req.Header.Get(header); value != "" {
			probe.Header.Set(header, value)
		}
	}
	response, err := base.RoundTrip(probe)
	if err != nil {
		return "", fmt.Errorf("fetch Agent DPoP nonce: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Agent DPoP nonce endpoint returned HTTP %d", response.StatusCode)
	}
	nonce := response.Header.Get("DPoP-Nonce")
	if !validDPoPNonce(nonce) {
		return "", errors.New("Agent DPoP nonce endpoint did not return a valid nonce")
	}
	return nonce, nil
}

// RoundTrip signs the request with RFC 9449 DPoP headers before passing it to the underlying transport.
func (d *DPoPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	isFileTransfer := strings.Contains(req.URL.Path, fileTransferPath)
	withoutProof := func() (*http.Response, error) {
		if !isFileTransfer {
			return d.Base.RoundTrip(req)
		}
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errors.New("file transfer requires an enrolled Agent identity")
	}
	if d.Identity == nil {
		return withoutProof()
	}

	identity, ok := d.Identity()
	if !ok || identity.PrivateKey == "" {
		return withoutProof()
	}

	privKey, err := identity.SigningKey()
	if err != nil || len(privKey) != ed25519.PrivateKeySize {
		return withoutProof()
	}

	token := ""
	if d.Token != nil {
		token = d.Token()
	}
	if token == "" {
		auth := strings.TrimSpace(req.Header.Get("Authorization"))
		switch {
		case len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer "):
			token = strings.TrimSpace(auth[7:])
		case len(auth) > 5 && strings.EqualFold(auth[:5], "DPoP "):
			token = strings.TrimSpace(auth[5:])
		}
	}
	if token == "" {
		token = identity.AccessToken
	}
	if token == "" {
		return withoutProof()
	}

	origin, _ := requestOriginAndHTU(req)
	nonces := d.nonceStore()
	isStream := req.Body != nil && req.Body != http.NoBody &&
		((isFileTransfer && req.ContentLength != 0) || (req.ContentLength < 0 && req.GetBody == nil))
	sentNonce := nonces.Get(origin)
	if isStream && (isFileTransfer || (d.BootstrapNonce && sentNonce == "")) && identity.AgentID != "" {
		sentNonce, err = fetchStreamNonce(d.Base, req, identity.AgentID)
		if err != nil {
			_ = req.Body.Close()
			return nil, err
		}
		nonces.Set(origin, sentNonce)
	}

	var bodyBytes []byte
	if !isStream && req.Body != nil && req.Body != http.NoBody {
		var readErr error
		bodyBytes, readErr = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
	}

	var bodyHash string
	if isStream {
		emptyDigest := sha256.Sum256(nil)
		bodyHash = base64.RawURLEncoding.EncodeToString(emptyDigest[:])
	} else {
		bodyDigest := sha256.Sum256(bodyBytes)
		bodyHash = base64.RawURLEncoding.EncodeToString(bodyDigest[:])
	}

	signRequest := func(target *http.Request, curToken, nonce string) error {
		_, htu := requestOriginAndHTU(target)
		proof, signErr := buildDPoPProofJWT(privKey, target.Method, htu, target.URL.RawQuery, curToken, nonce, bodyHash, isStream)
		if signErr != nil {
			return signErr
		}
		target.Header.Set("Authorization", "DPoP "+curToken)
		target.Header.Set("DPoP", proof)
		for _, header := range []string{"X-Komari-Signature", "X-Komari-Timestamp", "X-Komari-Nonce", "X-Komari-Body-Mode"} {
			target.Header.Del(header)
		}
		return nil
	}

	cloneWithBody := func() *http.Request {
		cloned := req.Clone(req.Context())
		if !isStream && req.Body != nil && req.Body != http.NoBody {
			cloned.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		return cloned
	}

	recordNonce := func(resp *http.Response) {
		if resp == nil {
			return
		}
		if nextNonce := strings.TrimSpace(resp.Header.Get("DPoP-Nonce")); nextNonce != "" {
			nonces.Set(origin, nextNonce)
		}
	}

	outReq := cloneWithBody()
	if signErr := signRequest(outReq, token, sentNonce); signErr != nil {
		return nil, signErr
	}

	resp, err := d.Base.RoundTrip(outReq)
	recordNonce(resp)

	if err == nil && isDPoPNonceChallenge(resp, sentNonce) {
		if isStream {
			return resp, nil
		}
		_ = resp.Body.Close()
		sentNonce = nonces.Get(origin)
		retryReq := cloneWithBody()
		if signErr := signRequest(retryReq, token, sentNonce); signErr != nil {
			return nil, signErr
		}
		resp, err = d.Base.RoundTrip(retryReq)
		recordNonce(resp)
	}

	if err == nil && resp.StatusCode == http.StatusUnauthorized && d.On401 != nil && !isDPoPNonceChallenge(resp, sentNonce) {
		if refreshErr := d.On401(req.Context(), token); refreshErr == nil {
			// Streaming request bodies (GetBody == nil) cannot be replayed safely
			// once handed to the transport. Refresh the credential cache and let
			// the caller's stream loop establish a fresh connection.
			if isStream {
				return resp, err
			}
			newToken := ""
			if d.Token != nil {
				newToken = d.Token()
			}
			if newToken != "" && newToken != token {
				_ = resp.Body.Close()
				retryReq := cloneWithBody()
				if signErr := signRequest(retryReq, newToken, nonces.Get(origin)); signErr != nil {
					return nil, signErr
				}
				resp, err = d.Base.RoundTrip(retryReq)
				recordNonce(resp)
			}
		}
	}

	return resp, err
}
