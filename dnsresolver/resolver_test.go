package dnsresolver

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestBuildTransportWithPreference_H2CAndNoConnLimit(t *testing.T) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	tr := buildTransportWithPreference(10*time.Second, tlsConfig, "4")

	if tr.MaxConnsPerHost != 0 {
		t.Fatalf("expected MaxConnsPerHost to be 0 (no limit), got %d", tr.MaxConnsPerHost)
	}

	if tr.MaxIdleConns < 64 {
		t.Fatalf("expected MaxIdleConns >= 64, got %d", tr.MaxIdleConns)
	}

	if tr.MaxIdleConnsPerHost < 16 {
		t.Fatalf("expected MaxIdleConnsPerHost >= 16, got %d", tr.MaxIdleConnsPerHost)
	}

	if tr.Protocols == nil {
		t.Fatal("expected Protocols to be configured on Transport for h2c support")
	}

	if !tr.Protocols.HTTP1() {
		t.Fatal("expected HTTP1 to be enabled for fallback")
	}

	if !tr.Protocols.HTTP2() {
		t.Fatal("expected HTTP2 to be enabled")
	}

	if !tr.Protocols.UnencryptedHTTP2() {
		t.Fatal("expected UnencryptedHTTP2 (h2c) to be enabled")
	}
}

func TestGetStreamingHTTPClientWithPreference_HasH2CSupport(t *testing.T) {
	client := GetStreamingHTTPClientWithPreference("4")
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	tr, ok := client.Transport.(*SmartStreamTransport)
	if !ok {
		t.Fatalf("expected *SmartStreamTransport, got %T", client.Transport)
	}

	if tr.H2CTransport == nil || !tr.H2CTransport.AllowHTTP {
		t.Fatal("expected H2CTransport with AllowHTTP=true for cleartext bidi streaming")
	}

	if tr.BaseTransport == nil || tr.BaseTransport.MaxConnsPerHost != 0 {
		t.Fatalf("expected BaseTransport with MaxConnsPerHost == 0, got %v", tr.BaseTransport)
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
	if err != nil || req.URL.Scheme != "http" {
		t.Fatalf("failed to create http request: %v", err)
	}
}
