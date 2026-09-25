package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	ping "github.com/prometheus-community/pro-bing"
)

func resolveIP(target string) (string, error) {
	if ip := net.ParseIP(target); ip != nil {
		return target, nil
	}
	addrs, err := net.LookupHost(target)
	if err != nil || len(addrs) == 0 {
		return "", errors.New("failed to resolve target")
	}
	return addrs[0], nil
}

func icmpPing(target string, timeout time.Duration) (int64, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.Trim(host, "[]")
	ip, err := resolveIP(host)
	if err != nil {
		return -1, err
	}
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return -1, err
	}
	pinger.Count = 1
	pinger.Timeout = timeout
	pinger.SetPrivileged(true)
	if err := pinger.Run(); err != nil {
		return -1, err
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return -1, errors.New("no packets received")
	}
	return stats.AvgRtt.Milliseconds(), nil
}

func tcpPing(target string, timeout time.Duration) (int64, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "80"
	}
	host = strings.Trim(host, "[]")
	ip, err := resolveIP(host)
	if err != nil {
		return -1, err
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
	if err != nil {
		return -1, err
	}
	defer conn.Close()
	return time.Since(start).Milliseconds(), nil
}

func httpPing(target string, timeout time.Duration) (int64, error) {
	targetURL, err := normalizeHTTPPingTarget(target)
	if err != nil {
		return -1, err
	}
	resolvedIP, err := resolveIP(targetURL.Hostname())
	if err != nil {
		return -1, err
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, net.JoinHostPort(resolvedIP, port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return -1, err
	}
	start := time.Now()
	resp, err := client.Do(req) // lgtm[go/request-forgery]
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return latency, nil
	}
	return latency, errors.New("http status not ok")
}

func normalizeHTTPPingTarget(target string) (*url.URL, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if targetURL.Scheme != "http" && targetURL.Scheme != "https" {
		return nil, errors.New("HTTP ping target must use http or https")
	}
	if targetURL.Host == "" || targetURL.Hostname() == "" || targetURL.User != nil || targetURL.Fragment != "" {
		return nil, errors.New("HTTP ping target has an invalid authority")
	}
	if _, err := net.LookupPort("tcp", targetURL.Port()); targetURL.Port() != "" && err != nil {
		return nil, errors.New("HTTP ping target has an invalid port")
	}
	return targetURL, nil
}

// ProbePing executes the shared latency policy used by the Connect transport.
// A result of -1 means packet loss or an unreachable target.
func ProbePing(pingType, pingTarget string, timeout time.Duration) int64 {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	const highLatencyThreshold = 1000
	const retryDropThresholdTcping = 800

	measure := func() (int64, error) {
		switch pingType {
		case "icmp":
			return icmpPing(pingTarget, timeout)
		case "tcp":
			return tcpPing(pingTarget, timeout)
		case "http":
			return httpPing(pingTarget, timeout)
		default:
			return -1, errors.New("unsupported ping type")
		}
	}

	latency, err := measure()
	if err != nil {
		return -1
	}
	firstLatency := latency
	if latency > int64(highLatencyThreshold) {
		const retries = 3
		for i := 0; i < retries; i++ {
			second, err2 := measure()
			if err2 != nil {
				return -1
			}
			if second <= int64(highLatencyThreshold) {
				if pingType == "tcp" && firstLatency-second > int64(retryDropThresholdTcping) {
					return -1
				}
				return second
			}
			if i == retries-1 {
				return -1
			}
		}
	}
	return latency
}
