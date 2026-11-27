package trafficwatch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/encoding/protowire"
)

const xrayGetStats = "/xray.app.stats.command.StatsService/GetStats"

type xrayStats struct {
	transport *http2.Transport
	client    *connect.Client[xrayStatRequest, xrayStatResponse]
}

func newXrayStats(endpoint string) *xrayStats {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
			if address != endpoint {
				return nil, errors.New("Xray stats dialing outside the configured endpoint")
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &xrayStats{transport: transport,
		client: connect.NewClient[xrayStatRequest, xrayStatResponse](httpClient, "http://"+endpoint+xrayGetStats,
			connect.WithGRPC(), connect.WithCodec(xrayStatsCodec{}), connect.WithReadMaxBytes(4096), connect.WithSendMaxBytes(256))}
}

func (x *xrayStats) counter(ctx context.Context, name string) (uint64, error) {
	result, err := x.client.CallUnary(ctx, connect.NewRequest(&xrayStatRequest{name: name}))
	if connect.CodeOf(err) == connect.CodeNotFound {
		return 0, nil // Xray may initialize counters on first use.
	}
	if err != nil {
		return 0, fmt.Errorf("Xray GetStats: %w", err)
	}
	if result.Msg.name != name {
		return 0, errors.New("Xray returned an unexpected aggregate name")
	}
	return result.Msg.value, nil
}

type xrayStatRequest struct{ name string }
type xrayStatResponse struct {
	name  string
	value uint64
}

// Xray's GetStats protobuf has only these fields. Keeping the codec scoped
// to the exact RPC avoids importing the proxy or exposing its user-stat APIs.
// https://github.com/XTLS/Xray-core/blob/main/app/stats/command/command.proto
type xrayStatsCodec struct{}

func (xrayStatsCodec) Name() string { return "proto" }

func (xrayStatsCodec) Marshal(msg any) ([]byte, error) {
	switch m := msg.(type) {
	case *xrayStatRequest:
		// reset is field 2; its omitted protobuf value is false.
		return protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), m.name), nil
	case *xrayStatResponse:
		stat := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), m.name)
		stat = protowire.AppendVarint(protowire.AppendTag(stat, 2, protowire.VarintType), m.value)
		return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), stat), nil
	default:
		return nil, errors.New("unexpected Xray stats message type")
	}
}

func (xrayStatsCodec) Unmarshal(data []byte, msg any) error {
	switch m := msg.(type) {
	case *xrayStatRequest:
		name, value, err := decodeXrayStat(data)
		if err == nil && value != 0 {
			return errors.New("Xray stats reset requested")
		}
		m.name = name
		return err
	case *xrayStatResponse:
		number, kind, n := protowire.ConsumeTag(data)
		if n < 0 || number != 1 || kind != protowire.BytesType {
			return errors.New("invalid Xray GetStats response")
		}
		stat, n := protowire.ConsumeBytes(data[n:])
		if n < 0 {
			return protowire.ParseError(n)
		}
		var err error
		m.name, m.value, err = decodeXrayStat(stat)
		return err
	default:
		return errors.New("unexpected Xray stats message type")
	}
}

func decodeXrayStat(data []byte) (name string, value uint64, err error) {
	for len(data) != 0 {
		number, kind, n := protowire.ConsumeTag(data)
		if n < 0 {
			return "", 0, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case number == 1 && kind == protowire.BytesType:
			name, n = protowire.ConsumeString(data)
		case number == 2 && kind == protowire.VarintType:
			value, n = protowire.ConsumeVarint(data)
		default:
			n = protowire.ConsumeFieldValue(number, kind, data)
		}
		if n < 0 {
			return "", 0, protowire.ParseError(n)
		}
		data = data[n:]
	}
	if name == "" || value > math.MaxInt64 {
		return "", 0, errors.New("invalid Xray aggregate statistic")
	}
	return name, value, nil
}
