package dnsresolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsServerTimeout = time.Second

func resolverForServer(primary string, fallbacks []string) *net.Resolver {
	if primary == "" {
		return net.DefaultResolver
	}
	servers := []string{primary}
	for _, server := range fallbacks {
		if server != primary {
			servers = append(servers, server)
		}
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// A stream connection lets the standard resolver supply the real
			// DNS question with a length prefix. Keep its host and TCP fallback
			// behavior while selecting a server on each actual DNS response.
			client, relay := net.Pipe()
			go relayDNSQuery(ctx, relay, network, servers)
			return client, nil
		},
	}
}

func relayDNSQuery(ctx context.Context, relay net.Conn, network string, servers []string) {
	defer relay.Close()
	var size uint16
	if err := binary.Read(relay, binary.BigEndian, &size); err != nil || size < 12 {
		return
	}
	query := make([]byte, size)
	if _, err := io.ReadFull(relay, query); err != nil {
		return
	}

	for _, server := range servers {
		if ctx.Err() != nil {
			return
		}
		response, err := exchangeDNS(ctx, network, server, query)
		if err != nil {
			continue
		}
		var header dnsmessage.Parser
		result, err := header.Start(response)
		if err != nil || !result.Response || result.ID != binary.BigEndian.Uint16(query) {
			continue
		}
		if !result.Truncated && result.RCode != dnsmessage.RCodeSuccess && result.RCode != dnsmessage.RCodeNameError {
			continue
		}
		_, _ = relay.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(response))), response...))
		return
	}
}

func exchangeDNS(ctx context.Context, network, server string, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsServerTimeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	switch network {
	case "udp":
		if n, err := conn.Write(query); err != nil || n != len(query) {
			return nil, errors.Join(err, io.ErrShortWrite)
		}
		response := make([]byte, 64<<10)
		n, err := conn.Read(response)
		return response[:n], err
	case "tcp":
		frame := append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)
		if n, err := conn.Write(frame); err != nil || n != len(frame) {
			return nil, errors.Join(err, io.ErrShortWrite)
		}
		var size uint16
		if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
			return nil, err
		}
		response := make([]byte, size)
		_, err := io.ReadFull(conn, response)
		return response, err
	default:
		return nil, errors.New("unsupported DNS network")
	}
}
