package rescue

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
)

type sshListenSocket struct {
	address netip.Addr
	port    uint32
	root    bool
}

func inspectSSHDaemon(ctx context.Context, port uint32) *rescuev1.SSHDaemonState {
	state := &rescuev1.SSHDaemonState{}
	var observed []uint32
	for _, file := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile(filepath.Join(procRootDirectory(), "net", file))
		if err != nil {
			continue
		}
		for _, socket := range parseSSHListenSockets(string(data)) {
			observed = append(observed, socket.port)
			if socket.port == port {
				state.ListenAddresses = append(state.ListenAddresses, socket.address.String())
			}
		}
	}
	state.ObservedListenPorts = uniqueUint32(observed)
	state.ListenAddresses = uniqueStrings(state.ListenAddresses)
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		state.Limitation = fmt.Sprintf("inspect local network addresses: %v", err)
		return state
	}
	probeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, address := range addresses {
		ip, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		candidate, ok := netip.AddrFromSlice(ip.IP)
		if !ok || !candidate.IsGlobalUnicast() {
			continue
		}
		// A locally verified SSH identification also supports socket-activated
		// services and excludes unrelated listeners and loopback-only bindings.
		if probeSSHIdentification(probeContext, net.JoinHostPort(candidate.Unmap().String(), strconv.FormatUint(uint64(port), 10))) {
			state.Running = true
			state.Reachable = true
			return state
		}
	}
	state.Limitation = fmt.Sprintf("no SSH service responded on a non-loopback address at TCP %d; check sshd and its ListenAddress", port)
	return state
}

func probeSSHIdentification(ctx context.Context, address string) bool {
	probe, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(probe, "tcp", address)
	if err != nil {
		return false
	}
	defer conn.Close()
	deadline, _ := probe.Deadline()
	if err := conn.SetReadDeadline(deadline); err != nil {
		return false
	}
	line, err := bufio.NewReaderSize(conn, 256).ReadSlice('\n')
	return err == nil && (strings.HasPrefix(string(line), "SSH-2.0-") || strings.HasPrefix(string(line), "SSH-1.99-"))
}

func parseSSHListenSockets(data string) []sshListenSocket {
	var sockets []sshListenSocket
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		ip, portHex, ok := strings.Cut(fields[1], ":")
		if !ok || (len(ip) != 8 && len(ip) != 32) {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		raw := make([]byte, 0, len(ip)/2)
		for offset := 0; offset < len(ip); offset += 8 {
			word, err := strconv.ParseUint(ip[offset:offset+8], 16, 32)
			if err != nil {
				break
			}
			raw = binary.NativeEndian.AppendUint32(raw, uint32(word))
		}
		if len(raw) != len(ip)/2 {
			continue
		}
		if address, ok := netip.AddrFromSlice(raw); ok {
			sockets = append(sockets, sshListenSocket{
				address: address.Unmap(), port: uint32(port),
				root: len(fields) > 7 && fields[7] == "0",
			})
		}
	}
	return sockets
}
