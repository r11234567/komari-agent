package qgastream

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:embed bpf/channel_bpfel.o
var channelLittleEndian []byte

//go:embed bpf/channel_bpfeb.o
var channelBigEndian []byte

const virtioPort = "/dev/virtio-ports/org.qemu.guest_agent.0"

// Capture owns temporary tracing links and the read end of the kernel ring.
// The embedding service must bind its lifetime to local authorization.
type Capture struct {
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
	losses     *ebpf.Map
	lastLoss   uint64
	decoders   [2]Decoder
	record     ringbuf.Record
}

func Attach(pid int) (*Capture, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("QGA evidence requires a root Agent")
	}
	if pid <= 0 || uint64(pid) > uint64(^uint32(0)) {
		return nil, errors.New("invalid QGA process ID")
	}
	process := fmt.Sprintf("/proc/%d", pid)
	if err := verifyExecutable(process); err != nil {
		return nil, err
	}
	var device unix.Stat_t
	if err := unix.Stat(virtioPort, &device); err != nil {
		return nil, fmt.Errorf("resolve QGA virtio port: %w", err)
	}
	if device.Mode&unix.S_IFMT != unix.S_IFCHR {
		return nil, errors.New("QGA virtio port is not a character device")
	}
	if err := verifyOpenPort(process, device); err != nil {
		return nil, err
	}
	object := channelLittleEndian
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		object = channelBigEndian
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("read embedded QGA trace: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load QGA trace: %w", err)
	}
	c := &Capture{collection: collection, losses: collection.Maps["channel_losses"]}
	if err := c.attach(uint32(pid), device); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func verifyExecutable(process string) error {
	exe, err := os.Stat(filepath.Join(process, "exe"))
	if err != nil {
		return fmt.Errorf("inspect QGA executable: %w", err)
	}
	for _, path := range []string{"/usr/sbin/qemu-ga", "/usr/bin/qemu-ga"} {
		installed, err := os.Stat(path)
		if err == nil && os.SameFile(exe, installed) {
			return nil
		}
	}
	return errors.New("process does not match an installed QGA executable")
}

func verifyOpenPort(process string, port unix.Stat_t) error {
	dir := filepath.Join(process, "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("inspect QGA file descriptors: %w", err)
	}
	for _, entry := range entries {
		var open unix.Stat_t
		if unix.Stat(filepath.Join(dir, entry.Name()), &open) == nil && open.Dev == port.Dev && open.Ino == port.Ino && open.Rdev == port.Rdev {
			return nil
		}
	}
	return errors.New("QGA process has no open virtio port")
}

func (c *Capture) attach(pid uint32, device unix.Stat_t) error {
	selector := struct {
		Inode uint64
		PID   uint32
		Dev   uint32
	}{device.Ino, pid, unix.Major(device.Rdev)<<20 | unix.Minor(device.Rdev)}
	if err := c.collection.Maps["selected_channel"].Put(uint32(0), selector); err != nil {
		return err
	}
	for _, name := range []string{"qga_request", "qga_response"} {
		hook, err := link.AttachTracing(link.TracingOptions{Program: c.collection.Programs[name]})
		if err != nil {
			return fmt.Errorf("attach %s: %w", name, err)
		}
		c.links = append(c.links, hook)
	}
	var err error
	c.reader, err = ringbuf.NewReader(c.collection.Maps["channel_fragments"])
	return err
}

// Next consumes one ring entry. A concurrent Stop unblocks a waiting reader.
// Use one reader and seal sensitive content before returning from publish.
func (c *Capture) Next(publish func(Direction, Frame) error) error {
	if err := c.reader.ReadInto(&c.record); err != nil {
		return err
	}
	raw := c.record.RawSample
	defer clear(raw)
	if len(raw) != 4096+8 {
		return errors.New("unexpected trace record size")
	}
	var losses uint64
	if err := c.losses.Lookup(uint32(0), &losses); err != nil {
		return err
	}
	if losses != c.lastLoss {
		c.lastLoss = losses
		for _, direction := range []Direction{Request, Response} {
			c.decoders[direction-1].Gap()
			if err := publish(direction, Frame{Lost: true}); err != nil {
				return err
			}
		}
	}
	direction := Direction(binary.NativeEndian.Uint32(raw))
	size := binary.NativeEndian.Uint32(raw[4:8])
	if (direction != Request && direction != Response) || size == 0 || size > 4096 {
		return errors.New("invalid trace record")
	}
	return c.decoders[direction-1].Feed(raw[8:8+size], func(frame Frame) error { return publish(direction, frame) })
}

func (c *Capture) Stop() error { return c.reader.Close() }

func (c *Capture) Close() {
	if c.reader != nil {
		_ = c.reader.Close()
	}
	for _, hook := range c.links {
		_ = hook.Close()
	}
	c.collection.Close()
	for i := range c.decoders {
		c.decoders[i].reset()
	}
	clear(c.record.RawSample)
}
