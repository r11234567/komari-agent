package qgastream

import (
	"encoding/json"
)

const frameLimit = 112 << 10

// Frame is valid during the publish callback. A consumer that retains a record seals it
// immediately. Reset and loss markers never contain partial payloads.
type Frame struct {
	Bytes []byte
	Reset bool
	Lost  bool
}

// Decoder parses a passive copy of one direction of the QGA JSON stream.
// Each direction has independent buffering and resynchronization state.
type Decoder struct {
	buffer    []byte
	depth     int
	quoted    bool
	escaped   bool
	untrusted bool
}

// Gap discards any partial message and waits for an explicit protocol boundary.
func (d *Decoder) Gap() {
	d.reset()
	d.untrusted = true
}

func (d *Decoder) Feed(fragment []byte, publish func(Frame) error) error {
	for _, b := range fragment {
		if b == 0xff {
			lost := len(d.buffer) != 0
			d.reset()
			if err := publish(Frame{Reset: true, Lost: lost}); err != nil {
				return err
			}
			continue
		}
		if d.untrusted {
			continue
		}
		if d.depth == 0 {
			switch b {
			case ' ', '\t', '\r', '\n':
				continue
			case '{':
				d.depth = 1
				if d.buffer == nil {
					d.buffer = make([]byte, 0, frameLimit)
				}
				d.buffer = append(d.buffer, b)
			default:
				d.Gap()
				if err := publish(Frame{Lost: true}); err != nil {
					return err
				}
			}
			continue
		}
		if len(d.buffer) == frameLimit {
			d.Gap()
			if err := publish(Frame{Lost: true}); err != nil {
				return err
			}
			continue
		}
		d.buffer = append(d.buffer, b)
		if d.escaped {
			d.escaped = false
			continue
		}
		if d.quoted {
			switch b {
			case '\\':
				d.escaped = true
			case '"':
				d.quoted = false
			}
			continue
		}
		switch b {
		case '"':
			d.quoted = true
		case '{', '[':
			d.depth++
		case '}', ']':
			d.depth--
		}
		if d.depth == 0 {
			frame := Frame{Lost: true}
			if json.Valid(d.buffer) {
				frame = Frame{Bytes: d.buffer}
			}
			err := publish(frame)
			d.reset()
			d.untrusted = frame.Lost
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Decoder) reset() {
	clear(d.buffer)
	d.buffer = d.buffer[:0]
	d.depth = 0
	d.quoted = false
	d.escaped = false
	d.untrusted = false
}
