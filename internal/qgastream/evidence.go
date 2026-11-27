package qgastream

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"
)

const maxPending = 32

// Observation describes traffic already seen at the guest-agent boundary.
// Paths and outputs are taken from that conversation. No file is opened by
// this parser, and a reply means seen on the channel, not read by the operator.
type Observation struct {
	Direction  Direction `json:"direction"`
	Command    string    `json:"command,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	Raw        []byte    `json:"raw,omitempty"`
	Digest     [32]byte  `json:"sha256"`
	Omitted    bool      `json:"omitted,omitempty"`
	Gap        bool      `json:"gap,omitempty"`
}

type requestContext struct {
	id       []byte
	command  string
	value    uint64
	relevant bool
}

// Evidence keeps only bounded correlation state. It starts after a witnessed
// QGA sync so an in-flight reply from before attachment cannot be attributed
// to the first new request.
type Evidence struct {
	pending   []requestContext
	execIDs   map[uint64]struct{}
	fileIDs   map[uint64]struct{}
	syncID    uint64
	awaitSync bool
	synced    bool
}

func (e *Evidence) Observe(direction Direction, frame Frame, emit func(Observation) error) error {
	if frame.Lost {
		e.reset()
		return emit(Observation{Direction: direction, ObservedAt: time.Now().UTC(), Gap: true})
	}
	if frame.Reset {
		if direction == Request {
			e.reset()
		}
		return nil
	}
	if direction == Request {
		return e.request(frame.Bytes, emit)
	}
	if direction == Response {
		return e.response(frame.Bytes, emit)
	}
	return nil
}

func (e *Evidence) reset() {
	clear(e.pending)
	e.pending = e.pending[:0]
	clear(e.execIDs)
	clear(e.fileIDs)
	e.synced = false
	e.awaitSync = false
}

func (e *Evidence) request(raw []byte, emit func(Observation) error) error {
	var frame struct {
		Command string          `json:"execute"`
		ID      json.RawMessage `json:"id"`
		Args    struct {
			SyncID uint64          `json:"id"`
			PID    uint64          `json:"pid"`
			Handle uint64          `json:"handle"`
			Mode   string          `json:"mode"`
			Env    json.RawMessage `json:"env"`
			Input  json.RawMessage `json:"input-data"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &frame); err != nil || frame.Command == "" || len(frame.Command) > 96 || len(frame.ID) > 64 {
		return e.Observe(Request, Frame{Lost: true}, emit)
	}
	if frame.Command == "guest-sync" || frame.Command == "guest-sync-delimited" {
		e.reset()
		e.syncID = frame.Args.SyncID
		e.awaitSync = true
		return nil
	}
	if !e.synced {
		return nil
	}
	if len(e.pending) == maxPending {
		return e.Observe(Request, Frame{Lost: true}, emit)
	}
	request := requestContext{id: frame.ID, command: frame.Command}
	switch frame.Command {
	case "guest-exec":
		request.relevant = true
	case "guest-exec-status":
		request.value = frame.Args.PID
		_, request.relevant = e.execIDs[request.value]
	case "guest-file-open":
		request.relevant = frame.Args.Mode == "" || strings.HasPrefix(frame.Args.Mode, "r")
	case "guest-file-read", "guest-file-close":
		request.value = frame.Args.Handle
		_, request.relevant = e.fileIDs[request.value]
	}
	e.pending = append(e.pending, request)
	if !request.relevant {
		return nil
	}
	// Invocation environment and stdin may contain credentials supplied to
	// the remote operation. Keep the request digest without those raw bytes.
	omit := len(frame.Args.Env) != 0 || len(frame.Args.Input) != 0
	return emit(observation(Request, request.command, raw, omit))
}

func (e *Evidence) response(raw []byte, emit func(Observation) error) error {
	var frame struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"return"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &frame); err != nil {
		return e.Observe(Response, Frame{Lost: true}, emit)
	}
	if e.awaitSync {
		var got uint64
		if len(frame.Result) != 0 && !bytes.Equal(frame.Result, []byte("null")) && json.Unmarshal(frame.Result, &got) == nil && got == e.syncID {
			e.synced, e.awaitSync = true, false
		}
		return nil
	}
	if !e.synced {
		return nil
	}
	if len(e.pending) == 0 || !bytes.Equal(e.pending[0].id, frame.ID) || (len(frame.Error) == 0) == (len(frame.Result) == 0) {
		return e.Observe(Response, Frame{Lost: true}, emit)
	}
	request := e.pending[0]
	e.pending[0] = requestContext{}
	e.pending = e.pending[1:]
	if !request.relevant {
		return nil
	}
	if len(frame.Result) != 0 {
		switch request.command {
		case "guest-exec":
			var result struct {
				PID uint64 `json:"pid"`
			}
			if json.Unmarshal(frame.Result, &result) == nil && result.PID > 0 {
				if !remember(&e.execIDs, result.PID) {
					return e.Observe(Response, Frame{Lost: true}, emit)
				}
			}
		case "guest-exec-status":
			var result struct {
				Exited bool `json:"exited"`
			}
			if json.Unmarshal(frame.Result, &result) == nil && result.Exited {
				delete(e.execIDs, request.value)
			}
		case "guest-file-open":
			var handle uint64
			if json.Unmarshal(frame.Result, &handle) == nil && handle > 0 && !remember(&e.fileIDs, handle) {
				return e.Observe(Response, Frame{Lost: true}, emit)
			}
		case "guest-file-close":
			delete(e.fileIDs, request.value)
		}
	}
	return emit(observation(Response, request.command, raw, false))
}

func remember(ids *map[uint64]struct{}, id uint64) bool {
	if *ids == nil {
		*ids = make(map[uint64]struct{})
	}
	if len(*ids) == 256 {
		return false
	}
	(*ids)[id] = struct{}{}
	return true
}

func observation(direction Direction, command string, raw []byte, omit bool) Observation {
	record := Observation{Direction: direction, Command: command, ObservedAt: time.Now().UTC(), Digest: sha256.Sum256(raw), Omitted: omit}
	if !omit {
		record.Raw = raw
	}
	return record
}
