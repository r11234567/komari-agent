package trafficwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	metrics "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ReadUpload reads only a completed analyzer record from the handoff directory.
func ReadUpload(root *os.Root, name string, enrolled, now time.Time) (*metrics.SubmitTrafficEvidenceRequest, error) {
	base, ok := strings.CutSuffix(name, ".json")
	if !ok {
		return nil, nil
	}
	kind, id, ok := strings.Cut(base, "-")
	if !ok {
		return nil, nil
	}
	switch kind {
	case "event":
		value, err := uuid.Parse(id)
		if err != nil || value.String() != id {
			return nil, nil
		}
	case "hour":
		if _, err := time.Parse("20060102T15", id); err != nil {
			return nil, nil
		}
	default:
		return nil, nil
	}
	file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxSnapshotBytes || info.Mode().Perm()&0o027 != 0 {
		return nil, errors.New("invalid evidence handoff file")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil || len(body) > maxSnapshotBytes {
		return nil, errors.New("could not read bounded evidence")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	decode := func(dst any) bool {
		return decoder.Decode(dst) == nil && errors.Is(decoder.Decode(new(any)), io.EOF)
	}
	if kind == "hour" {
		var h hourSummary
		if !decode(&h) || h.Hour.UTC().Format("20060102T15") != id || !h.Through.After(h.Hour) {
			return nil, errors.New("invalid evidence hour")
		}
		started := h.StartedAt
		if started.IsZero() {
			started = h.Hour
		}
		if started.Before(h.Hour) || !started.Before(h.Through) {
			return nil, errors.New("invalid evidence hour start")
		}
		if started.Before(enrolled) || !h.Hour.Add(7*24*time.Hour).After(now) {
			return nil, nil
		}
		services := make(map[string]*metrics.TrafficEvidenceBytes, len(h.Services))
		for name, count := range h.Services {
			services[name] = evidenceBytes(count)
		}
		return &metrics.SubmitTrafficEvidenceRequest{Record: &metrics.SubmitTrafficEvidenceRequest_Hour{
			Hour: &metrics.TrafficEvidenceHour{
				HourUtc: timestamppb.New(h.Hour), Through: timestamppb.New(h.Through),
				Observed: evidenceBytes(h.Observed), Services: services, Unexplained: evidenceBytes(h.Unexplained), Partial: h.Partial,
			},
		}}, nil
	}
	var s snapshot
	if !decode(&s) || s.ID != id || !s.Complete {
		return nil, errors.New("invalid evidence incident")
	}
	if s.Start.Before(enrolled) || !s.End.Add(snapshotTTL).After(now) {
		return nil, nil
	}
	return &metrics.SubmitTrafficEvidenceRequest{Record: &metrics.SubmitTrafficEvidenceRequest_Incident{
		Incident: &metrics.TrafficEvidenceIncident{
			Id: s.ID, Reason: s.Reason, InterfaceName: s.Interface, Sampler: s.Sampler,
			TriggeredAt: timestamppb.New(s.TriggeredAt), Start: timestamppb.New(s.Start), End: timestamppb.New(s.End),
			FirstPacketAt: evidenceTime(s.FirstPacket), LastPacketAt: evidenceTime(s.LastPacket), FlowsSpanSlices: s.SpansSlices,
			Observed: evidenceBytes(s.Observed), TriggerUnexplained: evidenceBytes(s.TriggerUnexplained), UnclassifiedBytes: s.Unclassified,
			Partial: s.Partial, Complete: s.Complete, IngressSources: evidencePeers(s.Sources), EgressDestinations: evidencePeers(s.Destinations),
			Other: evidenceBytes(s.Other),
		},
	}}, nil
}

func evidenceTime(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func evidenceBytes(t Traffic) *metrics.TrafficEvidenceBytes {
	return &metrics.TrafficEvidenceBytes{RxBytes: t.RX, TxBytes: t.TX}
}

func evidencePeers(peers []peer) []*metrics.TrafficEvidencePeer {
	out := make([]*metrics.TrafficEvidencePeer, 0, len(peers))
	for _, p := range peers {
		out = append(out, &metrics.TrafficEvidencePeer{Ip: p.Address.String(), Bytes: p.Bytes})
	}
	return out
}
