package clientcore

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/internal/trafficwatch"
)

func (c *Client) runTrafficEvidence(ctx context.Context, identity credentials.Identity, inbox string) {
	if !filepath.IsAbs(inbox) || identity.EnrolledAt.IsZero() {
		log.Print("Traffic evidence requires an absolute inbox and an enrolled Agent identity")
		return
	}
	acknowledged := make(map[string]time.Time)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		c.sendTrafficEvidence(ctx, identity, inbox, acknowledged)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Client) sendTrafficEvidence(ctx context.Context, identity credentials.Identity, inbox string, acknowledged map[string]time.Time) {
	root, err := os.OpenRoot(inbox)
	if err != nil {
		log.Print("Traffic evidence inbox unavailable")
		return
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return
	}
	entries, err := dir.ReadDir(1024)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) == 1024 {
		log.Print("Traffic evidence inbox exceeds its file limit or is unreadable")
		return
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		seen[entry.Name()] = true
	}
	for name := range acknowledged {
		if !seen[name] {
			delete(acknowledged, name)
		}
	}
	now := time.Now().UTC()
	currentHour := "hour-" + now.Format("20060102T15") + ".json"
	priority := func(name string) int {
		switch {
		case name == currentHour:
			return 0
		case strings.HasPrefix(name, "event-"):
			return 1
		default:
			return 2
		}
	}
	slices.SortStableFunc(entries, func(a, b os.DirEntry) int {
		return priority(a.Name()) - priority(b.Name())
	})
	sent := 0
	for _, entry := range entries {
		if ctx.Err() != nil || sent == 12 {
			return
		}
		if !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil || acknowledged[entry.Name()].Equal(info.ModTime()) {
			continue
		}
		record, err := trafficwatch.ReadUpload(root, entry.Name(), identity.EnrolledAt, now)
		if err != nil {
			log.Print("Skipping an invalid traffic evidence handoff record")
		} else if record != nil {
			sent++
			record.AgentId = identity.AgentID
			request := connect.NewRequest(record)
			c.authorize(request.Header())
			callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			response, err := c.metrics.SubmitTrafficEvidence(callCtx, request)
			cancel()
			if connect.CodeOf(err) == connect.CodeInvalidArgument {
				log.Print("Panel rejected a traffic evidence record")
			} else if err != nil || !response.Msg.Accepted {
				return
			}
		}
		acknowledged[entry.Name()] = info.ModTime()
	}
}
