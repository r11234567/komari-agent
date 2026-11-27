package hostops

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const RootExecutionApprovalFeature = "root-execution-approval=v1"

func HostSupportsRootExecutionApproval(m *Manifest) bool {
	if m == nil || TrustedPath(m.HostTool) != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.HostTool, "version")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	output, err := cmd.Output()
	return err == nil && slices.Contains(strings.Fields(string(output)), RootExecutionApprovalFeature)
}
