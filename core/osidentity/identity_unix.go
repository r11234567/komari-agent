//go:build !windows

package osidentity

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

func (i *Identity) Configure(cmd *exec.Cmd, directory string) error {
	uid, err := strconv.ParseUint(i.User.Uid, 10, 32)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(i.User.Gid, 10, 32)
	if err != nil {
		return err
	}
	cmd.Env = i.Environment()
	cmd.Dir = directory
	if cmd.Dir == "" {
		cmd.Dir = i.User.HomeDir
	}
	if os.Geteuid() == 0 {
		groupIDs, err := i.User.GroupIds()
		if err != nil {
			return err
		}
		groups := make([]uint32, 0, len(groupIDs))
		for _, id := range groupIDs {
			g, err := strconv.ParseUint(id, 10, 32)
			if err != nil {
				return err
			}
			groups = append(groups, uint32(g))
		}
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}
	}
	return nil
}
