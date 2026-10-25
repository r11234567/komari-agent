//go:build linux

package hostcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	flags "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/statelock"
	"github.com/komari-monitor/komari-agent/rescue"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type fileBackup struct {
	Path   string `json:"path"`
	Backup string `json:"backup"`
	Mode   uint32 `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Exists bool   `json:"exists"`
}
type ownership struct {
	Path string `json:"path"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	Mode uint32 `json:"mode"`
}
type hostJournal struct {
	Version            int          `json:"version"`
	Manifest           string       `json:"manifest"`
	ID                 string       `json:"operation_id"`
	Phase              string       `json:"phase"`
	Operator           string       `json:"operator"`
	Revision           []byte       `json:"revision"`
	Operation          []byte       `json:"operation"`
	Receipt            []byte       `json:"receipt,omitempty"`
	SupersededReceipts [][]byte     `json:"superseded_receipts,omitempty"`
	Backups            []fileBackup `json:"backups"`
	Ownership          []ownership  `json:"ownership"`
	RecoveryOwnership  []ownership  `json:"recovery_ownership,omitempty"`
	Error              string       `json:"error,omitempty"`
	PreviousMode       int32        `json:"previous_mode"`
	PreviousUID        int          `json:"previous_uid"`
	PreviousHelper     bool         `json:"previous_helper"`
	FenceStage         string       `json:"fence_stage,omitempty"`
	dir                string
}

// This journal schema is independent from the wire/installation protocol. Older
// development journals lack ownership metadata and must never be guessed at.
const hostJournalVersion = 3

// Legacy installations can keep a retired Agent ELF beside their state. Copy
// bounded files as streams rather than treating every file as a small JSON blob.
const (
	maxStateFileBytes = int64(256 << 20)
	maxStateTreeBytes = int64(512 << 20)
	maxStateEntries   = 512
)

type stateFenceBudget struct {
	entries int
	bytes   int64
}

func (j *hostJournal) prepareRestorationReceipt() error {
	if len(j.Receipt) != 0 {
		var r hostv1.ReportHostOperationRequest
		if err := proto.Unmarshal(j.Receipt, &r); err != nil {
			return err
		}
		if r.Phase != hostv1.HostOperationPhase_HOST_OPERATION_PHASE_RESTORED {
			j.SupersededReceipts = append(j.SupersededReceipts, j.Receipt)
			j.Receipt = nil
		}
	}
	return j.save()
}

func (j *hostJournal) save() error {
	return hostops.WriteJSON(filepath.Join(j.dir, "transaction.json"), j, 0o600)
}
func journalDir(m *hostops.Manifest) string {
	return filepath.Join("/var/lib/komari-host", m.ServiceName)
}
func profilePath(m *hostops.Manifest) string {
	return filepath.Join("/etc/systemd/system", m.ServiceName+".service.d/95-komari-host-profile.conf")
}
func bootstrapPath(m *hostops.Manifest) string {
	return filepath.Join(filepath.Dir(m.Executable), "host-bootstrap.json")
}
func helperUnit(m *hostops.Manifest) string { return m.ServiceName + "-rescue.service" }
func helperBinary(m *hostops.Manifest) string {
	return filepath.Join(filepath.Dir(m.HostTool), "komari-agent-rescue")
}
func helperConfig(m *hostops.Manifest) string {
	return filepath.Join(filepath.Dir(m.HostTool), "rescue.json")
}
func helperUnitPath(m *hostops.Manifest) string {
	return filepath.Join("/etc/systemd/system", helperUnit(m))
}

func (j *hostJournal) backup(path string) error {
	for _, b := range j.Backups {
		if b.Path == path {
			return nil
		}
	}
	b := fileBackup{Path: path, Backup: filepath.Join(j.dir, fmt.Sprintf("backup-%d", len(j.Backups)))}
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		j.Backups = append(j.Backups, b)
		return j.save()
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 256<<20 {
		return errors.New("unsafe transaction backup file")
	}
	if err = hostops.TrustedPath(path); err != nil {
		return err
	}
	b.Exists = true
	b.Mode = uint32(st.Mode().Perm())
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot preserve backup ownership")
	}
	b.UID, b.GID = int(stat.Uid), int(stat.Gid)
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(b.Backup, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(output, input)
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	j.Backups = append(j.Backups, b)
	return j.save()
}

// A stopped daemon's files are copied to fresh root inodes before a root
// daemon uses them. Merely chowning leaves pre-existing writable FDs usable.
// Directory traversal is bounded and never follows a link or crosses a mount.
func (j *hostJournal) seal(path string, owner int, device uint64, depth int, recovery bool, budget *stateFenceBudget) error {
	if depth > 8 {
		return fmt.Errorf("state tree exceeds depth limit at %q", path)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	sys := st.Sys().(*syscall.Stat_t)
	if uint64(sys.Dev) != device || (int(sys.Uid) != owner && sys.Uid != 0) || (!st.IsDir() && (!st.Mode().IsRegular() || sys.Nlink != 1)) {
		return fmt.Errorf("state tree contains an unexpected owner, mount, link or special file at %q", path)
	}
	budget.entries++
	if budget.entries > maxStateEntries {
		return fmt.Errorf("state tree exceeds entry limit at %q", path)
	}
	remaining := min(maxStateFileBytes, maxStateTreeBytes-budget.bytes)
	// Reject an unsupported file before changing its ownership or mode. A
	// partially fenced tree can still restore metadata without recopying it.
	if !st.IsDir() && st.Size() > remaining {
		return fmt.Errorf("state file %q is %d bytes; remaining migration limit is %d bytes", path, st.Size(), remaining)
	}
	entries := &j.Ownership
	if recovery {
		entries = &j.RecoveryOwnership
	}
	known := false
	for _, e := range *entries {
		known = known || e.Path == path
	}
	if !known {
		if len(*entries) >= maxStateEntries {
			return errors.New("state tree exceeds reviewed migration limit")
		}
		*entries = append(*entries, ownership{Path: path, UID: int(sys.Uid), GID: int(sys.Gid), Mode: uint32(st.Mode().Perm())})
	}
	if err = j.save(); err != nil {
		return err
	}
	if err = f.Chown(0, 0); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if st.IsDir() {
		mode = 0o700
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if st.IsDir() {
		entries, err := f.ReadDir(maxStateEntries + 1)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if len(entries) > maxStateEntries {
			return fmt.Errorf("state directory %q has too many entries", path)
		}
		for _, entry := range entries {
			if err = j.seal(filepath.Join(path, entry.Name()), owner, device, depth+1, recovery, budget); err != nil {
				return err
			}
		}
		return f.Sync()
	}
	n, err := copySealedStateFile(path, f, remaining)
	if err != nil {
		return err
	}
	budget.bytes += n
	return nil
}

func copySealedStateFile(path string, input io.Reader, limit int64) (int64, error) {
	output, err := os.CreateTemp(filepath.Dir(path), ".komari-state-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(output.Name())
	defer output.Close()
	if err = output.Chmod(0o600); err != nil {
		return 0, err
	}
	n, err := io.Copy(output, io.LimitReader(input, limit+1))
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, fmt.Errorf("state file %q grew beyond migration limit of %d bytes", path, limit)
	}
	if err = output.Sync(); err != nil {
		return n, err
	}
	if err = output.Close(); err != nil {
		return n, err
	}
	if err = os.Rename(output.Name(), path); err != nil {
		return n, err
	}
	return n, statelock.SyncDirectory(filepath.Dir(path))
}

func (j *hostJournal) fenceStateDirectories(dirs []string, owner int, recovery bool) error {
	if recovery && j.FenceStage == "sealing" {
		// The original daemon was stopped and no target profile was published.
		// Restore the recorded metadata directly: repeating a failed copy can
		// fail on the same size/disk limit and strand the original service.
		return nil
	}
	if !recovery {
		j.FenceStage = "sealing"
		if err := j.save(); err != nil {
			return err
		}
	}
	budget := &stateFenceBudget{}
	for _, dir := range dirs {
		st, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !st.IsDir() {
			return fmt.Errorf("state root %q is not a directory", dir)
		}
		if err = j.seal(dir, owner, uint64(st.Sys().(*syscall.Stat_t).Dev), 0, recovery, budget); err != nil {
			return err
		}
	}
	return nil
}
func stateDirectories(m *hostops.Manifest) ([]string, error) {
	var dirs []string
	for _, p := range []string{m.CredentialsFile, m.RuntimeStateFile, m.PrivilegedStateFile, m.ReplayStateFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, errors.New("state paths must be absolute and clean")
		}
		dir := filepath.Dir(p)
		if dir == "/" || dir == "/etc" || dir == "/var" || dir == "/var/lib" || dir == "/opt" || dir == "/usr" {
			return nil, errors.New("state requires a dedicated directory")
		}
		found := false
		for _, existing := range dirs {
			if dir == existing {
				found = true
			} else if strings.HasPrefix(dir, existing+"/") || strings.HasPrefix(existing, dir+"/") {
				return nil, errors.New("nested state roots require reviewed migration")
			}
		}
		if !found {
			if err := hostops.TrustedPath(filepath.Dir(dir)); err != nil {
				return nil, fmt.Errorf("state parent must be root protected: %w", err)
			}
			dirs = append(dirs, dir)
		}
	}
	return dirs, nil
}

func validateActions(m *hostops.Manifest, p *hostops.Policy, t *hostops.Trust, r *configv1.PrivilegedRevision, o serviceObservation) error {
	a := r.Authorization
	seen := map[hostv1.HostAction]bool{}
	for _, action := range a.Actions {
		seen[action] = true
	}
	target := int32(a.TargetPrivilegeMode)
	if target != 1 && target != 2 {
		return errors.New("only Linux root/non-root profiles are supported")
	}
	current := int32(2)
	if o.User == "" || o.User == "root" {
		current = 1
	}
	if current != p.PrivilegeMode {
		return errors.New("actual systemd user differs from protected policy; diagnose before applying")
	}
	if seen[1] != (current != target) {
		return errors.New("identity action does not match actual source/target diff")
	}
	settings := privileged.SettingsFromProto(r.Privileged)
	if settings.RemoteControlEnabled && (p.ForceDenyRemoteControl || !p.AllowRemoteControl) || settings.WebSSHEnabled && !p.AllowWebSSH || settings.ExecutionEnabled && !p.AllowExecution || settings.EnableGPU && !p.AllowGPU || settings.RescueHelperEnabled && (p.ForceDenyRescueHelper || !p.AllowRescueHelper && !seen[2]) {
		return errors.New("approved configuration exceeds protected local ceilings")
	}
	if seen[2] && len(t.ReleaseKeys) == 0 {
		return errors.New("pin an independently verified release signing key before installing rescue")
	}
	if settings.RescueHelperEnabled && settings.RemoteControlEnabled {
		return errors.New("rescue and ordinary remote control must remain mutually exclusive")
	}
	if seen[2] != (settings.RescueHelperEnabled && !p.HelperInstalled) || seen[3] != (!settings.RescueHelperEnabled && p.HelperInstalled) {
		return errors.New("helper actions do not match installed/desired state")
	}
	if len(a.Actions) == 0 {
		return errors.New("no host actions: this revision must be applied by the daemon")
	}
	if t.ServiceUser == "root" {
		return errors.New("original non-root service identity missing")
	}
	return nil
}

func apply(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(out)
	manifest := fs.String("manifest", "", "installed service manifest (defaults beside host binary)")
	revision := fs.Uint64("revision", 0, "exact approved revision")
	artifact := fs.String("helper-artifact", "", "administrator-staged rescue ELF (only for helper install)")
	release := fs.String("release-manifest", "", "publisher-signed helper release manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *revision == 0 || fs.NArg() != 0 {
		return errors.New("--revision N is required; nonce is never a CLI argument")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	unlock, err := acquireHostLock()
	if err != nil {
		return err
	}
	defer unlock()
	m, err := resolveManifest(*manifest)
	if err != nil {
		return err
	}
	if err = rejectPendingSoftwareUpgrade(m); err != nil {
		return err
	}
	p, err := hostops.ReadPolicy(m)
	if err != nil {
		return err
	}
	t, err := hostops.ReadTrust(m)
	if err != nil {
		return err
	}
	dir := journalDir(m)
	if err = ensureTrustedDir(dir); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0o700); err != nil {
		return err
	}
	journalPath := filepath.Join(dir, "transaction.json")
	if _, err = os.Lstat(journalPath); !os.IsNotExist(err) {
		return fmt.Errorf("transaction journal exists; reconcile with %s or recover with %s before starting another operation", hostRecoveryCommand(m, "resume"), hostRecoveryCommand(m, "restore"))
	}
	panel, err := newPanel(m, t)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	r, err := panel.current(ctx)
	if err != nil {
		return err
	}
	if r.Revision != *revision || r.State != configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_NEEDS_MANUAL_AUTHORIZATION {
		return errors.New("requested revision is not the current approved host task")
	}
	o, err := observe(m.ServiceName)
	if err != nil {
		return err
	}
	if err = validateActions(m, p, t, r, o); err != nil {
		return err
	}
	previousUID := 0
	if p.PrivilegeMode == 2 {
		account, e := user.Lookup(o.User)
		if e != nil {
			return fmt.Errorf("resolve original systemd identity: %w", e)
		}
		previousUID, err = strconv.Atoi(account.Uid)
		if err != nil {
			return err
		}
	}
	dirs, err := stateDirectories(m)
	if err != nil {
		return err
	}
	workingDir := o.WorkingDirectory
	if workingDir == "" {
		workingDir = "/"
	}
	if !filepath.IsAbs(workingDir) || filepath.Clean(workingDir) != workingDir || strings.ContainsAny(workingDir, "\n\r%") {
		return errors.New("service WorkingDirectory must be a literal absolute path")
	}
	sealedWorkingDir := false
	for _, stateDir := range dirs {
		sealedWorkingDir = sealedWorkingDir || stateDir == workingDir
	}
	if !sealedWorkingDir {
		if err = hostops.TrustedPath(workingDir); err != nil {
			return fmt.Errorf("WorkingDirectory must be a sealed state root or administrator-owned directory: %w", err)
		}
	}
	bootstrap, err := captureBootstrap(m, o, t)
	if err != nil {
		return err
	}
	installRescue := false
	for _, action := range r.Authorization.Actions {
		installRescue = installRescue || action == hostv1.HostAction_HOST_ACTION_INSTALL_RESCUE_HELPER
	}
	if (*artifact == "") != (*release == "") || !installRescue && (*artifact != "" || *release != "") {
		return errors.New("--helper-artifact and --release-manifest must be supplied together for a rescue install")
	}
	fmt.Fprintf(out, "service=%s actual_user=%s main_pid=%s policy_mode=%d target_mode=%d actions=%v\n", m.ServiceName, o.User, o.MainPID, p.PrivilegeMode, r.Authorization.TargetPrivilegeMode, r.Authorization.Actions)
	if installRescue {
		fmt.Fprintln(out, "This task will install and authorize a separate root rescue service. Local PAM authentication authorizes this installation; the Agent identity follows the approved target.")
		if *artifact == "" {
			fmt.Fprintf(out, "After authentication, Host will fetch and verify publisher-signed rescue release %s if it is not already cached.\n", ReleaseVersion)
		}
	}
	operator, err := authenticate()
	if err != nil {
		return err
	}
	var helper []byte
	var helperVersion string
	if installRescue {
		helper, helperVersion, err = prepareHelper(ctx, m, t, *artifact, *release, ReleaseVersion, newReleaseClient(), out)
		if err != nil {
			return fmt.Errorf("rescue preparation failed; original service was not stopped: %w", err)
		}
		fmt.Fprintf(out, "verified_helper_release=%s\n", helperVersion)
	}
	// Authentication may have taken minutes. Re-read and compare the full
	// authorization before claiming a lease or modifying any OS state.
	current, err := panel.current(ctx)
	if err != nil {
		return err
	}
	if !proto.Equal(current.Authorization, r.Authorization) || current.State != r.State {
		return errors.New("approval changed during local authentication")
	}
	r = current
	j := &hostJournal{Version: hostJournalVersion, Manifest: m.ManifestPath, ID: uuid.NewString(), Phase: "claiming", Operator: operator, PreviousMode: p.PrivilegeMode, PreviousUID: previousUID, PreviousHelper: p.HelperInstalled, dir: dir}
	j.Revision, err = proto.Marshal(r)
	if err != nil {
		return err
	}
	if err = j.save(); err != nil {
		return err
	}
	response, err := panel.host.PrepareHostOperation(ctx, auth(panel, &hostv1.PrepareHostOperationRequest{AgentId: t.AgentID, OperationId: j.ID, Revision: r.Revision, ApprovalGeneration: r.ApprovalGeneration, ConfigHash: r.ConfigHash, Nonce: r.Authorization.Nonce}))
	if err != nil {
		return fmt.Errorf("claim pending; resume operation %s: %w", j.ID, err)
	}
	op := response.Msg.Operation
	if err = hostops.VerifyOperation(t, op, r.Authorization, j.ID); err != nil {
		return err
	}
	if op.Phase != 1 {
		return errors.New("new operation has unexpected phase")
	}
	j.Operation, err = proto.Marshal(op)
	if err != nil {
		return err
	}
	j.Phase = "prepared"
	if err = j.save(); err != nil {
		return err
	}
	if err = j.report(ctx, panel, hostv1.HostOperationPhase_HOST_OPERATION_PHASE_APPLYING, ""); err != nil {
		return err
	}
	for _, path := range []string{profilePath(m), bootstrapPath(m), m.HostPolicyFile, hostops.AppliedPath(m), helperBinary(m), helperConfig(m), helperUnitPath(m)} {
		if err = j.backup(path); err != nil {
			return err
		}
	}
	j.Phase = "mutating"
	if err = j.save(); err != nil {
		return err
	}
	if err = executeTransaction(ctx, m, p, t, r, j, dirs, bootstrap, helper, helperVersion, workingDir); err != nil {
		j.Error = err.Error()
		_ = j.save()
		if restoreErr := restoreTransaction(m, j); restoreErr != nil {
			return fmt.Errorf("apply failed: %v; restoration also failed: %w; journal=%s", err, restoreErr, journalPath)
		}
		// Restoration does not depend on the expired/superseded execution grant.
		// Give its receipt a fresh bounded deadline and never hide a lost ACK.
		recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer recoveryCancel()
		if reportErr := j.reportRestoration(recoveryCtx, panel, err.Error()); reportErr != nil {
			return fmt.Errorf("apply failed: %v; original service restored; recovery receipt pending: %w; run %s", err, reportErr, hostRecoveryCommand(m, "restore"))
		}
		if archiveErr := archiveJournal(j); archiveErr != nil {
			return fmt.Errorf("apply failed: %v; original service restored and panel confirmed recovery; archive pending: %w; run %s", err, archiveErr, hostRecoveryCommand(m, "restore"))
		}
		return fmt.Errorf("apply failed; original service restored, recovery receipt accepted and transaction archived; save and confirm a new revision: %w", err)
	}
	j.Phase = "local_applied"
	if err = j.save(); err != nil {
		return err
	}
	if err = j.report(ctx, panel, hostv1.HostOperationPhase_HOST_OPERATION_PHASE_LOCAL_APPLIED, ""); err != nil {
		fmt.Fprintf(out, "Local OS changes verified; control-plane acknowledgement pending. Retry %s before the execution lease expires.\n", hostRecoveryCommand(m, "resume"))
		return err
	}
	return finishHost(ctx, m, panel, j, out)
}

func executeTransaction(ctx context.Context, m *hostops.Manifest, p *hostops.Policy, t *hostops.Trust, r *configv1.PrivilegedRevision, j *hostJournal, dirs []string, bootstrap *flags.Config, helper []byte, helperVersion, workingDir string) error {
	if _, err := systemctl("stop", m.ServiceName); err != nil {
		return err
	}
	u, err := user.Lookup(t.ServiceUser)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	if err = j.fenceStateDirectories(dirs, uid, false); err != nil {
		return err
	}
	// Check the live lease after stopping/fencing the old daemon, immediately
	// before writing a profile that can increase host authority.
	panel, err := newPanel(m, t)
	if err != nil {
		return err
	}
	current, err := panel.current(ctx)
	if err != nil {
		return err
	}
	if !proto.Equal(current.Authorization, r.Authorization) || current.State != configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_APPLYING {
		return errors.New("approval superseded before profile change")
	}
	op, err := panel.get(ctx, j.ID)
	if err != nil {
		return err
	}
	if err = hostops.VerifyOperation(t, op, r.Authorization, j.ID); err != nil {
		return err
	}
	if op.Phase != 2 {
		return errors.New("host operation is not applying")
	}
	settings := privileged.SettingsFromProto(r.Privileged)
	// Persist this boundary before changing any protected profile or starting
	// a target daemon. Old journals without the marker always fence on restore.
	j.FenceStage = "profile"
	if err = j.save(); err != nil {
		return err
	}
	// Local ceilings remain independent of panel targets, so a later approved
	// same-identity change can re-enable a capability. Daemon startup verifies
	// historical snapshots against the root-pinned signature before using them.
	p.PrivilegeMode = int32(settings.RequiredPrivilegeMode)
	p.HostRevision = r.Revision
	p.HostSettings = &settings
	// Only this signed action, after fresh PAM, can grant first-install consent.
	for _, action := range r.Authorization.Actions {
		if action == hostv1.HostAction_HOST_ACTION_INSTALL_RESCUE_HELPER {
			p.AllowRescueHelper = true
		}
	}
	p.HelperInstalled = settings.RescueHelperEnabled
	p.HelperAuthorized = settings.RescueHelperEnabled
	if err = hostops.WriteJSON(m.HostPolicyFile, p, 0o644); err != nil {
		return err
	}
	bootstrap.Endpoint = t.Endpoint
	bootstrap.ServiceManifestFile = m.ManifestPath
	bootstrap.CredentialsFile = m.CredentialsFile
	bootstrap.RuntimeStateFile = m.RuntimeStateFile
	bootstrap.PrivilegedStateFile = m.PrivilegedStateFile
	bootstrap.ReplayStateFile = m.ReplayStateFile
	bootstrap.ConfigFile = ""
	bootstrap.HostProc = ""
	bootstrap.IgnoreUnsafeCert = false
	// A reviewed transaction may release a historical argv restriction only
	// after the administrator has explicitly released its protected policy deny.
	bootstrap.DisableRemoteControl = p.ForceDenyRemoteControl
	bootstrap.DisableAutoUpdate = true
	bootstrap.Token = ""
	bootstrap.AutoDiscoveryKey = ""
	if err = hostops.WriteJSON(bootstrapPath(m), bootstrap, 0o600); err != nil {
		return err
	}
	if err = ensureTrustedDir(filepath.Dir(profilePath(m))); err != nil {
		return err
	}
	unit := "[Service]\nUser=" + t.ServiceUser + "\nGroup=" + u.Gid + "\nSupplementaryGroups=\nExecStart=\nExecStart=" + unitQuote(m.Executable) + " --service-manifest " + unitQuote(m.ManifestPath) + " --config " + unitQuote(bootstrapPath(m)) + "\nEnvironment=\nEnvironmentFile=\nPassEnvironment=\nWorkingDirectory=" + workingDir + "\nNoNewPrivileges=true\nCapabilityBoundingSet=\nCapabilityBoundingSet=CAP_NET_RAW\nAmbientCapabilities=\nAmbientCapabilities=CAP_NET_RAW\n"
	if p.PrivilegeMode == 1 {
		unit = "[Service]\nUser=root\nGroup=root\nSupplementaryGroups=\nExecStart=\nExecStart=" + unitQuote(m.Executable) + " --service-manifest " + unitQuote(m.ManifestPath) + " --config " + unitQuote(bootstrapPath(m)) + "\nEnvironment=\nEnvironmentFile=\nPassEnvironment=\nWorkingDirectory=" + workingDir + "\nNoNewPrivileges=false\nCapabilityBoundingSet=~\nAmbientCapabilities=\n"
	}
	if err = hostops.AtomicWrite(profilePath(m), []byte(unit), 0o644); err != nil {
		return err
	}
	if settings.RescueHelperEnabled && len(helper) > 0 {
		if err = installHelper(m, t, bootstrap, helper, helperVersion); err != nil {
			return err
		}
	}
	if !settings.RescueHelperEnabled {
		if _, err = os.Stat(helperUnitPath(m)); err == nil {
			if _, err = systemctl("stop", helperUnit(m)); err != nil {
				return err
			}
			if _, err = systemctl("disable", helperUnit(m)); err != nil {
				return err
			}
			for _, path := range []string{helperUnitPath(m), helperBinary(m), helperConfig(m)} {
				if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		}
	}
	if p.PrivilegeMode == 2 {
		if err = changeOwnership(j.Ownership, uid, gid, false); err != nil {
			return err
		}
		if err = os.Chown(bootstrapPath(m), 0, gid); err != nil {
			return err
		}
		if err = os.Chmod(bootstrapPath(m), 0o640); err != nil {
			return err
		}
	}
	if _, err = systemctl("daemon-reload"); err != nil {
		return err
	}
	if settings.RescueHelperEnabled {
		if _, err = systemctl("enable", helperUnit(m)); err != nil {
			return err
		}
		if err = restartReviewedService(helperUnit(m)); err != nil {
			return err
		}
		if err = verifyService(m.ServiceName+"-rescue", 0, 1); err != nil {
			return err
		}
	}
	if err = restartReviewedService(m.ServiceName); err != nil {
		return err
	}
	actualUID := uid
	if p.PrivilegeMode == 1 {
		actualUID = 0
	}
	if err = verifyService(m.ServiceName, actualUID, p.PrivilegeMode); err != nil {
		return err
	}
	if settings.RescueHelperEnabled {
		if err = waitHelper(m); err != nil {
			return err
		}
	}
	return hostops.WriteJSON(hostops.AppliedPath(m), hostops.AppliedRecord{Version: 2, Revision: j.Revision, Operation: j.Operation}, 0o644)
}

func changeOwnership(entries []ownership, uid, gid int, original bool) error {
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if original {
			uid = e.UID
			gid = e.GID
		}
		st, err := os.Lstat(e.Path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("state path became a symlink during restoration")
		}
		if err = os.Chown(e.Path, uid, gid); err != nil {
			return err
		}
		mode := os.FileMode(e.Mode)
		if !original {
			mode = 0o600
			if st.IsDir() {
				mode = 0o700
			}
		}
		if err = os.Chmod(e.Path, mode); err != nil {
			return err
		}
	}
	return nil
}
func restoreTransaction(m *hostops.Manifest, j *hostJournal) error {
	// Persist intent before the first OS mutation. A crash during restoration
	// must never be resumed as if the target profile were still locally applied.
	j.Phase = "restoring"
	if err := j.save(); err != nil {
		return err
	}
	if _, err := systemctl("stop", m.ServiceName); err != nil {
		return err
	}
	if _, err := os.Stat(helperUnitPath(m)); err == nil {
		if _, err = systemctl("stop", helperUnit(m)); err != nil {
			return err
		}
		_, _ = systemctl("disable", helperUnit(m))
	}
	// The target daemon may have created/replaced files after the first fence.
	// Fence again before restoring access; original metadata stays immutable in
	// Ownership, while recovery captures are kept separately across interruptions.
	dirs, err := stateDirectories(m)
	if err != nil {
		return err
	}
	t, err := hostops.ReadTrust(m)
	if err != nil {
		return err
	}
	u, err := user.Lookup(t.ServiceUser)
	if err != nil {
		return err
	}
	owner, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	if err = j.fenceStateDirectories(dirs, owner, true); err != nil {
		return err
	}
	for i := len(j.Backups) - 1; i >= 0; i-- {
		b := j.Backups[i]
		if !b.Exists {
			if err := os.Remove(b.Path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		data, err := os.ReadFile(b.Backup)
		if err != nil {
			return err
		}
		if err = hostops.AtomicWriteOwned(b.Path, data, os.FileMode(b.Mode), b.UID, b.GID); err != nil {
			return err
		}
	}
	if err := restoreStateOwnership(j, dirs); err != nil {
		return err
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if j.PreviousHelper {
		if _, err := systemctl("enable", helperUnit(m)); err != nil {
			return err
		}
		if err := restartReviewedService(helperUnit(m)); err != nil {
			return err
		}
	}
	if err := restartReviewedService(m.ServiceName); err != nil {
		return err
	}
	policy, err := hostops.ReadPolicy(m)
	if err != nil {
		return err
	}
	if policy.PrivilegeMode != j.PreviousMode {
		return errors.New("restored policy differs from recorded original identity")
	}
	if err = verifyService(m.ServiceName, j.PreviousUID, j.PreviousMode); err != nil {
		return err
	}
	j.Phase = "restored"
	return j.save()
}

func restoreStateOwnership(j *hostJournal, dirs []string) error {
	original := map[string]ownership{}
	for _, e := range j.Ownership {
		original[e.Path] = e
	}
	entries := append([]ownership(nil), j.Ownership...)
	for _, e := range j.RecoveryOwnership {
		if _, exists := original[e.Path]; exists {
			continue
		}
		for _, dir := range dirs {
			if e.Path != dir && !strings.HasPrefix(e.Path, dir+"/") {
				continue
			}
			if root, sealedOriginally := original[dir]; sealedOriginally {
				// A file created by the target daemon has no earlier metadata.
				// Give it the original state root's account and restrictive modes.
				e.UID, e.GID, e.Mode = root.UID, root.GID, 0o600
				st, err := os.Lstat(e.Path)
				if os.IsNotExist(err) {
					break
				}
				if err != nil {
					return err
				}
				if st.IsDir() {
					e.Mode = 0o700
				}
			}
			break
		}
		entries = append(entries, e)
	}
	return changeOwnership(entries, 0, 0, true)
}
func (j *hostJournal) report(ctx context.Context, p *panel, phase hostv1.HostOperationPhase, detail string) error {
	if len(j.Receipt) == 0 {
		msg := &hostv1.ReportHostOperationRequest{AgentId: p.trust.AgentID, OperationId: j.ID, ReceiptId: uuid.NewString(), Phase: phase, Error: detail, LocalAuthentication: "PAM:komari-host:authenticate+acct_mgmt", Operator: j.Operator}
		var err error
		j.Receipt, err = proto.Marshal(msg)
		if err != nil {
			return err
		}
		if err = j.save(); err != nil {
			return err
		}
	}
	var req hostv1.ReportHostOperationRequest
	if err := proto.Unmarshal(j.Receipt, &req); err != nil {
		return err
	}
	if req.Phase != phase {
		return errors.New("an earlier durable host receipt must be resolved before another phase")
	}
	resp, err := p.host.ReportHostOperation(ctx, auth(p, &req))
	if err != nil {
		return err
	}
	if !resp.Msg.Accepted {
		return errors.New("host receipt rejected")
	}
	j.Receipt = nil
	return j.save()
}

func (j *hostJournal) reportRestoration(ctx context.Context, p *panel, detail string) error {
	if err := j.prepareRestorationReceipt(); err != nil {
		return err
	}
	// Older hosts cleared an accepted restoration receipt but left the active
	// journal behind. A new receipt for that terminal operation is illegal.
	// Reconcile the signed operation instead, including after a lost archive ACK.
	op, err := p.get(ctx, j.ID)
	if err != nil {
		return err
	}
	if op.GetPhase() == hostv1.HostOperationPhase_HOST_OPERATION_PHASE_RESTORED {
		var original configv1.PrivilegedRevision
		if err = proto.Unmarshal(j.Revision, &original); err != nil {
			return err
		}
		if original.Authorization == nil {
			return errors.New("restoration journal has no original authorization")
		}
		if err = hostops.VerifyOperation(p.trust, op, original.Authorization, j.ID); err != nil {
			return fmt.Errorf("cannot verify the panel's existing restoration: %w", err)
		}
		if len(j.Receipt) != 0 {
			j.SupersededReceipts = append(j.SupersededReceipts, j.Receipt)
			j.Receipt = nil
		}
		return j.save()
	}
	return j.report(ctx, p, hostv1.HostOperationPhase_HOST_OPERATION_PHASE_RESTORED, detail)
}

func finishHost(ctx context.Context, m *hostops.Manifest, p *panel, j *hostJournal, out io.Writer) error {
	fmt.Fprintln(out, "Local service identity/profile verified; host result recorded. Waiting for the restarted daemon to load and acknowledge the revision.")
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			fmt.Fprintf(out, "Local changes complete; daemon acknowledgement pending. Run %s to reconcile. The panel applied revision has not been fabricated.\n", hostRecoveryCommand(m, "resume"))
			return nil
		case <-ticker.C:
			// Get current using the daemon API; the approval may now be expired,
			// which is acceptable for observing a completed operation, never a grant.
			resp, err := p.privileged.GetPrivilegedDelivery(ctx, auth(p, &configv1.GetPrivilegedDeliveryRequest{AgentId: p.trust.AgentID}))
			if err != nil {
				continue
			}
			var old configv1.PrivilegedRevision
			if err = proto.Unmarshal(j.Revision, &old); err != nil {
				return err
			}
			r := resp.Msg.Revision
			if err = hostops.VerifySignedRevision(p.trust, r); err != nil {
				return err
			}
			if r.GetRevision() != old.Revision || r.GetApprovalGeneration() != old.ApprovalGeneration {
				return fmt.Errorf("host result belongs to a superseded target; run %s before saving and confirming another revision", hostRecoveryCommand(m, "restore"))
			}
			if r.GetState() == configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED {
				j.Phase = "completed"
				if err = j.save(); err != nil {
					return err
				}
				fmt.Fprintln(out, "Daemon acknowledgement received; panel confirms this revision is applied.")
				return archiveJournal(j)
			}
		}
	}
}
func archiveJournal(j *hostJournal) error {
	// Archive the whole transaction directory, including backups, then leave a
	// fresh per-service directory for the next operation. Never discard history.
	if err := os.Rename(j.dir, j.dir+"-"+j.ID); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(j.dir))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func hostRecoveryCommand(m *hostops.Manifest, action string) string {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	return "sudo " + quote(m.HostTool) + " " + action + " --manifest " + quote(m.ManifestPath)
}

func resolveJournalManifest(m *hostops.Manifest, j *hostJournal) (*hostops.Manifest, error) {
	if j.Version != hostJournalVersion {
		return nil, fmt.Errorf("unsupported transaction journal version %d", j.Version)
	}
	if j.ID == "" || j.Manifest == "" {
		return nil, errors.New("transaction journal is missing its operation ID or manifest")
	}
	// Installation writes a registry manifest and a separate adjacent copy.
	// Resume may discover either one. Revalidate the original trusted manifest
	// and compare every resolved field before accepting an alternate path.
	original, err := resolveManifest(j.Manifest)
	if err != nil {
		return nil, fmt.Errorf("cannot validate journal manifest %s: %w", j.Manifest, err)
	}
	comparison := *original
	comparison.ManifestPath = m.ManifestPath
	if comparison != *m {
		return nil, fmt.Errorf("journal installation differs from selected manifest; use the original installation: %s", hostRecoveryCommand(original, "resume"))
	}
	return original, nil
}

func resume(args []string, out io.Writer, restore bool) error {
	fs := flag.NewFlagSet("resume", flag.ContinueOnError)
	fs.SetOutput(out)
	manifest := fs.String("manifest", "", "installed service manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	unlock, err := acquireHostLock()
	if err != nil {
		return err
	}
	defer unlock()
	m, err := resolveManifest(*manifest)
	if err != nil {
		return err
	}
	var j hostJournal
	j.dir = journalDir(m)
	if err = hostops.ReadJSON(filepath.Join(j.dir, "transaction.json"), &j, true); err != nil {
		return err
	}
	m, err = resolveJournalManifest(m, &j)
	if err != nil {
		return err
	}
	if j.Phase == "completed" || j.Phase == "unclaimed" {
		return archiveJournal(&j)
	}
	switch j.Phase {
	case "claiming", "prepared", "mutating", "local_applied", "restoring", "restored":
	default:
		return errors.New("unknown journal phase; no service changes made")
	}
	_, err = authenticate()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if j.Phase == "claiming" && len(j.Operation) == 0 && len(j.Backups) == 0 && len(j.Ownership) == 0 {
		t, e := hostops.ReadTrust(m)
		if e != nil {
			return e
		}
		p, e := newPanel(m, t)
		if e != nil {
			return e
		}
		_, e = p.get(ctx, j.ID)
		if connect.CodeOf(e) == connect.CodeNotFound {
			j.Phase = "unclaimed"
			if err = j.save(); err != nil {
				return err
			}
			fmt.Fprintln(out, "No host operation was claimed and no local files changed; archived the unstarted transaction.")
			return archiveJournal(&j)
		}
		if e != nil {
			return fmt.Errorf("claim outcome unknown; no local changes made: %w", e)
		}
	}
	if restore || j.Phase != "local_applied" {
		if j.Phase != "restored" {
			if j.Phase == "claiming" || j.Phase == "prepared" {
				// Mutation begins only after the durable mutating marker.
				j.Phase = "restored"
				if err = j.save(); err != nil {
					return err
				}
			} else {
				if err = restoreTransaction(m, &j); err != nil {
					return err
				}
			}
		}
		// A failed/superseded/expired grant is never resumed by increasing
		// authority. Recovery restores locally even if the panel is unavailable.
		t, e := hostops.ReadTrust(m)
		if e != nil {
			return fmt.Errorf("local restoration complete; cannot deliver receipt: %w", e)
		}
		p, e := newPanel(m, t)
		if e != nil {
			return fmt.Errorf("local restoration complete; cannot deliver receipt: %w", e)
		}
		if err = j.reportRestoration(ctx, p, "interrupted operation restored by local administrator"); err != nil {
			return fmt.Errorf("local restoration complete; recovery receipt pending: %w", err)
		}
		if err = archiveJournal(&j); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, "Original service restored and verified; recovery receipt accepted and transaction archived. Save a new revision before applying another change.")
		return err
	}
	t, err := hostops.ReadTrust(m)
	if err != nil {
		return err
	}
	p, err := newPanel(m, t)
	if err != nil {
		return err
	}
	var original configv1.PrivilegedRevision
	if err = proto.Unmarshal(j.Revision, &original); err != nil {
		return err
	}
	op, err := p.get(ctx, j.ID)
	if err != nil {
		return err
	}
	if err = hostops.VerifyOperation(t, op, original.Authorization, j.ID); err != nil {
		return fmt.Errorf("lease expired or invalid; run %s: %w", hostRecoveryCommand(m, "restore"), err)
	}
	if op.Phase == 3 {
		j.Receipt = nil
		if err = j.save(); err != nil {
			return err
		}
		return finishHost(ctx, m, p, &j, out)
	}
	current, err := p.current(ctx)
	if err != nil {
		return fmt.Errorf("cannot establish current unexpired authority; run %s to recover: %w", hostRecoveryCommand(m, "restore"), err)
	}
	if !proto.Equal(current.Authorization, original.Authorization) {
		return fmt.Errorf("approval superseded; run %s before another grant", hostRecoveryCommand(m, "restore"))
	}
	policy, err := hostops.ReadPolicy(m)
	if err != nil {
		return err
	}
	uid := 0
	if policy.PrivilegeMode == 2 {
		account, e := user.Lookup(t.ServiceUser)
		if e != nil {
			return e
		}
		uid, e = strconv.Atoi(account.Uid)
		if e != nil {
			return e
		}
	}
	if err = verifyService(m.ServiceName, uid, policy.PrivilegeMode); err != nil {
		return err
	}
	if policy.HelperInstalled {
		if err = waitHelper(m); err != nil {
			return err
		}
	}
	if op.Phase < 3 {
		if err = j.report(ctx, p, hostv1.HostOperationPhase_HOST_OPERATION_PHASE_LOCAL_APPLIED, ""); err != nil {
			return err
		}
	}
	return finishHost(ctx, m, p, &j, out)
}

// installHelper uses only a verified release and root-generated fixed config.
// The helper speaks signed RPC to the pinned panel; no daemon-to-root shell IPC.
func installHelper(m *hostops.Manifest, t *hostops.Trust, bootstrap *flags.Config, binary []byte, version string) error {
	if err := hostops.AtomicWrite(helperBinary(m), binary, 0o755); err != nil {
		return err
	}
	state := filepath.Join("/var/lib/komari-rescue", m.ServiceName)
	if err := ensureTrustedDir(state); err != nil {
		return err
	}
	if err := os.Chmod(state, 0o700); err != nil {
		return err
	}
	cfg := rescue.Config{Endpoint: t.Endpoint, AgentID: t.AgentID, Version: version, HostManifest: m.ManifestPath, CredentialsFile: m.CredentialsFile, InstanceIDPath: filepath.Join(state, "instance"), ReplayFile: filepath.Join(state, "replay.json"), CFAccessClientID: bootstrap.CFAccessClientID, CFAccessClientSecret: bootstrap.CFAccessClientSecret, Action: rescue.ActionConfig{AgentPath: m.Executable, ServiceName: m.ServiceName, ControlPlaneURL: t.Endpoint, IsolationStatePath: filepath.Join(state, "isolation.json")}}
	if err := hostops.WriteJSON(helperConfig(m), cfg, 0o600); err != nil {
		return err
	}
	unit := "[Unit]\nDescription=Komari bounded rescue helper\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nUser=root\nGroup=root\nExecStart=" + unitQuote(helperBinary(m)) + " --config " + unitQuote(helperConfig(m)) + "\nWorkingDirectory=/\nEnvironment=PATH=/usr/sbin:/usr/bin:/sbin:/bin\nNoNewPrivileges=false\nCapabilityBoundingSet=~\nRestart=on-failure\nRestartSec=5\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n"
	return hostops.AtomicWrite(helperUnitPath(m), []byte(unit), 0o644)
}
