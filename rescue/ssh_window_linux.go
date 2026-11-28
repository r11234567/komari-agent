//go:build linux

package rescue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	commonv1 "github.com/r11234567/komari-proto/gen/go/komari/common/v1"
	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const sshWindowV4Set = "komari_rescue_ssh_v4"
const sshWindowV6Set = "komari_rescue_ssh_v6"

// The local administrator names the table and chain that contain the rescue
// rules. The two sets are dedicated to this helper and start empty.
type sshWindowConfig struct {
	Backend   string `json:"backend,omitempty"`
	Table     string `json:"table"`
	Chain     string `json:"chain"`
	Interface string `json:"interface"`
	Port      uint32 `json:"port"`
	statePath string
}

type sshWindowGrant struct {
	ID        string     `json:"id"`
	Key       string     `json:"enrollment_key_id"`
	Source    netip.Addr `json:"source_ip"`
	Port      uint32     `json:"port"`
	CreatedAt time.Time  `json:"created_at"`
	StartedAt time.Time  `json:"started_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	ListenIP  string     `json:"listen_ip,omitempty"`
}

type sshWindowState struct {
	Current *sshWindowGrant `json:"current,omitempty"`
	Pending *sshWindowGrant `json:"pending,omitempty"`
}

func loadSSHWindowConfig(manifest *hostops.Manifest) (sshWindowConfig, error) {
	var config sshWindowConfig
	if manifest == nil {
		return config, errors.New("temporary SSH requires a locally configured rescue helper")
	}
	path := filepath.Join(filepath.Dir(manifest.HostPolicyFile), manifest.ServiceName+".temporary-ssh.json")
	if err := hostops.ReadJSON(path, &config, true); err != nil {
		return config, fmt.Errorf("read temporary SSH settings: %w", err)
	}
	validBackend := config.Backend == "" && sshNftIdentifier.MatchString(config.Table) && sshNftIdentifier.MatchString(config.Chain) ||
		config.Backend == sshWindowUFW && config.Table == "" && config.Chain == ""
	if !validBackend || config.Port == 0 || config.Port > 65535 || !validSSHWindowInterface(config.Interface) {
		return config, errors.New("invalid temporary SSH table, chain, interface or port")
	}
	config.statePath = strings.TrimSuffix(path, ".json") + "-state.json"
	return config, nil
}

func validSSHWindowInterface(s string) bool {
	return s != "" && len(s) <= 15 && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-')
	}) < 0
}

func (config sshWindowConfig) loadState() (sshWindowState, error) {
	var state sshWindowState
	err := hostops.ReadJSON(config.statePath, &state, true)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	return state, err
}

func (config sshWindowConfig) saveState(state sshWindowState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWrite(config.statePath, data, 0o600)
}

func (config sshWindowConfig) receipt(grant *sshWindowGrant, active bool) *rescuev1.TemporarySSHAccess {
	if grant == nil {
		return nil
	}
	receipt := &rescuev1.TemporarySSHAccess{
		Port: grant.Port, Granted: active, GrantedAt: timestamppb.New(grant.StartedAt),
		ExpiresAt: timestamppb.New(grant.ExpiresAt), SourceIp: grant.Source.String(), GrantId: grant.ID,
		ExpiryMechanism: rescuev1.ExpiryMechanism_EXPIRY_MECHANISM_NFTABLES_TIMEOUT,
	}
	if config.Backend == sshWindowUFW {
		receipt.ExpiryMechanism = rescuev1.ExpiryMechanism_EXPIRY_MECHANISM_IPSET_TIMEOUT
	}
	if active && grant.ListenIP != "" {
		receipt.SshdState = &rescuev1.SSHDaemonState{Running: true, Reachable: true,
			ListenAddresses: []string{grant.ListenIP}, ObservedListenPorts: []uint32{grant.Port}}
	}
	return receipt
}

func sshWindowStatus(ctx context.Context, manifest *hostops.Manifest, key string, status *rescuev1.RescueHelperStatus) {
	if manifest == nil || key == "" {
		return
	}
	status.SshWindowSupported = true
	status.SshEnrollmentKeyId = key
	config, err := loadSSHWindowConfig(manifest)
	if err != nil {
		code := "SSH_CONFIG_INVALID"
		if errors.Is(err, os.ErrNotExist) {
			code = "SSH_CONFIG_MISSING"
			_, failureErr := checkSSHWindowFirewall(ctx)
			var failure *sshWindowSetupError
			if errors.As(failureErr, &failure) {
				code, err = failure.code, failure
			} else {
				err = fmt.Errorf("%w; run komari-host setup-rescue-ssh --check on the node to see what setup needs", err)
			}
		}
		status.SshWindowError = sshWindowDiagnostic(code, err)
		return
	}
	sshAccessMu.Lock()
	defer sshAccessMu.Unlock()
	snapshot, err := config.inspect(ctx, true)
	if err != nil {
		code := "SSH_NFT_READ_FAILED"
		if errors.Is(err, errSSHWindowRules) {
			code = "SSH_NFT_RULES_INVALID"
		}
		if config.Backend == sshWindowUFW {
			code = "SSH_UFW_CHECK_FAILED"
		}
		status.SshWindowError = sshWindowDiagnostic(code, err)
		return
	}
	state, grant, err := config.reconcile(snapshot)
	if err != nil {
		status.SshWindowError = sshWindowDiagnostic("SSH_STATE_INVALID", err)
		return
	}
	status.SshAccessPort = config.Port
	if grant != nil && grant.Key == key {
		status.SshAccess = config.receipt(grant, true)
	} else if state.Current != nil && state.Current.Key == key {
		status.SshAccess = config.receipt(state.Current, false)
	}
}

func sshWindowDiagnostic(code string, err error) *commonv1.ErrorDetail {
	return &commonv1.ErrorDetail{Code: code, Message: strings.ToValidUTF8(truncateError(err.Error()), "")}
}

func executeSSHWindow(ctx context.Context, manifest *hostops.Manifest, session *rescuev1.RescueSession, mayGrant func() bool) (ActionResult, error) {
	if !isPrivileged() {
		return ActionResult{}, errors.New("temporary SSH requires a privileged rescue helper")
	}
	config, err := loadSSHWindowConfig(manifest)
	if err != nil {
		return ActionResult{}, err
	}
	if session.Action == rescuev1.RescueAction_RESCUE_ACTION_REVOKE_TEMPORARY_SSH_ACCESS {
		return config.revoke(ctx, session.GetSshWindow().GetEnrollmentKeyId(), session.GetSshWindow().GetPreviousGrantId())
	}
	return config.grant(ctx, session, temporarySSHDuration, mayGrant)
}

func revokeSSHWindowForEnrollment(ctx context.Context, manifest *hostops.Manifest, key string) error {
	if key == "" {
		return errors.New("temporary SSH revocation has no enrollment binding")
	}
	config, err := loadSSHWindowConfig(manifest)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err = config.revoke(ctx, key, "")
	return err
}

func checkSSHWindowIdentity(ctx context.Context, manifest *hostops.Manifest) {
	config, err := loadSSHWindowConfig(manifest)
	if err != nil {
		return
	}
	state, err := config.loadState()
	if err != nil {
		return
	}
	window := state.Pending
	if window == nil {
		window = state.Current
	}
	if window == nil || !time.Now().Before(window.ExpiresAt) {
		return
	}
	data, err := hostops.ReadCandidate(manifest.CredentialsFile)
	var identity credentials.Identity
	if errors.Is(err, os.ErrNotExist) ||
		err == nil && json.Unmarshal(data, &identity) == nil && identity.KeyID != "" &&
			(identity.KeyID != window.Key || identity.RefreshExpired(time.Now()) && !time.Now().Before(identity.AccessTokenExpiresAt)) {
		if err := revokeSSHWindowForEnrollment(ctx, manifest, window.Key); err != nil {
			log.Printf("revoke temporary SSH after local credential change: %v", err)
		}
	}
}

func (config sshWindowConfig) grant(ctx context.Context, session *rescuev1.RescueSession, duration time.Duration, mayGrant func() bool) (ActionResult, error) {
	source, err := netip.ParseAddr(session.GetSshWindow().GetSourceIp())
	if err != nil || !source.IsGlobalUnicast() || source.Is4In6() || source.Zone() != "" {
		return ActionResult{}, errors.New("temporary SSH requires a single source IPv4 or IPv6 address")
	}
	if session.GetSshPort() != config.Port || session.GetSshWindow().GetEnrollmentKeyId() == "" ||
		!validSSHGrantID(session.GetSessionId()) || session.GetCreatedAt() == nil || !session.GetCreatedAt().IsValid() {
		return ActionResult{}, errors.New("temporary SSH authorization does not match the node's configured port or enrollment")
	}
	sshAccessMu.Lock()
	defer sshAccessMu.Unlock()
	snapshot, err := config.inspect(ctx, true)
	if err != nil {
		return ActionResult{}, err
	}
	state, active, err := config.reconcile(snapshot)
	if err != nil {
		return ActionResult{}, err
	}
	if state.Current != nil {
		if state.Current.ID == session.GetSessionId() && active != nil {
			receipt := config.receipt(active, true)
			receipt.SshdState = inspectSSHWindowListener(ctx, config, source)
			return ActionResult{SSHAccess: receipt}, nil
		}
		if !session.GetCreatedAt().AsTime().After(state.Current.CreatedAt) {
			return ActionResult{}, errors.New("this temporary SSH authorization has already been used or superseded")
		}
	}
	previous := session.GetSshWindow().GetPreviousGrantId()
	if active != nil && (previous != active.ID || active.Key != session.GetSshWindow().GetEnrollmentKeyId()) ||
		active == nil && previous != "" {
		return ActionResult{}, errors.New("the temporary SSH window has changed")
	}
	listener := inspectSSHWindowListener(ctx, config, source)
	result := ActionResult{SSHAccess: &rescuev1.TemporarySSHAccess{
		Port: config.Port, SourceIp: source.String(), GrantId: session.GetSessionId(), SshdState: listener,
	}}
	if !listener.GetReachable() {
		return result, errors.New(listener.GetLimitation())
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if mayGrant != nil && !mayGrant() {
		return result, errors.New("temporary SSH authorization no longer matches the current enrollment")
	}
	now := time.Now().UTC()
	grant := &sshWindowGrant{
		ID: session.GetSessionId(), Key: session.GetSshWindow().GetEnrollmentKeyId(), Source: source, Port: config.Port,
		CreatedAt: session.GetCreatedAt().AsTime(), StartedAt: now, ExpiresAt: now.Add(duration), ListenIP: listener.ListenAddresses[0],
	}
	state.Pending = grant
	if err := config.saveState(state); err != nil {
		return result, err
	}
	applyErr := config.replaceKernelGrant(ctx, grant)
	verify, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	snapshot, err = config.inspect(verify, true)
	if err != nil {
		return result, errors.Join(applyErr, err)
	}
	_, active, err = config.reconcile(snapshot)
	if err != nil {
		return result, errors.Join(applyErr, err)
	}
	if active == nil || active.ID != grant.ID {
		return result, errors.Join(errors.New("temporary SSH rule and timeout were not confirmed"), applyErr)
	}
	result.SSHAccess = config.receipt(active, true)
	result.SSHAccess.SshdState = listener
	return result, nil
}

func validSSHGrantID(id string) bool {
	return len(id) == 32 && strings.IndexFunc(id, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) < 0
}

func (config sshWindowConfig) revoke(ctx context.Context, key, id string) (ActionResult, error) {
	sshAccessMu.Lock()
	defer sshAccessMu.Unlock()
	state, err := config.loadState()
	if err != nil || state.Current == nil && state.Pending == nil {
		return ActionResult{}, err
	}
	// Read the sets even if the administrator has removed the linking rules.
	snapshot, err := config.inspect(ctx, false)
	if err != nil {
		return ActionResult{}, err
	}
	state, active, err := config.reconcile(snapshot)
	if err != nil {
		return ActionResult{}, err
	}
	if active != nil && active.Key == key && (id == "" || id == active.ID) {
		applyErr := config.clearKernelGrant(ctx)
		verify, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if remaining, err := config.inspect(verify, false); err != nil || remaining != nil {
			return ActionResult{}, errors.Join(errors.New("temporary SSH removal was not confirmed"), applyErr, err)
		}
		logSSHWindow("revoked", config, active)
		return ActionResult{SSHAccess: config.receipt(active, false)}, nil
	}
	if state.Current != nil && state.Current.Key == key && state.Current.ID == id {
		return ActionResult{SSHAccess: config.receipt(state.Current, false)}, nil
	}
	return ActionResult{}, nil
}

func inspectSSHWindowListener(ctx context.Context, config sshWindowConfig, source netip.Addr) *rescuev1.SSHDaemonState {
	state := &rescuev1.SSHDaemonState{}
	iface, err := net.InterfaceByName(config.Interface)
	if err != nil {
		state.Limitation = fmt.Sprintf("SSH interface %s is unavailable", config.Interface)
		return state
	}
	addresses, err := iface.Addrs()
	if err != nil {
		state.Limitation = fmt.Sprintf("could not read addresses of SSH interface %s", config.Interface)
		return state
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().Is4() != source.Is4() {
			continue
		}
		ip := prefix.Addr().String()
		if probeSSHIdentification(ctx, net.JoinHostPort(ip, strconv.FormatUint(uint64(config.Port), 10))) {
			state.Running, state.Reachable = true, true
			state.ListenAddresses = []string{ip}
			state.ObservedListenPorts = []uint32{config.Port}
			return state
		}
	}
	state.Limitation = fmt.Sprintf("no SSH listener responded on %s TCP %d for the requested address family", config.Interface, config.Port)
	return state
}
