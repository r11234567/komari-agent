package cmd

// Privileged configuration commands.
//
// A privileged setting is one that widens what the Agent may do. Those are
// never adopted by the Agent on its own: they are delivered, and then a person
// on this host decides. These commands are that decision point, which is why
// they live in the CLI rather than in the daemon's config loop.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/localauth"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/dnsresolver"
	"github.com/komari-monitor/komari-agent/requestheaders"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var upgradeAssumeYes bool

// privilegedPath resolves where the privileged configuration state lives.
//
// Like the credentials path this is a root-level persistent flag, so the
// running daemon and these commands cannot end up reading different files and
// disagreeing about what is pending or active.
func privilegedPath() string { return flags.PrivilegedStateFile }

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Apply a privileged configuration change delivered by the panel",
	Long: `Apply a privileged configuration change delivered by the panel.

Some settings widen what the Agent is allowed to do, such as enabling remote
control or the rescue helper. The panel can deliver those, but it cannot turn
them on: that would let anyone who controls the panel widen privileges on
every machine at once. Instead the change waits here until someone on this
host approves it.

You will be asked to authenticate. The password is checked by this machine and
is never sent to the panel or seen by the Agent; the panel is only told which
method verified you.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		loadFromEnv()
		store, err := privileged.Open(privilegedPath())
		if err != nil {
			return err
		}
		state := store.State()
		if state.Pending == nil {
			fmt.Println("No privileged change is waiting to be applied.")
			fmt.Printf("Active revision: %d\n", state.AppliedRevision)
			return nil
		}
		if !state.PendingExpiry.IsZero() && time.Now().After(state.PendingExpiry) {
			return fmt.Errorf("the pending change (revision %d) expired on %s\nask the panel to deliver it again",
				state.PendingRevision, state.PendingExpiry.Local().Format("2006-01-02 15:04"))
		}

		describePending(state)

		if !upgradeAssumeYes && !confirm("Apply this change on this machine?") {
			fmt.Println("Cancelled. Nothing was changed.")
			return nil
		}

		// Verification happens before anything is written, so declining or
		// failing leaves the host exactly as it was.
		result, err := localauth.Verify(localauth.Options{
			Prompt: "Confirm you are authorized to change this machine's privileges.",
		})
		if err != nil {
			return err
		}

		privilegeMode := currentPrivilegeMode()
		applied, err := store.Promote(privilegeMode)
		if err != nil {
			// The most common cause is a change that assumes root while the
			// Agent still runs unprivileged, which means the service itself
			// has to be reinstalled first.
			return err
		}

		auditPrivilegeChange(state, result, privilegeMode)

		fmt.Printf("\nApplied privileged revision %d.\n", store.State().AppliedRevision)
		describeSettings(applied)
		fmt.Println("\nRestart the Agent for the change to take effect: systemctl restart komari-agent")

		// Reporting is best-effort on purpose. The change is already active
		// locally, and a panel that cannot be reached must not make the host
		// disagree with itself about what it is running.
		if err := reportPrivilegedOutcome(cmd.Context(), state.PendingRevision,
			configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED, privilegeMode, result); err != nil {
			fmt.Fprintf(os.Stderr, "\nNote: could not tell the panel yet: %v\n", err)
			fmt.Fprintln(os.Stderr, "The change is applied locally and the Agent will report it when it reconnects.")
		}
		return nil
	},
}

var rollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Withdraw the active privileged configuration",
	Long: `Withdraw the active privileged configuration and return to the previous one.

This works without the panel, which is the point: if a privileged change was
wrong, or the panel that sent it is unreachable, this machine still has to be
able to take the privileges back. The panel is told afterwards.

The withdrawn settings become the new rollback target, so rolling back by
mistake can itself be undone.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		loadFromEnv()
		store, err := privileged.Open(privilegedPath())
		if err != nil {
			return err
		}
		state := store.State()
		if state.Previous == nil {
			return errors.New("there is no previous privileged configuration to return to")
		}

		fmt.Printf("Active revision:   %d\n", state.AppliedRevision)
		describeSettings(state.Active)
		fmt.Printf("\nWould return to revision %d\n", state.PreviousRevision)
		describeSettings(*state.Previous)

		if !upgradeAssumeYes && !confirm("\nRoll back to the previous configuration?") {
			fmt.Println("Cancelled. Nothing was changed.")
			return nil
		}

		// Rolling back narrows privileges rather than widening them, so it is
		// intentionally cheaper to authorize than an upgrade: requiring a
		// password to undo a bad change is how hosts stay stuck with one.
		restored, revision, err := store.Rollback()
		if err != nil {
			return err
		}

		privilegeMode := currentPrivilegeMode()
		auditRollback(state.AppliedRevision, revision)

		fmt.Printf("\nRolled back to privileged revision %d.\n", revision)
		describeSettings(restored)
		fmt.Println("\nRestart the Agent for the change to take effect: systemctl restart komari-agent")

		if err := reportPrivilegedOutcome(cmd.Context(), state.AppliedRevision,
			configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_ROLLED_BACK, privilegeMode, localauth.Result{}); err != nil {
			fmt.Fprintf(os.Stderr, "\nNote: could not tell the panel yet: %v\n", err)
			fmt.Fprintln(os.Stderr, "The rollback is applied locally and the Agent will report it when it reconnects.")
		}
		return nil
	},
}

var privilegedStatusCmd = &cobra.Command{
	Use:   "privileged",
	Short: "Show the privileged configuration and any pending change",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := privileged.Open(privilegedPath())
		if err != nil {
			return err
		}
		state := store.State()
		fmt.Printf("Active revision:  %d\n", state.AppliedRevision)
		describeSettings(state.Active)
		fmt.Printf("\nPrivilege mode:   %s\n", describeMode(currentPrivilegeMode()))
		if state.Previous != nil {
			fmt.Printf("Can roll back to: revision %d\n", state.PreviousRevision)
		}
		if state.Pending != nil {
			fmt.Println()
			describePending(state)
		}
		return nil
	},
}

func describePending(state privileged.State) {
	fmt.Printf("Pending revision %d\n", state.PendingRevision)
	describeSettings(*state.Pending)
	switch configv1.UpgradeClass(state.PendingClass) {
	case configv1.UpgradeClass_UPGRADE_CLASS_MANUAL_PRIVILEGED:
		fmt.Println("\nThis change crosses a privilege boundary, so it has to be approved here on the machine.")
	case configv1.UpgradeClass_UPGRADE_CLASS_MANUAL_CONFIRM:
		fmt.Println("\nThis change stays within the current privilege level and needs a confirmation.")
	}
	for _, reason := range state.PendingReasons {
		fmt.Printf("  - %s\n", reason)
	}
	if !state.PendingExpiry.IsZero() {
		fmt.Printf("Expires: %s\n", state.PendingExpiry.Local().Format("2006-01-02 15:04"))
	}
}

func describeSettings(settings privileged.Settings) {
	fmt.Printf("  remote control  %s\n", onOff(settings.RemoteControlEnabled))
	fmt.Printf("  WebSSH          %s\n", onOff(settings.WebSSHEnabled))
	fmt.Printf("  execution       %s\n", onOff(settings.ExecutionEnabled))
	fmt.Printf("  GPU monitoring  %s\n", onOff(settings.EnableGPU))
	fmt.Printf("  rescue helper   %s\n", onOff(settings.RescueHelperEnabled))
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

func describeMode(mode reportv1.PrivilegeMode) string {
	switch mode {
	case reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT:
		return "root"
	case reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT:
		return "non-root user"
	case reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_ADMINISTRATOR:
		return "administrator"
	case reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_STANDARD_USER:
		return "standard user"
	default:
		return "unknown"
	}
}

func currentPrivilegeMode() reportv1.PrivilegeMode {
	return capability.Detect(false).GetPrivilegeMode()
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	var answer string
	if _, err := fmt.Scanln(&answer); err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

// auditPrivilegeChange records the change in the host's own log.
//
// The local record is the one that matters for accountability: it survives
// independently of the panel, so an operator reviewing a machine can see that
// its privileges changed even if the panel's history is gone or disputed.
func auditPrivilegeChange(state privileged.State, result localauth.Result, mode reportv1.PrivilegeMode) {
	message := fmt.Sprintf(
		"privileged configuration applied: revision %d -> %d; remote_control=%s webssh=%s execution=%s rescue_helper=%s; privilege_mode=%s; operator=%s; verified_by=%s",
		state.AppliedRevision, state.PendingRevision,
		onOff(state.Pending.RemoteControlEnabled), onOff(state.Pending.WebSSHEnabled),
		onOff(state.Pending.ExecutionEnabled), onOff(state.Pending.RescueHelperEnabled),
		describeMode(mode), result.Operator, result.Method,
	)
	writeAuditLog(message)
}

func auditRollback(from, to uint64) {
	writeAuditLog(fmt.Sprintf("privileged configuration rolled back: revision %d -> %d", from, to))
}

// writeAuditLog sends one line to the system log at authpriv, which is where
// privilege changes belong and where existing log shipping already looks.
func writeAuditLog(message string) {
	binary, err := exec.LookPath("logger")
	if err != nil {
		// Without logger the change still happened, so say so on stderr
		// rather than failing an operation that has already completed.
		fmt.Fprintf(os.Stderr, "Note: could not write to the system log: %v\n", err)
		return
	}
	command := exec.Command(binary, "-p", "authpriv.notice", "-t", "komari-agent", message)
	if err := command.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Note: could not write to the system log: %v\n", err)
	}
}

// reportPrivilegedOutcome tells the panel what happened here.
//
// It carries the privilege mode the Agent actually ended up with, so the panel
// can check the outcome against what the revision assumed instead of trusting
// the reported state alone.
func reportPrivilegedOutcome(parent context.Context, revision uint64, state configv1.PrivilegedDeliveryState, mode reportv1.PrivilegeMode, auth localauth.Result) error {
	credentialStore, err := credentials.Open(credentialsPath())
	if err != nil {
		return err
	}
	identity, ok := credentialStore.Identity()
	if !ok {
		return errors.New("this machine is not enrolled")
	}
	client := configv1connect.NewPrivilegedDeliveryServiceClient(
		dnsresolver.GetHTTPClientWithPreference(30*time.Second, flags.PreferIPVersion), identity.Endpoint)

	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	request := connect.NewRequest(&configv1.ReportPrivilegedDeliveryRequest{
		AgentId:             identity.AgentID,
		Revision:            revision,
		State:               state,
		FinishedAt:          timestamppb.Now(),
		ActivePrivilegeMode: mode,
	})
	requestheaders.ApplyAgentAuthentication(request.Header(), identity.AccessToken,
		flags.CFAccessClientID, flags.CFAccessClientSecret)
	if _, err := client.ReportPrivilegedDelivery(ctx, request); err != nil {
		return err
	}

	// A manual upgrade additionally redeems its nonce, which is what proves to
	// the panel that the upgrade ran on this machine rather than being claimed
	// from somewhere else.
	if state == configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED && auth.Method != "" {
		store, storeErr := privileged.Open(privilegedPath())
		if storeErr != nil {
			return nil
		}
		if nonce := store.State().PendingNonce; nonce != "" {
			complete := connect.NewRequest(&configv1.CompleteManualUpgradeRequest{
				AgentId:                identity.AgentID,
				Nonce:                  nonce,
				LocalAuthentication:    string(auth.Method),
				Operator:               auth.Operator,
				ResultingPrivilegeMode: mode,
			})
			requestheaders.ApplyAgentAuthentication(complete.Header(), identity.AccessToken,
				flags.CFAccessClientID, flags.CFAccessClientSecret)
			if _, err := client.CompleteManualUpgrade(ctx, complete); err != nil {
				return err
			}
		}
	}
	return nil
}

func init() {
	upgradeCmd.Flags().BoolVarP(&upgradeAssumeYes, "yes", "y", false, "Do not ask for confirmation (local authentication is still required)")
	rollbackCmd.Flags().BoolVarP(&upgradeAssumeYes, "yes", "y", false, "Do not ask for confirmation")
	statusCmd.AddCommand(privilegedStatusCmd)
	RootCmd.AddCommand(upgradeCmd, rollbackCmd)
}
