package cmd

// Enrollment and credential commands.
//
// These exist because an Agent's identity is no longer a token an operator
// pastes into a config file. A pasted token is a bearer secret: anyone who
// reads the file, a backup or a shell history can replay it from anywhere.
// Instead the Agent generates a keypair, a human approves it once in the
// panel, and the resulting credentials are bound to that key.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/enrollment"
	"github.com/komari-monitor/komari-agent/dnsresolver"
	"github.com/komari-monitor/komari-agent/update"
	"github.com/spf13/cobra"
)

const enrollmentTimeout = 15 * time.Minute

var (
	loginEndpoint string
	loginNoPin    bool
)

// credentialsPath resolves where credentials live.
//
// The path is a root-level persistent flag rather than a per-command one so
// that a host storing its identity somewhere non-default does not have to
// repeat the location on every subcommand, and so the running daemon and the
// CLI cannot disagree about which file is authoritative.
func credentialsPath() string { return flags.CredentialsFile }

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Enroll this machine with a Komari panel",
	Long: `Enroll this machine with a Komari panel.

The Agent generates a keypair locally, asks the panel to start an approval,
and prints a link. Open it in a browser, sign in to the panel, and approve
this machine. The Agent polls until you do.

Nothing is sent to the panel that could authenticate as this machine later:
the private key never leaves this host, and the credentials the panel issues
are bound to it.

The approval link requires a panel login every time. That is deliberate — it
is the step where a human decides this machine may join.`,
	Example: `  komari-agent login --endpoint panel.example.com
  komari-agent login --endpoint https://panel.example.com:8443`,
	RunE: func(cmd *cobra.Command, args []string) error {
		loadFromEnv()
		endpoint := firstNonEmpty(loginEndpoint, flags.Endpoint)
		if strings.TrimSpace(endpoint) == "" {
			return errors.New("a panel address is required: pass --endpoint panel.example.com")
		}

		store, err := credentials.Open(credentialsPath())
		if err != nil {
			return err
		}
		if existing, ok := store.Identity(); ok && existing.AgentID != "" {
			return fmt.Errorf("this machine is already enrolled with %s as agent %s\nrun 'komari-agent logout' first if you want to enroll somewhere else",
				existing.Endpoint, existing.AgentID)
		}

		client, err := enrollment.New(endpoint, dnsresolver.GetHTTPClientWithPreference(30*time.Second, flags.PreferIPVersion))
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, enrollmentTimeout)
		defer cancel()

		fmt.Printf("Enrolling with %s\n\n", client.Endpoint())
		identity, err := client.Enroll(ctx, nil, printInstruction)
		if err != nil {
			return err
		}

		if err := store.Save(identity); err != nil {
			return err
		}

		// Trust is established here, on first contact. The operator typed the
		// panel's address by hand, so recording which keys answered is what
		// allows a later substitution to be noticed rather than accepted.
		if !loginNoPin {
			if err := pinTrust(ctx, client, store, identity); err != nil {
				fmt.Fprintf(os.Stderr, "\nWarning: could not pin the panel's signing keys: %v\n", err)
				fmt.Fprintln(os.Stderr, "Enrollment succeeded. Run 'komari-agent trust refresh' once the panel is reachable.")
			}
		}

		fmt.Printf("\nEnrolled as agent %s\n", identity.AgentID)
		fmt.Printf("Credentials stored at %s\n", store.Path())
		if !identity.RefreshTokenExpiresAt.IsZero() {
			fmt.Printf("Sign-in valid until %s (renewed automatically)\n",
				identity.RefreshTokenExpiresAt.Local().Format("2006-01-02 15:04"))
		}
		fmt.Println("\nStart the Agent with: komari-agent")
		return nil
	},
}

var refreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Renew this machine's credentials",
	Long: `Renew this machine's credentials.

The running Agent renews itself, so this is normally unnecessary. Use it when
the Agent has been stopped past its renewal window, or after a panel-side
revocation, to check whether this machine can still authenticate.

If the sign-in has fully expired, this cannot recover it: re-enrolling needs
a human to approve in the panel again. That is the point of an expiry.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		loadFromEnv()
		store, err := credentials.Open(credentialsPath())
		if err != nil {
			return err
		}
		identity, ok := store.Identity()
		if !ok {
			return errors.New("this machine is not enrolled; run 'komari-agent login' first")
		}
		if identity.RefreshExpired(time.Now()) {
			return fmt.Errorf("the sign-in for agent %s expired on %s\nrun 'komari-agent login --endpoint %s' to enroll again",
				identity.AgentID, identity.RefreshTokenExpiresAt.Local().Format("2006-01-02"), identity.Endpoint)
		}

		client, err := enrollment.New(identity.Endpoint, dnsresolver.GetHTTPClientWithPreference(30*time.Second, flags.PreferIPVersion))
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
		defer cancel()

		renewed, err := client.Refresh(ctx, identity)
		if err != nil {
			return err
		}
		if err := store.UpdateCredentials(renewed.AgentID, renewed.AccessToken, renewed.AccessTokenExpiresAt,
			renewed.RefreshToken, renewed.RefreshTokenExpiresAt, renewed.Scopes); err != nil {
			return err
		}
		fmt.Printf("Renewed credentials for agent %s\n", renewed.AgentID)
		if !renewed.RefreshTokenExpiresAt.IsZero() {
			fmt.Printf("Sign-in valid until %s\n", renewed.RefreshTokenExpiresAt.Local().Format("2006-01-02 15:04"))
		}
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show this machine's enrollment and configuration state",
	Long: `Show this machine's enrollment and configuration state.

Reports which panel this machine belongs to, whether its credentials are
current, what privileges the Agent holds, and which configuration revision is
running.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		loadFromEnv()
		store, err := credentials.Open(credentialsPath())
		if err != nil {
			return err
		}
		fmt.Printf("Agent version:   %s\n", update.CurrentVersion)

		identity, ok := store.Identity()
		if !ok {
			fmt.Println("Enrollment:      not enrolled")
			fmt.Println("\nRun 'komari-agent login --endpoint panel.example.com' to enroll.")
			return nil
		}
		fmt.Printf("Panel:           %s\n", identity.Endpoint)
		fmt.Printf("Agent ID:        %s\n", identity.AgentID)

		now := time.Now()
		switch {
		case identity.RefreshExpired(now):
			fmt.Println("Sign-in:         EXPIRED - run 'komari-agent login' to enroll again")
		case identity.NeedsRefresh(now):
			fmt.Println("Sign-in:         valid, access token renewing")
		default:
			fmt.Println("Sign-in:         valid")
		}
		if !identity.RefreshTokenExpiresAt.IsZero() {
			fmt.Printf("Valid until:     %s\n", identity.RefreshTokenExpiresAt.Local().Format("2006-01-02 15:04"))
		}
		fmt.Printf("Pinned keys:     %d\n", len(identity.ControlPlaneKeys))
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove this machine's stored credentials",
	Long: `Remove this machine's stored credentials.

This only affects this host. The machine stays registered in the panel, so
remove it there as well if you are decommissioning it.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := credentials.Open(credentialsPath())
		if err != nil {
			return err
		}
		identity, ok := store.Identity()
		if !ok {
			fmt.Println("This machine is not enrolled; nothing to remove.")
			return nil
		}
		if err := store.Clear(); err != nil {
			return err
		}
		fmt.Printf("Removed credentials for agent %s\n", identity.AgentID)
		fmt.Printf("The machine is still registered in %s; remove it there too if it is being retired.\n", identity.Endpoint)
		return nil
	},
}

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Inspect and update the panel signing keys this machine accepts",
	Long: `Inspect and update the panel signing keys this machine accepts.

The Agent verifies that privileged instructions really came from the panel,
rather than from something positioned between them. These are the keys it
checks against.`,
}

var trustShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the pinned panel signing keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := credentials.Open(credentialsPath())
		if err != nil {
			return err
		}
		identity, ok := store.Identity()
		if !ok {
			return errors.New("this machine is not enrolled; run 'komari-agent login' first")
		}
		if len(identity.ControlPlaneKeys) == 0 {
			fmt.Println("No panel signing keys are pinned.")
			fmt.Println("Run 'komari-agent trust refresh' to fetch them.")
			return nil
		}
		fmt.Printf("Panel: %s\n\n", identity.Endpoint)
		for _, key := range identity.ControlPlaneKeys {
			fmt.Printf("  key id      %s\n", key.KeyID)
			fmt.Printf("  fingerprint %s\n", enrollment.Fingerprint(key))
			if key.NotAfter != nil {
				fmt.Printf("  expires     %s\n", key.NotAfter.Local().Format("2006-01-02"))
			}
			fmt.Println()
		}
		return nil
	},
}

var trustRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Re-fetch the panel signing keys",
	Long: `Re-fetch the panel signing keys.

Run this after the panel rotates its keys. Compare the printed fingerprints
against the panel before relying on them: this replaces what the Agent trusts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		loadFromEnv()
		store, err := credentials.Open(credentialsPath())
		if err != nil {
			return err
		}
		identity, ok := store.Identity()
		if !ok {
			return errors.New("this machine is not enrolled; run 'komari-agent login' first")
		}
		client, err := enrollment.New(identity.Endpoint, dnsresolver.GetHTTPClientWithPreference(30*time.Second, flags.PreferIPVersion))
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
		defer cancel()
		if err := pinTrust(ctx, client, store, identity); err != nil {
			return err
		}
		fmt.Println("Pinned keys updated. Verify the fingerprints above against the panel.")
		return nil
	},
}

var reauthCmd = &cobra.Command{
	Use:   "reauth",
	Short: "Re-authenticate this machine when its sign-in has expired",
	Long: `Re-authenticate this machine when its sign-in has expired.

When the refresh token expires (after ~180 days), the Agent can no longer
renew itself silently. This command starts a new device authorization grant
that a panel administrator must approve, just like the original login, but
preserves the machine's identity, keypair, and pinned trust bundle.

Use this instead of 'logout + login' to avoid losing the machine's history
and configuration in the panel.`,
	Example: `  komari-agent reauth`,
	RunE: func(cmd *cobra.Command, args []string) error {
		loadFromEnv()
		store, err := credentials.Open(credentialsPath())
		if err != nil {
			return err
		}
		identity, ok := store.Identity()
		if !ok {
			return errors.New("this machine is not enrolled; run 'komari-agent login' instead")
		}
		if !identity.RefreshExpired(time.Now()) {
			fmt.Printf("Sign-in for agent %s is still valid (until %s).\n",
				identity.AgentID, identity.RefreshTokenExpiresAt.Local().Format("2006-01-02 15:04"))
			fmt.Println("Use 'komari-agent refresh' to renew the access token, or wait until it expires.")
			return nil
		}

		client, err := enrollment.New(identity.Endpoint, dnsresolver.GetHTTPClientWithPreference(30*time.Second, flags.PreferIPVersion))
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, enrollmentTimeout)
		defer cancel()

		fmt.Printf("Re-authenticating agent %s with %s\n\n", identity.AgentID, client.Endpoint())
		renewed, err := client.Reauth(ctx, identity, printInstruction)
		if err != nil {
			return err
		}

		if err := store.Save(renewed); err != nil {
			return err
		}

		fmt.Printf("\nRe-authenticated as agent %s\n", renewed.AgentID)
		if !renewed.RefreshTokenExpiresAt.IsZero() {
			fmt.Printf("Sign-in valid until %s (renewed automatically)\n",
				renewed.RefreshTokenExpiresAt.Local().Format("2006-01-02 15:04"))
		}
		return nil
	},
}

func pinTrust(ctx context.Context, client *enrollment.Client, store *credentials.Store, identity credentials.Identity) error {
	keys, algorithms, requireAll, minimum, err := client.FetchTrustBundle(ctx, identity.AgentID)
	if err != nil {
		return err
	}
	if err := store.PinTrustBundle(keys, algorithms, requireAll, minimum); err != nil {
		return err
	}
	for _, key := range keys {
		fmt.Printf("Pinned panel key %s\n  fingerprint %s\n", key.KeyID, enrollment.Fingerprint(key))
	}
	return nil
}

func printInstruction(instruction enrollment.Instruction) {
	target := instruction.VerificationURIComplete
	if strings.TrimSpace(target) == "" {
		target = instruction.VerificationURI
	}
	fmt.Println("Open this link and sign in to approve this machine:")
	fmt.Printf("\n    %s\n\n", target)
	if instruction.UserCode != "" {
		fmt.Printf("Verification code: %s\n", instruction.UserCode)
	}
	if !instruction.ExpiresAt.IsZero() {
		fmt.Printf("The link expires at %s.\n", instruction.ExpiresAt.Local().Format("15:04:05"))
	}
	fmt.Println("\nWaiting for approval...")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func init() {
	loginCmd.Flags().StringVarP(&loginEndpoint, "endpoint", "e", "", "Panel address, for example panel.example.com")
	loginCmd.Flags().BoolVar(&loginNoPin, "no-pin", false, "Skip pinning the panel signing keys during enrollment")
	trustCmd.AddCommand(trustShowCmd, trustRefreshCmd)
	RootCmd.AddCommand(loginCmd, refreshCmd, reauthCmd, statusCmd, logoutCmd, trustCmd)
}
