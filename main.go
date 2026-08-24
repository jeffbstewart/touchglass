// Command touchglass gates break-glass CLI credentials behind a
// physical FIDO2 touch, using the touchvault library
// (github.com/jeffbstewart/touchvault, FIDO2 hmac-secret). The
// worked example throughout is a Talos/Kubernetes cluster's
// superuser identities, its first consumer.
//
// Threat model: this is a MISHAP fence, not malice containment. It
// makes an inadvertent break-glass invocation -- by an agent, a
// stray script, muscle memory -- fail closed on a touch that the
// caller cannot provide. It does NOT contain an attacker who reads
// secrets.yaml from the repo and mints a fresh admin cert from the
// CA; that remains the separate secrets.yaml-custody question.
//
// Two private credentials are sealed in one vault, enrolled to BOTH
// of the operator's YubiKeys so losing one key is not a break-glass
// lockout:
//
//	k8s-breakglass-key   -- the system:masters client PRIVATE KEY.
//	                        Its public cert stays in the clear (it
//	                        is public, and the cert-expiry exporter
//	                        must read its notAfter).
//	talos-breakglass-config -- the whole os:admin talosconfig
//	                        (talosctl has no exec-plugin hook, so it
//	                        is unsealed to a tmpfs path per session).
//
// Subcommands:
//
//	credential   kubectl exec credential plugin: touch -> emit an
//	             ExecCredential with the system:masters cert/key and
//	             a short expiry (client-go caches it, so one touch
//	             opens a working window rather than gating every
//	             command).
//	seal         one-time ceremony (the operator, at the hardware):
//	             create the vault, store the key + talosconfig, enroll
//	             both keys, write the sealed bytes.
//	talos-unseal break-glass for the machine API: touch -> write the
//	             talosconfig to a caller-provided (tmpfs) path for a
//	             single session; the caller shreds it after.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jeffbstewart/touchvault"
	"github.com/jeffbstewart/touchvault/fido"
)

const (
	rpID        = "touchglass.invalid"
	rpName      = "touchglass"
	entryK8sKey = "k8s-breakglass-key"
	entryTalos  = "talos-breakglass-config"
	execAPIVer  = "client.authentication.k8s.io/v1"
)

// agentEnvMarkers are the well-known variables that agent coding
// harnesses set in every subprocess they spawn. Their presence is a
// fast, friendly pre-check that refuses BEFORE the touch prompt with
// a named breadcrumb -- belt-and-suspenders only. The touch is the
// real, fail-closed gate: an unlisted or home-grown agent still
// cannot produce one. (Verified conventions as of 2026-08-24;
// CLAUDECODE self-observed, GEMINI_CLI/QWEN_CODE documented as set
// in shell subprocesses, the rest attested.)
var agentEnvMarkers = []string{
	"CLAUDECODE",      // Claude Code
	"GEMINI_CLI",      // Gemini CLI
	"QWEN_CODE",       // Qwen Code
	"CODEX_SANDBOX",   // OpenAI Codex CLI (sandboxed)
	"CURSOR_AGENT",    // Cursor agent
	"CURSOR_TRACE_ID", // Cursor agent
	"OPENCODE",        // opencode
	"OPENCODE_RUN_ID", // opencode
	"AIDER_CHAT",      // aider (best-effort; aider does not reliably self-identify)
}

func main() {
	// Refuse everything, before any dispatch, when a known agent
	// harness environment is detected. Break-glass must never run
	// under an agent -- this is the fast, named pre-check; the FIDO2
	// touch (below, per subcommand) is the real, unlisted-agent-proof
	// gate.
	if err := refuseIfAgent(); err != nil {
		fmt.Fprintf(os.Stderr, "touchglass: %v\n", err)
		os.Exit(1)
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "credential":
		err = runCredential(os.Args[2:])
	case "seal":
		err = runSeal(os.Args[2:])
	case "talos-unseal":
		err = runTalosUnseal(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "touchglass: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: touchglass <subcommand> [flags]

subcommands:
  credential     kubectl exec credential plugin (touch -> ExecCredential)
  seal           one-time enrollment ceremony (run at the hardware)
  talos-unseal   write the talosconfig to a path for one session (touch)
`)
}

// refuseIfAgent aborts, naming the marker, when a known agent
// harness environment is detected.
func refuseIfAgent() error {
	for _, k := range agentEnvMarkers {
		if os.Getenv(k) != "" {
			return fmt.Errorf("break-glass refused: agent execution environment detected (%s set). "+
				"Break-glass requires a physical FIDO2 touch from an interactive terminal", k)
		}
	}
	return nil
}

func runCredential(args []string) error {
	fs := flag.NewFlagSet("credential", flag.ContinueOnError)
	vaultPath := fs.String("vault", "", "path to the sealed touchvault file (required)")
	certPath := fs.String("cert", "", "path to the system:masters client certificate PEM, in the clear (required)")
	window := fs.Duration("window", 5*time.Minute, "how long the emitted credential stays cached before another touch is required")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vaultPath == "" || *certPath == "" {
		return errors.New("credential: -vault and -cert are required")
	}

	cert, err := os.ReadFile(*certPath)
	if err != nil {
		return fmt.Errorf("reading clear certificate: %w", err)
	}
	key, err := unsealEntry(*vaultPath, entryK8sKey)
	if err != nil {
		return err
	}

	out := map[string]any{
		"apiVersion": execAPIVer,
		"kind":       "ExecCredential",
		"status": map[string]any{
			"clientCertificateData": string(cert),
			"clientKeyData":         key,
			"expirationTimestamp":   time.Now().Add(*window).UTC().Format(time.RFC3339),
		},
	}
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(out)
}

func runTalosUnseal(args []string) error {
	fs := flag.NewFlagSet("talos-unseal", flag.ContinueOnError)
	vaultPath := fs.String("vault", "", "path to the sealed touchvault file (required)")
	outPath := fs.String("out", "", "path to write the talosconfig to; use a tmpfs/ramdisk path and shred after (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vaultPath == "" || *outPath == "" {
		return errors.New("talos-unseal: -vault and -out are required")
	}

	cfg, err := unsealEntry(*vaultPath, entryTalos)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("writing talosconfig: %w", err)
	}
	fmt.Fprintf(os.Stderr, "talosconfig written to %s -- use it, then shred it (this is a break-glass session)\n", *outPath)
	return nil
}

// unsealEntry opens the vault, unlocks it with a physical touch, and
// returns one named secret.
func unsealEntry(vaultPath, name string) (string, error) {
	sealed, err := os.ReadFile(vaultPath)
	if err != nil {
		return "", fmt.Errorf("reading vault: %w", err)
	}
	auth, err := fido.New()
	if err != nil {
		return "", fmt.Errorf("initializing FIDO2 authenticator: %w", err)
	}
	v, err := touchvault.Open(sealed)
	if err != nil {
		return "", fmt.Errorf("opening vault: %w", err)
	}
	fmt.Fprintln(os.Stderr, "cell1 break-glass: touch your security key...")
	sess, err := v.Unlock(auth)
	if err != nil {
		return "", fmt.Errorf("unlocking vault (touch failed or no enrolled key present): %w", err)
	}
	defer sess.Lock()
	secret, err := touchvault.ReadString(sess, name)
	if err != nil {
		return "", fmt.Errorf("reading %q from vault: %w", name, err)
	}
	return secret, nil
}

func runSeal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	vaultPath := fs.String("vault", "", "output path for the sealed vault (required)")
	k8sKeyPath := fs.String("k8s-key", "", "path to the system:masters client PRIVATE KEY PEM to seal (required)")
	talosPath := fs.String("talosconfig", "", "path to the os:admin talosconfig to seal (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vaultPath == "" || *k8sKeyPath == "" || *talosPath == "" {
		return errors.New("seal: -vault, -k8s-key and -talosconfig are all required")
	}

	auth, err := fido.New()
	if err != nil {
		return fmt.Errorf("initializing FIDO2 authenticator: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Insert your PRIMARY key. Touch to create the vault...")
	admin, err := touchvault.Create(auth, touchvault.Options{
		RPID:   rpID,
		RPName: rpName,
		Label:  "yk-primary",
	})
	if err != nil {
		return fmt.Errorf("creating vault: %w", err)
	}
	if err := putFile(admin, entryK8sKey, *k8sKeyPath); err != nil {
		return err
	}
	if err := putFile(admin, entryTalos, *talosPath); err != nil {
		return err
	}

	fmt.Fprint(os.Stderr, "Now insert your BACKUP key and press Enter (both keys must be enrolled)... ")
	fmt.Fscanln(os.Stdin)
	if err := admin.EnrollKey(auth, 1, "yk-backup"); err != nil {
		return fmt.Errorf("enrolling backup key: %w", err)
	}

	sealed, err := admin.Sealed()
	if err != nil {
		return fmt.Errorf("sealing vault: %w", err)
	}
	if err := os.WriteFile(*vaultPath, sealed, 0o644); err != nil {
		return fmt.Errorf("writing vault: %w", err)
	}
	fmt.Fprintf(os.Stderr, "vault sealed to %s (both keys enrolled). Commit it; the private material is ciphertext toward keys the repo never holds.\n", *vaultPath)
	return nil
}

func putFile(admin touchvault.Admin, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()
	if err := admin.Put(name, f); err != nil {
		return fmt.Errorf("storing %q: %w", name, err)
	}
	return nil
}
