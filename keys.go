package main

// Key management on an existing vault: list, add, remove, check.
//
// seal builds a vault from plaintext and enrolls exactly two keys.
// These subcommands change which security keys open a vault that
// already exists, without the plaintext: touchvault re-wraps the
// vault's data key for a new key, so no secret is decrypted to disk
// and the original key files are never needed again.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeffbstewart/touchvault"
	"github.com/jeffbstewart/touchvault/fido"
)

// openVault reads and parses a sealed vault. Metadata (slots, names)
// is readable without a touch.
func openVault(path string) (touchvault.Vault, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading vault: %w", err)
	}
	v, err := touchvault.Open(sealed)
	if err != nil {
		return nil, fmt.Errorf("opening vault: %w", err)
	}
	return v, nil
}

func printSlots(slots []touchvault.SlotInfo) {
	for _, s := range slots {
		fmt.Fprintf(os.Stderr, "  %s\n", s)
	}
}

func runKeys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ContinueOnError)
	vaultPath := fs.String("vault", "", "path to the sealed touchvault file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vaultPath == "" {
		return errors.New("keys: -vault is required")
	}
	v, err := openVault(*vaultPath)
	if err != nil {
		return err
	}
	slots := v.Slots()
	fmt.Fprintf(os.Stderr, "%s: %d enrolled key(s)\n", *vaultPath, len(slots))
	printSlots(slots)
	fmt.Fprintf(os.Stderr, "secrets: %v\n", v.Names())
	return nil
}

// chooseSlot picks the slot for a new key: the requested one, or the
// lowest free one when requested is negative. It refuses a label
// already in use, so a listing always tells two keys apart.
func chooseSlot(slots []touchvault.SlotInfo, requested int, label string) (int, error) {
	if label == "" {
		return 0, errors.New("a -label is required (name the physical key, e.g. yk-laptop-usbc)")
	}
	for _, s := range slots {
		if s.Label == label {
			return 0, fmt.Errorf("label %q is already used by slot %d", label, s.Slot)
		}
		if requested >= 0 && s.Slot == requested {
			return 0, fmt.Errorf("slot %d is occupied (%s)", requested, s.Label)
		}
	}
	if requested >= 0 {
		return requested, nil
	}
	return touchvault.FreeSlot(slots), nil
}

func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	vaultPath := fs.String("vault", "", "path to the sealed touchvault file, rewritten in place (required)")
	label := fs.String("label", "", "name for the new key's slot, shown by `keys` (required)")
	slot := fs.Int("slot", -1, "slot number for the new key (default: the lowest free slot)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vaultPath == "" {
		return errors.New("enroll: -vault is required")
	}
	v, err := openVault(*vaultPath)
	if err != nil {
		return err
	}
	target, err := chooseSlot(v.Slots(), *slot, *label)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	auth, err := fido.New()
	if err != nil {
		return fmt.Errorf("initializing FIDO2 authenticator: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Currently enrolled:")
	printSlots(v.Slots())
	fmt.Fprintln(os.Stderr, "Touch an ALREADY-ENROLLED key to unlock the vault for administration...")
	admin, err := v.Administer(auth)
	if err != nil {
		return fmt.Errorf("unlocking vault (touch failed or no enrolled key present): %w", err)
	}
	defer admin.Lock()

	fmt.Fprintf(os.Stderr, "Unlocked. Now insert the NEW key and press Enter. Touch ONLY the new key for the next three prompts\n"+
		"(touching an enrolled key here enrolls it a second time, which is no backup)... ")
	fmt.Fscanln(os.Stdin)
	if err := admin.EnrollKey(auth, target, *label); err != nil {
		return fmt.Errorf("enrolling new key: %w", err)
	}
	if err := writeSealed(admin, *vaultPath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Enrolled %q into slot %d. Vault now opens with:\n", *label, target)
	printSlots(admin.Slots())
	fmt.Fprintln(os.Stderr, "Prove it: with ONLY the new key present, run `touchglass check -vault <vault>`. Then commit the vault.")
	return nil
}

func runRemoveKey(args []string) error {
	fs := flag.NewFlagSet("remove-key", flag.ContinueOnError)
	vaultPath := fs.String("vault", "", "path to the sealed touchvault file, rewritten in place (required)")
	slot := fs.Int("slot", -1, "slot number to remove, as `keys` lists it (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vaultPath == "" || *slot < 0 {
		return errors.New("remove-key: -vault and -slot are required")
	}
	v, err := openVault(*vaultPath)
	if err != nil {
		return err
	}
	found := false
	for _, s := range v.Slots() {
		if s.Slot == *slot {
			found = true
			fmt.Fprintf(os.Stderr, "Removing %s\n", s)
		}
	}
	if !found {
		return fmt.Errorf("remove-key: slot %d is not enrolled", *slot)
	}

	auth, err := fido.New()
	if err != nil {
		return fmt.Errorf("initializing FIDO2 authenticator: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Touch an enrolled key to unlock the vault for administration...")
	admin, err := v.Administer(auth)
	if err != nil {
		return fmt.Errorf("unlocking vault (touch failed or no enrolled key present): %w", err)
	}
	defer admin.Lock()
	// RemoveKey, never ForceRemoveKey: the last key's removal is a
	// lockout, and this tool has no business offering it.
	if err := admin.RemoveKey(*slot); err != nil {
		return fmt.Errorf("removing slot %d: %w", *slot, err)
	}
	if err := writeSealed(admin, *vaultPath); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Removed. Vault now opens with:")
	printSlots(admin.Slots())
	return nil
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	vaultPath := fs.String("vault", "", "path to the sealed touchvault file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vaultPath == "" {
		return errors.New("check: -vault is required")
	}
	v, err := openVault(*vaultPath)
	if err != nil {
		return err
	}
	auth, err := fido.New()
	if err != nil {
		return fmt.Errorf("initializing FIDO2 authenticator: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Touch the key to check...")
	sess, err := v.Unlock(auth)
	if err != nil {
		return fmt.Errorf("NOT enrolled, or the touch failed: %w", err)
	}
	sess.Lock()
	fmt.Fprintln(os.Stderr, "OK: that key unlocks the vault (nothing was read)")
	return nil
}

// writeSealed persists the vault atomically: a temp file in the same
// directory, then a rename over the original, so a failure mid-write
// never leaves a truncated vault (which would be a lockout until git
// restores it).
func writeSealed(admin touchvault.Admin, path string) error {
	sealed, err := admin.Sealed()
	if err != nil {
		return fmt.Errorf("sealing vault: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".touchglass-*.tmp")
	if err != nil {
		return fmt.Errorf("writing vault: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing vault: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("writing vault: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("writing vault: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("replacing vault: %w", err)
	}
	return nil
}
