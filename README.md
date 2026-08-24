# touchglass

Break-glass CLI credentials that will not release without a physical
security-key touch.

`touchglass` seals a privileged credential (a `kubectl`
`system:masters` client key, a Talos `os:admin` config -- anything a
CLI reads from a file) inside a [touchvault](https://github.com/jeffbstewart/touchvault)
FIDO2 vault, and hands it back only after a physical touch on an
enrolled security key. It plugs in as a `kubectl` **exec credential
plugin**, so the touch happens inline on every break-glass session --
no touch, no credential, from any environment.

It pairs with `touchvault` as a family: `touchvault` keeps day-to-day
secrets behind a touch; `touchglass` keeps the *superuser* behind
one.

## Why

The powerful credentials on a cluster -- the RBAC-bypassing
`system:masters` cert, the machine-API `os:admin` config -- are
usually plaintext files on an operator's disk. Any process running as
that operator (an AI coding agent, a stray script, a mis-aimed
command) can read and use them. Behavioural rules ("don't touch prod")
are suggestions; a file permission is not much better.

`touchglass` makes the credential *physically* gated: the private
material is decrypted only by a touch that a human must be present to
give. An inadvertent invocation blocks on a prompt the caller cannot
satisfy and fails closed.

## What it is and isn't

A **mishap fence**, not malice containment. It stops accidents and
casual misuse cold. It does **not** contain an attacker who has
already achieved code execution as you at the moment you touch, nor
one who can reconstruct the credential from a cluster CA they can
read. Pair it with least-privilege defaults (a read-only day-to-day
identity) so break-glass is rare and deliberate.

## How it works

- **`credential`** -- a `kubectl` exec credential plugin. On each
  session it unlocks the vault (one touch), emits an `ExecCredential`
  with the client cert/key and a short expiry; client-go caches
  within that window, so one touch opens a working session rather
  than gating every command. The public cert stays in the clear so
  cert-expiry monitoring can read it; only the private key is sealed.
- **`seal`** -- the one-time enrollment ceremony. Creates the vault,
  stores the credentials, and enrolls two security keys (a backup, so
  losing one key is not a lockout). Requires physical touches; run it
  at the hardware.
- **`talos-unseal`** -- for CLIs with no exec-plugin hook (Talos'
  `talosctl`): unlock on a touch and write the config to a tmpfs path
  for a single session; shred it after.

A fast pre-check refuses even before the touch prompt when a known
agent-harness environment variable is set
(`CLAUDECODE`/`GEMINI_CLI`/`QWEN_CODE`/...), with a named message --
but that is only a friendly breadcrumb. The touch is the real gate,
and it works against unlisted and home-grown agents too, because none
of them can press a key.

## Install

    go install github.com/jeffbstewart/touchglass@latest

Requires a FIDO2 authenticator with the `hmac-secret` extension (e.g.
a YubiKey 5). Built and tested on Windows (native WebAuthn); the
touchvault FIDO provider is platform-specific.

## Usage

    touchglass seal         --vault vault.bin --k8s-key masters.key --talosconfig talosconfig
    touchglass credential   --vault vault.bin --cert breakglass.crt   # used by a kubeconfig exec stanza
    touchglass talos-unseal --vault vault.bin --out /dev/shm/talosconfig

Wire `credential` into a kubeconfig:

    users:
      - name: breakglass
        user:
          exec:
            apiVersion: client.authentication.k8s.io/v1
            command: touchglass
            args: [credential, --vault, /path/vault.bin, --cert, /path/breakglass.crt, --window, 5m]
            interactiveMode: Always

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
