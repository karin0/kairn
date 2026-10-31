# kairn

Claude Code ends each commit message it writes with a trailer such as `Claude-Session: https://claude.ai/code/session_01AbCdEfGhJkMnPqRsTuVwXy`. Once such a commit is pushed to a public repository, every reader can see the session ID and group commits by the session that wrote them.

kairn is a git `commit-msg` hook that replaces this trailer with `Cairn: <ciphertext>` before git writes the commit. Only the holder of the secret key can turn the ciphertext back into the session URL. Each seal uses a fresh ephemeral key, so two commits from one session carry different ciphertexts.

Anthropic can still link a commit to its session, since the session transcript records the commit hash that `git commit` prints. kairn hides the session from readers of the repository only.

## Commands

- `kairn keygen` writes a new secret key to `$XDG_CONFIG_HOME/kairn/secret.key`, or `~/.config/kairn/secret.key`, and prints the public key. It refuses to overwrite an existing key, since every earlier ciphertext would become unreadable.
- `kairn seal <public-key> <message-file>` is the hook. It matches the `Claude-Session` key in any letter case, as git does for trailer keys. A `Claude-Session:` line whose value is not a session URL fails the hook, and git aborts the commit.
- `kairn open <rev>` prints the session URL of every `Cairn` trailer of the commit.

## Ciphertext format

The ciphertext is a libsodium-compatible sealed box (`crypto_box_seal`: X25519 and XSalsa20-Poly1305) of the session ID after the prefix `https://claude.ai/code/session_`. The trailer value encodes each byte of the sealed box as the braille pattern character U+2800 plus the byte. A 24-byte session ID becomes a 72-byte sealed box, which takes 72 characters and 72 terminal columns.

Keys are 32 bytes, encoded in base64url without padding.

## Installation

Run `kairn keygen` and keep a backup of `secret.key`. Then install `kairn` on `PATH` and declare the hook in the global git configuration:

```bash
cargo install --locked --git https://github.com/karin0/kairn
git config --global hook.kairn.command 'kairn seal <public-key>'
git config --global hook.kairn.event commit-msg
```

Git runs hooks declared in the configuration before the repository's own `.git/hooks/commit-msg`, which still runs, and appends the message file path to the command.

Two paths still write the plaintext trailer: `git commit --no-verify`, which skips every `commit-msg` hook, and any environment without the hook, such as a Claude Code cloud session. Rebase, cherry-pick, and plain amend keep the message as it is, and a sealed message stays sealed.

## Development

`./check.sh` runs shellcheck, rustfmt, clippy, the tests, and the release build.
