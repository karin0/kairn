# kairn

Claude Code ends each commit message it writes with a trailer such as `Claude-Session: https://claude.ai/code/session_01AbCdEfGhJkMnPqRsTuVwXy`, so every reader of a public repository can group its commits by the session that wrote them.

kairn is a git `commit-msg` hook that replaces this trailer with a `Cairn: <ciphertext>` trailer, which only the holder of the secret key can read. Claude Code writes the trailer only while the session has a claude.ai URL through Remote Control, so kairn also seals the local session ID, which keeps a commit traceable through the local transcript. Each seal uses a fresh ephemeral key, so two commits from one session carry different ciphertexts.

kairn hides the session from readers of the repository only. Anthropic can still link a commit to its session, since the session transcript records the commit hash.

## Commands

- `kairn keygen` writes a new secret key to `$XDG_CONFIG_HOME/kairn/secret.key`, or `~/.config/kairn/secret.key`, and prints the public key. It refuses to overwrite an existing key.
- `kairn seal <public-key> <message-file>` is the hook. It seals the local ID from `CLAUDE_CODE_SESSION_ID`, which names the transcript `~/.claude/projects/<project>/<UUID>.jsonl`, and the remote ID from the `Claude-Session:` line or `CLAUDE_CODE_BRIDGE_SESSION_ID`. A session URL on any other line fails the hook, and so does a malformed or disagreeing ID. The hook checks comment lines and the diff that `git commit -v` adds, since git removes them only after the hook runs and only in some cleanup modes, so a commit whose staged diff holds a session URL must be made without `-v`.
- `kairn open <rev>` prints the local ID and the session URL of each `Cairn:` line of a commit.

## Ciphertext format

The ciphertext is a libsodium-compatible sealed box (`crypto_box_seal`: X25519 and XSalsa20-Poly1305), which adds 48 bytes to its plaintext. The trailer encodes each byte as the braille character U+2800 plus the byte, so it takes one terminal column per byte.

A remote ID is `01` followed by 22 base58 digits in the Bitcoin alphabet, which encode a 128-bit number. Every remote ID observed so far has this form, and the hook rejects any other.

Version 2, which `seal` writes, has a 32-byte plaintext: the local UUID and then the 128-bit number of the remote ID, each as 16 big-endian bytes, with 16 zero bytes for an absent ID. Its fixed length hides whether a commit came from a session with a remote URL. It keeps the remote ID beside the local ID so that a commit stays traceable after its transcript is lost.

Version 1, which `open` still reads, has the 24 characters of the remote ID as its plaintext. `open` tells the versions apart by length.

Keys are 32 bytes, encoded in base64url without padding.

## Installation

Run `kairn keygen` and keep a backup of `secret.key`, since losing it makes every ciphertext unreadable. Then install `kairn` on `PATH` and declare the hook in the global git configuration, which needs git 2.54 or later:

```bash
cargo install --locked --git https://github.com/karin0/kairn
git config --global hook.kairn.command 'kairn seal <public-key>'
git config --global hook.kairn.event commit-msg
```

The repository's own `.git/hooks/commit-msg` still runs after kairn.

`git commit --no-verify`, git before 2.54, and an environment without the hook still write the plaintext trailer. Rebase, cherry-pick, and amend keep a sealed message sealed.

Claude Code also ends each pull request description with the bare session URL. No git hook sees it, so it must be deleted by hand.

## Development

`./check.sh` runs shellcheck, rustfmt, clippy, the tests, and the release build.
