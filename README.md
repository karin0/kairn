# kairn

Claude Code ends each commit message it writes with a trailer such as `Claude-Session: https://claude.ai/code/session_01AbCdEfGhJkMnPqRsTuVwXy`. Once such a commit is pushed to a public repository, every reader can see the session ID and group commits by the session that wrote them.

kairn is a git `commit-msg` hook that seals the session of each commit Claude Code makes into a `Cairn: <ciphertext>` trailer before git writes the commit, and removes the `Claude-Session` trailer. Claude Code writes that trailer only while the session has a claude.ai URL through Remote Control, so kairn also seals the local session ID that Claude Code passes to its shell commands. A commit stays traceable through the local transcript when the session has no remote URL. Only the holder of the secret key can read the ciphertext. Each seal uses a fresh ephemeral key, so two commits from one session carry different ciphertexts.

Anthropic can still link a commit to its session, since the session transcript records the commit hash that `git commit` prints. kairn hides the session from readers of the repository only.

## Commands

`kairn --help` describes these commands for a Claude Code session that meets the hook, and every hook failure points to it.

- `kairn keygen` writes a new secret key to `$XDG_CONFIG_HOME/kairn/secret.key`, or `~/.config/kairn/secret.key`, and prints the public key. It refuses to overwrite an existing key, since every earlier ciphertext would become unreadable.
- `kairn seal <public-key> <message-file>` is the hook. It reads two IDs, and either of them may be absent:
  - The local ID is the UUID in `CLAUDE_CODE_SESSION_ID`, which also names the transcript `~/.claude/projects/<project>/<UUID>.jsonl` on the machine that ran the session.
  - The remote ID comes from the `Claude-Session:` line and from `CLAUDE_CODE_BRIDGE_SESSION_ID`, whose value is `session_<ID>`. When both hold an ID, they must agree.

  An empty variable counts as unset. A malformed variable, a `Claude-Session:` value that is not a session URL, two disagreeing remote IDs, or a session URL on any other line, in any letter case, fail the hook, and git aborts the commit. The hook output is written for the Claude Code session that ran `git commit`, so it states the line and how to correct it, or asks the session to report a failure that it cannot correct, such as a malformed variable or a session ID of another form, to the user. Every hook failure also warns that `--no-verify` would publish the session URL. The hook replaces every line that starts with the `Claude-Session:` key in any letter case, as git matches trailer keys, with a `Cairn:` line in place, including a line outside the final trailer paragraph. A message without such a line gets a `Cairn:` trailer appended by `git interpret-trailers`, unless it already has a `Cairn:` line, since `git commit --amend` runs the hook again on a sealed message. A message stays unchanged when the hook finds no ID.
- `kairn open <rev>` reads every line of the commit message that starts with the `Cairn:` key, matched by the same rule as `seal`, and prints the local ID and then the session URL that the line holds. A `Cairn:` line whose value is not a sealed box fails the command.

## Ciphertext format

The ciphertext is a libsodium-compatible sealed box (`crypto_box_seal`: X25519 and XSalsa20-Poly1305), which adds 48 bytes to its plaintext. The trailer value encodes each byte of the sealed box as the braille pattern character U+2800 plus the byte, so each byte takes one character and one terminal column. `open` tells the two versions apart by length.

A remote ID is `01` followed by 22 base58 digits in the Bitcoin alphabet, which encode a 128-bit number. Every remote ID observed so far has this form, and the hook rejects any other.

Version 2, which `seal` writes, has a 32-byte plaintext: the local UUID and then the 128-bit number of the remote ID, each as 16 big-endian bytes, with 16 zero bytes for an absent ID. Its sealed box takes 80 bytes, whichever IDs it holds, so a reader of the repository cannot tell whether a commit came from a session with a remote URL. It keeps the remote ID even when the local ID is present, although the transcript records the remote URLs of its session, so that a commit stays traceable after its transcript is lost.

Version 1, which `open` still reads, has the 24 characters of the remote ID as its plaintext and a 72-byte sealed box.

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

Claude Code also ends each pull request description it writes with the bare session URL. No git hook sees a pull request description, so the URL must be deleted by hand before the pull request is created.

## Development

`./check.sh` runs shellcheck, rustfmt, clippy, the tests, and the release build.
