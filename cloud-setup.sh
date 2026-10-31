#!/bin/bash
# Installs the kairn commit-msg hook in a Claude Code cloud session.
# usage: cloud-setup.sh <public-key>
set -euo pipefail

min_git=2.54
ppa_key=F911AB184317630C59970973E363C90F8F1B6217
keyring=/etc/apt/keyrings/git-core.gpg

# Written before kairn exists, so a failed install makes git abort every commit.
git config --global hook.kairn.command "kairn seal $1"
git config --global hook.kairn.event commit-msg

git_is_recent() {
    printf '%s\n' "$min_git" "$(git version | cut -d ' ' -f 3)" | sort -V -C
}

if ! git_is_recent; then
    key=$(curl -fsS --max-time 60 "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$ppa_key")
    gpg --show-keys --with-colons <<<"$key" | grep -q "^fpr:*$ppa_key:"
    install -d /etc/apt/keyrings
    gpg --dearmor --yes -o "$keyring" <<<"$key"
    codename=$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release)
    echo "deb [signed-by=$keyring] https://ppa.launchpadcontent.net/git-core/ppa/ubuntu $codename main" \
        >/etc/apt/sources.list.d/git-core.list
    apt-get update -q
    apt-get install -y -q git
    git_is_recent
fi

curl -fsSL --max-time 60 -o /usr/local/bin/kairn \
    https://github.com/karin0/kairn/releases/download/latest/kairn-x86_64-unknown-linux-musl
chmod 755 /usr/local/bin/kairn
