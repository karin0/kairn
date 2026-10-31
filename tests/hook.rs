use std::fs;
use std::process::{Command, Output};

use tempfile::TempDir;

const KAIRN: &str = env!("CARGO_BIN_EXE_kairn");
const URL: &str = "https://claude.ai/code/session_01AbCdEfGhJkMnPqRsTuVwXy";

struct Sandbox {
    dir: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let sandbox = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::create_dir(sandbox.dir.path().join("repo")).unwrap();
        let public = String::from_utf8(sandbox.run(KAIRN, &["keygen"]).stdout).unwrap();
        let hook = format!("{KAIRN} seal {}", public.trim());
        sandbox.run("git", &["init", "-q"]);
        for (key, value) in [
            ("user.name", "test"),
            ("user.email", "test@example.com"),
            ("hook.kairn.command", &hook),
            ("hook.kairn.event", "commit-msg"),
        ] {
            sandbox.run("git", &["config", key, value]);
        }
        sandbox
    }

    fn try_run(&self, program: &str, args: &[&str]) -> Output {
        Command::new(program)
            .args(args)
            .current_dir(self.dir.path().join("repo"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("config"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
    }

    fn run(&self, program: &str, args: &[&str]) -> Output {
        let output = self.try_run(program, args);
        assert!(output.status.success(), "{output:?}");
        output
    }

    fn commit(&self, message: &str) -> Output {
        self.try_run("git", &["commit", "-q", "--allow-empty", "-m", message])
    }
}

#[test]
fn committed_session_url_is_sealed_and_opens() {
    let sandbox = Sandbox::new();
    let commit = sandbox.commit(&format!("test: seal\n\nClaude-Session: {URL}"));
    assert!(commit.status.success(), "{commit:?}");

    let log = String::from_utf8(sandbox.run("git", &["log", "--format=%B"]).stdout).unwrap();
    assert!(!log.contains("claude.ai"), "{log}");
    assert!(log.contains("Cairn: "), "{log}");
    let opened = sandbox.run(KAIRN, &["open", "HEAD"]);
    assert_eq!(
        String::from_utf8(opened.stdout).unwrap(),
        format!("{URL}\n")
    );
}

#[test]
fn session_url_outside_the_trailer_block_opens() {
    let sandbox = Sandbox::new();
    let commit = sandbox.commit(&format!("test: seal\n\nClaude-Session: {URL}\n\nfooter"));
    assert!(commit.status.success(), "{commit:?}");

    let opened = sandbox.run(KAIRN, &["open", "HEAD"]);
    assert_eq!(
        String::from_utf8(opened.stdout).unwrap(),
        format!("{URL}\n")
    );
}

#[test]
fn commit_with_an_unknown_session_url_aborts() {
    let sandbox = Sandbox::new();
    let commit = sandbox.commit("test: seal\n\nClaude-Session: https://example.com/session_abc");
    assert!(!commit.status.success());
    assert!(
        !sandbox
            .try_run("git", &["rev-parse", "HEAD"])
            .status
            .success()
    );
}

#[test]
fn open_fails_on_a_commit_without_cairn() {
    let sandbox = Sandbox::new();
    assert!(sandbox.commit("test: plain").status.success());
    assert!(!sandbox.try_run(KAIRN, &["open", "HEAD"]).status.success());
}
