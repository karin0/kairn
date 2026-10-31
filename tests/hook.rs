use std::fs;
use std::process::{Command, Output};

use tempfile::TempDir;

const KAIRN: &str = env!("CARGO_BIN_EXE_kairn");
const URL: &str = "https://claude.ai/code/session_01AbCdEfGhJkMnPqRsTuVwXy";
const LOCAL_ID_VAR: &str = "CLAUDE_CODE_SESSION_ID";
const BRIDGE_ID_VAR: &str = "CLAUDE_CODE_BRIDGE_SESSION_ID";
const LOCAL: &str = "12345678-1234-4abc-8def-0123456789ab";
const LOCAL_ENV: &[(&str, &str)] = &[(LOCAL_ID_VAR, LOCAL)];

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

    /// Runs `program` outside any Claude Code session, plus the variables of `env`.
    fn try_run_in(&self, env: &[(&str, &str)], program: &str, args: &[&str]) -> Output {
        Command::new(program)
            .args(args)
            .current_dir(self.dir.path().join("repo"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("config"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove(LOCAL_ID_VAR)
            .env_remove(BRIDGE_ID_VAR)
            .envs(env.iter().copied())
            .output()
            .unwrap()
    }

    fn try_run(&self, program: &str, args: &[&str]) -> Output {
        self.try_run_in(&[], program, args)
    }

    fn run(&self, program: &str, args: &[&str]) -> Output {
        let output = self.try_run(program, args);
        assert!(output.status.success(), "{output:?}");
        output
    }

    fn commit(&self, env: &[(&str, &str)], message: &str) -> Output {
        self.try_run_in(
            env,
            "git",
            &["commit", "-q", "--allow-empty", "-m", message],
        )
    }

    fn open(&self) -> String {
        String::from_utf8(self.run(KAIRN, &["open", "HEAD"]).stdout).unwrap()
    }

    fn log(&self) -> String {
        String::from_utf8(self.run("git", &["log", "--format=%B"]).stdout).unwrap()
    }
}

#[test]
fn committed_session_url_is_sealed_and_opens() {
    let sandbox = Sandbox::new();
    let commit = sandbox.commit(LOCAL_ENV, &format!("test: seal\n\nClaude-Session: {URL}"));
    assert!(commit.status.success(), "{commit:?}");

    let log = sandbox.log();
    assert!(!log.contains("claude.ai"), "{log}");
    assert!(log.contains("Cairn: "), "{log}");
    assert_eq!(sandbox.open(), format!("{LOCAL}\n{URL}\n"));
}

#[test]
fn session_url_outside_the_trailer_block_opens() {
    let sandbox = Sandbox::new();
    let commit = sandbox.commit(
        &[],
        &format!("test: seal\n\nClaude-Session: {URL}\n\nfooter"),
    );
    assert!(commit.status.success(), "{commit:?}");
    assert_eq!(sandbox.open(), format!("{URL}\n"));
}

#[test]
fn ambient_session_is_appended_and_kept_on_amend() {
    let sandbox = Sandbox::new();
    let bridge = (BRIDGE_ID_VAR, "session_01AbCdEfGhJkMnPqRsTuVwXy");
    let commit = sandbox.commit(&[LOCAL_ENV[0], bridge], "test: seal\n\nbody");
    assert!(commit.status.success(), "{commit:?}");
    let log = sandbox.log();
    assert!(log.starts_with("test: seal\n\nbody\n\nCairn: "), "{log}");
    assert_eq!(sandbox.open(), format!("{LOCAL}\n{URL}\n"));

    let amend = sandbox.try_run_in(
        LOCAL_ENV,
        "git",
        &["commit", "-q", "--allow-empty", "--amend", "--no-edit"],
    );
    assert!(amend.status.success(), "{amend:?}");
    assert_eq!(sandbox.log(), log);
}

#[test]
fn commit_with_a_mismatched_bridge_id_aborts() {
    let sandbox = Sandbox::new();
    let bridge = (BRIDGE_ID_VAR, "session_01AbCdEfGhJkMnPqRsTuVwXz");
    let commit = sandbox.commit(&[bridge], &format!("test: seal\n\nClaude-Session: {URL}"));
    assert!(!commit.status.success());
    assert!(
        !sandbox
            .try_run("git", &["rev-parse", "HEAD"])
            .status
            .success()
    );
}

#[test]
fn commit_with_an_unknown_session_url_aborts() {
    let sandbox = Sandbox::new();
    let commit = sandbox.commit(
        &[],
        "test: seal\n\nClaude-Session: https://example.com/session_abc",
    );
    assert!(!commit.status.success());
    let stderr = String::from_utf8(commit.stderr).unwrap();
    assert!(
        stderr.starts_with("kairn: commit-msg hook rejected the commit: line 3: "),
        "{stderr}"
    );
    assert!(stderr.contains("--no-verify"), "{stderr}");
    assert!(
        !sandbox
            .try_run("git", &["rev-parse", "HEAD"])
            .status
            .success()
    );
}

#[test]
fn commit_with_a_malformed_local_id_aborts() {
    let sandbox = Sandbox::new();
    let commit = sandbox.commit(&[(LOCAL_ID_VAR, "not-a-uuid")], "test: plain");
    assert!(!commit.status.success());
}

#[test]
fn empty_session_variables_are_absent() {
    let sandbox = Sandbox::new();
    let env = [(LOCAL_ID_VAR, ""), (BRIDGE_ID_VAR, "")];
    assert!(sandbox.commit(&env, "test: plain").status.success());
    assert_eq!(sandbox.log(), "test: plain\n\n");
}

#[test]
fn open_fails_on_a_commit_without_cairn() {
    let sandbox = Sandbox::new();
    assert!(sandbox.commit(&[], "test: plain").status.success());
    assert!(!sandbox.try_run(KAIRN, &["open", "HEAD"]).status.success());
}

#[test]
fn help_describes_the_hook() {
    let sandbox = Sandbox::new();
    let help = String::from_utf8(sandbox.run(KAIRN, &["--help"]).stdout).unwrap();
    assert!(
        help.contains("kairn seal <public-key> <message-file>"),
        "{help}"
    );
}
