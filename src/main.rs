use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypto_box::aead::OsRng;
use crypto_box::{PublicKey, SecretKey};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const SESSION_TRAILER: &str = "Claude-Session:";
const SESSION_URL_PREFIX: &str = "https://claude.ai/code/session_";
const CAIRN_TRAILER: &str = "Cairn: ";
const BRAILLE_BASE: u32 = 0x2800;
const SECRET_KEY_FILE: &str = "secret.key";
const USAGE: &str =
    "usage: kairn keygen | kairn seal <public-key> <message-file> | kairn open <rev>";

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["keygen"] => println!("{}", encode_key(keygen(&kairn_dir()?)?.as_bytes())),
        ["seal", key, path] => {
            let key = PublicKey::from(decode_key(key)?);
            let path = Path::new(path);
            let message = at(path, fs::read_to_string(path))?;
            at(path, fs::write(path, seal_message(&key, &message)?))?;
        }
        ["open", rev] => {
            let key = read_secret_key(&kairn_dir()?)?;
            for url in open_commit(&key, rev)? {
                println!("{url}");
            }
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn at<T>(path: &Path, result: io::Result<T>) -> Result<T> {
    result.map_err(|e| format!("{}: {e}", path.display()).into())
}

fn kairn_dir() -> Result<PathBuf> {
    let config = match env::var_os("XDG_CONFIG_HOME").filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env::var_os("HOME").ok_or("HOME is unset")?).join(".config"),
    };
    Ok(config.join("kairn"))
}

fn encode_key(key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

fn decode_key(text: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(URL_SAFE_NO_PAD.decode(text)?).map_err(|_| "key must be 32 bytes".into())
}

fn keygen(dir: &Path) -> Result<PublicKey> {
    let secret = SecretKey::generate(&mut OsRng);
    at(dir, fs::create_dir_all(dir))?;
    let path = dir.join(SECRET_KEY_FILE);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path);
    at(
        &path,
        writeln!(at(&path, file)?, "{}", encode_key(&secret.to_bytes())),
    )?;
    Ok(secret.public_key())
}

fn read_secret_key(dir: &Path) -> Result<SecretKey> {
    let path = dir.join(SECRET_KEY_FILE);
    let text = at(&path, fs::read_to_string(&path))?;
    Ok(SecretKey::from(decode_key(text.trim())?))
}

fn seal_message(key: &PublicKey, message: &str) -> Result<String> {
    let mut sealed = String::with_capacity(message.len());
    for line in message.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        let Some(value) = body
            .get(..SESSION_TRAILER.len())
            .filter(|key| key.eq_ignore_ascii_case(SESSION_TRAILER))
            .map(|_| &body[SESSION_TRAILER.len()..])
        else {
            sealed.push_str(line);
            continue;
        };
        let id = value
            .trim()
            .strip_prefix(SESSION_URL_PREFIX)
            .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
            .ok_or_else(|| format!("unknown session URL:{value}"))?;
        sealed.push_str(CAIRN_TRAILER);
        sealed.push_str(&seal_session(key, id)?);
        sealed.push_str(&line[body.len()..]);
    }
    Ok(sealed)
}

fn seal_session(key: &PublicKey, id: &str) -> Result<String> {
    Ok(key
        .seal(&mut OsRng, id.as_bytes())?
        .into_iter()
        .map(|b| char::from_u32(BRAILLE_BASE + u32::from(b)).unwrap())
        .collect())
}

fn open_session(key: &SecretKey, value: &str) -> Result<String> {
    let sealed = value
        .chars()
        .map(|c| {
            u32::from(c)
                .checked_sub(BRAILLE_BASE)
                .and_then(|b| u8::try_from(b).ok())
                .ok_or_else(|| format!("not a braille pattern: {c:?}"))
        })
        .collect::<std::result::Result<Vec<u8>, _>>()?;
    let id = String::from_utf8(key.unseal(&sealed)?)?;
    Ok(format!("{SESSION_URL_PREFIX}{id}"))
}

fn open_commit(key: &SecretKey, rev: &str) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args([
            "log",
            "-1",
            "--format=%(trailers:key=Cairn,valueonly)",
            "--end-of-options",
            rev,
        ])
        // A partial clone would otherwise fetch a missing commit over the network.
        .env("GIT_NO_LAZY_FETCH", "1")
        .stderr(Stdio::inherit())
        .output()?;
    if !output.status.success() {
        return Err(format!("git log exited with {}", output.status).into());
    }
    let urls = String::from_utf8(output.stdout)?
        .lines()
        .filter(|line| !line.is_empty())
        .map(|value| open_session(key, value))
        .collect::<Result<Vec<_>>>()?;
    if urls.is_empty() {
        return Err(format!("{rev} has no Cairn trailer").into());
    }
    Ok(urls)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const URL: &str = "https://claude.ai/code/session_01AbCdEfGhJkMnPqRsTuVwXy";
    const ID: &str = "01AbCdEfGhJkMnPqRsTuVwXy";

    #[test]
    fn sealed_session_opens_to_its_url() {
        let secret = SecretKey::generate(&mut OsRng);
        let value = seal_session(&secret.public_key(), ID).unwrap();
        assert_eq!(value.chars().count(), 72);
        assert_eq!(open_session(&secret, &value).unwrap(), URL);
        assert_ne!(seal_session(&secret.public_key(), ID).unwrap(), value);
    }

    #[test]
    fn sealed_session_does_not_open_with_another_key() {
        let value = seal_session(&SecretKey::generate(&mut OsRng).public_key(), ID).unwrap();
        assert!(open_session(&SecretKey::generate(&mut OsRng), &value).is_err());
    }

    #[test]
    fn seal_message_rewrites_only_the_session_trailer() {
        let secret = SecretKey::generate(&mut OsRng);
        let head = "fix: x\n\nbody\n\nCo-Authored-By: C <c@example.com>\n";
        let message = format!("{head}{SESSION_TRAILER} {URL}\r\n");
        let sealed = seal_message(&secret.public_key(), &message).unwrap();
        let value = sealed
            .strip_prefix(head)
            .and_then(|tail| tail.strip_prefix(CAIRN_TRAILER))
            .and_then(|tail| tail.strip_suffix("\r\n"))
            .unwrap();
        assert_eq!(open_session(&secret, value).unwrap(), URL);
    }

    #[test]
    fn seal_message_matches_the_trailer_key_in_any_case() {
        let key = SecretKey::generate(&mut OsRng).public_key();
        for trailer in ["claude-session:", "CLAUDE-SESSION:"] {
            let sealed = seal_message(&key, &format!("fix: x\n\n{trailer} {URL}\n")).unwrap();
            assert!(!sealed.contains(URL), "{sealed}");
        }
    }

    #[test]
    fn seal_message_keeps_a_message_without_the_trailer() {
        let message = "fix: x\n\nCairn: \u{2801}\n";
        let key = SecretKey::generate(&mut OsRng).public_key();
        assert_eq!(seal_message(&key, message).unwrap(), message);
    }

    #[test]
    fn seal_message_rejects_an_unknown_session_url() {
        let key = SecretKey::generate(&mut OsRng).public_key();
        for value in [
            "https://example.com/session_abc",
            SESSION_URL_PREFIX,
            "https://claude.ai/code/session_a/b",
        ] {
            assert!(seal_message(&key, &format!("fix: x\n\n{SESSION_TRAILER} {value}\n")).is_err());
        }
    }

    #[test]
    fn keygen_writes_a_private_key_once() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().join("kairn");
        let public = keygen(&dir).unwrap();
        let path = dir.join(SECRET_KEY_FILE);
        let written = fs::read(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(read_secret_key(&dir).unwrap().public_key(), public);

        assert!(keygen(&dir).is_err());
        assert_eq!(fs::read(&path).unwrap(), written);
    }
}
