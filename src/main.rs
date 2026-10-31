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
const CAIRN_TRAILER: &str = "Cairn:";
const LOCAL_ID_VAR: &str = "CLAUDE_CODE_SESSION_ID";
const BRIDGE_ID_VAR: &str = "CLAUDE_CODE_BRIDGE_SESSION_ID";
const BRIDGE_ID_PREFIX: &str = "session_";
const REMOTE_ID_PREFIX: &str = "01";
const REMOTE_ID_DIGITS: usize = 22;
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const UUID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
const V1_PLAINTEXT_LEN: usize = REMOTE_ID_PREFIX.len() + REMOTE_ID_DIGITS;
const V2_PLAINTEXT_LEN: usize = 32;
const BRAILLE_BASE: u32 = 0x2800;
const SECRET_KEY_FILE: &str = "secret.key";
const USAGE: &str =
    "usage: kairn keygen | kairn seal <public-key> <message-file> | kairn open <rev>";

/// Each ID is a nonzero 128-bit value, since a zero half of the v2 plaintext marks an absent ID.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Session {
    local: Option<u128>,
    remote: Option<u128>,
}

impl Session {
    fn from_env() -> Result<Self> {
        Ok(Self {
            local: env_id(LOCAL_ID_VAR, parse_uuid)?,
            remote: env_id(BRIDGE_ID_VAR, |value| {
                value
                    .strip_prefix(BRIDGE_ID_PREFIX)
                    .and_then(parse_remote_id)
            })?,
        })
    }

    fn lines(self) -> impl Iterator<Item = String> {
        self.local.map(format_uuid).into_iter().chain(
            self.remote
                .map(|id| format!("{SESSION_URL_PREFIX}{}", format_remote_id(id))),
        )
    }
}

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
            let ambient = Session::from_env()?;
            let path = Path::new(path);
            let message = at(path, fs::read_to_string(path))?;
            at(
                path,
                fs::write(path, seal_message(&key, &message, ambient)?),
            )?;
        }
        ["open", rev] => {
            let key = read_secret_key(&kairn_dir()?)?;
            for session in open_commit(&key, rev)? {
                for line in session.lines() {
                    println!("{line}");
                }
            }
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn at<T>(path: &Path, result: io::Result<T>) -> Result<T> {
    result.map_err(|e| format!("{}: {e}", path.display()).into())
}

fn env_id(name: &str, parse: impl Fn(&str) -> Option<u128>) -> Result<Option<u128>> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .to_str()
                .and_then(&parse)
                .ok_or_else(|| format!("invalid {name}: {}", value.display()).into())
        })
        .transpose()
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

fn parse_uuid(text: &str) -> Option<u128> {
    // u128::from_str_radix accepts a leading '+', which the digit check rules out.
    let well_formed = text.split('-').map(str::len).eq(UUID_GROUPS)
        && text.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit());
    if !well_formed {
        return None;
    }
    u128::from_str_radix(&text.replace('-', ""), 16)
        .ok()
        .filter(|&id| id != 0)
}

fn format_uuid(id: u128) -> String {
    let hex = format!("{id:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn parse_remote_id(text: &str) -> Option<u128> {
    text.strip_prefix(REMOTE_ID_PREFIX)
        .filter(|digits| digits.len() == REMOTE_ID_DIGITS)?
        .bytes()
        .try_fold(0u128, |id, c| {
            let digit = BASE58.iter().position(|&d| d == c)?;
            id.checked_mul(58)?.checked_add(u128::try_from(digit).ok()?)
        })
        .filter(|&id| id != 0)
}

fn format_remote_id(mut id: u128) -> String {
    let mut digits = [0; REMOTE_ID_DIGITS];
    for digit in digits.iter_mut().rev() {
        *digit = BASE58[usize::try_from(id % 58).unwrap()];
        id /= 58;
    }
    REMOTE_ID_PREFIX
        .chars()
        .chain(digits.iter().map(|&d| char::from(d)))
        .collect()
}

fn seal_message(key: &PublicKey, message: &str, ambient: Session) -> Result<String> {
    let mut sealed = String::with_capacity(message.len());
    let mut has_cairn = false;
    for line in message.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        has_cairn |= trailer_value(body, CAIRN_TRAILER).is_some();
        let Some(value) = trailer_value(body, SESSION_TRAILER) else {
            sealed.push_str(line);
            continue;
        };
        let remote = value
            .trim()
            .strip_prefix(SESSION_URL_PREFIX)
            .and_then(parse_remote_id)
            .ok_or_else(|| format!("unknown session URL:{value}"))?;
        if ambient.remote.is_some_and(|bridge| bridge != remote) {
            return Err(format!("{BRIDGE_ID_VAR} differs from session URL:{value}").into());
        }
        let session = Session {
            remote: Some(remote),
            ..ambient
        };
        sealed.push_str(CAIRN_TRAILER);
        sealed.push(' ');
        sealed.push_str(&seal_session(key, session)?);
        sealed.push_str(&line[body.len()..]);
        has_cairn = true;
    }
    if has_cairn || ambient == Session::default() {
        return Ok(sealed);
    }
    let trailer = format!("{CAIRN_TRAILER} {}", seal_session(key, ambient)?);
    append_trailer(&sealed, &trailer)
}

fn trailer_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.get(..key.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(key))
        .map(|_| &line[key.len()..])
}

fn append_trailer(message: &str, trailer: &str) -> Result<String> {
    let mut child = Command::new("git")
        .args(["interpret-trailers", "--trailer", trailer])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    // git reads the whole message before it writes any output.
    child.stdin.take().unwrap().write_all(message.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!("git interpret-trailers exited with {}", output.status).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn seal_session(key: &PublicKey, session: Session) -> Result<String> {
    let plaintext = [session.local, session.remote].map(|id| id.unwrap_or(0).to_be_bytes());
    Ok(key
        .seal(&mut OsRng, plaintext.as_flattened())?
        .into_iter()
        .map(|b| char::from_u32(BRAILLE_BASE + u32::from(b)).unwrap())
        .collect())
}

fn open_session(key: &SecretKey, value: &str) -> Result<Session> {
    let sealed = value
        .chars()
        .map(|c| {
            u32::from(c)
                .checked_sub(BRAILLE_BASE)
                .and_then(|b| u8::try_from(b).ok())
                .ok_or_else(|| format!("not a braille pattern: {c:?}"))
        })
        .collect::<std::result::Result<Vec<u8>, _>>()?;
    let plaintext = key.unseal(&sealed)?;
    match plaintext.len() {
        V1_PLAINTEXT_LEN => Ok(Session {
            local: None,
            remote: Some(
                parse_remote_id(str::from_utf8(&plaintext)?).ok_or("invalid sealed session ID")?,
            ),
        }),
        V2_PLAINTEXT_LEN => {
            let (local, remote) = plaintext.split_at(V2_PLAINTEXT_LEN / 2);
            let id = |half: &[u8]| {
                Some(u128::from_be_bytes(half.try_into().unwrap())).filter(|&id| id != 0)
            };
            Ok(Session {
                local: id(local),
                remote: id(remote),
            })
        }
        len => Err(format!("unknown plaintext length {len}").into()),
    }
}

fn open_commit(key: &SecretKey, rev: &str) -> Result<Vec<Session>> {
    let output = Command::new("git")
        .args(["log", "-1", "--format=%B", "--end-of-options", rev])
        // A partial clone would otherwise fetch a missing commit over the network.
        .env("GIT_NO_LAZY_FETCH", "1")
        .stderr(Stdio::inherit())
        .output()?;
    if !output.status.success() {
        return Err(format!("git log exited with {}", output.status).into());
    }
    let sessions = String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| trailer_value(line, CAIRN_TRAILER))
        .map(|value| open_session(key, value.trim()))
        .collect::<Result<Vec<_>>>()?;
    if sessions.is_empty() {
        return Err(format!("{rev} has no Cairn line").into());
    }
    Ok(sessions)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const URL: &str = "https://claude.ai/code/session_01AbCdEfGhJkMnPqRsTuVwXy";
    const REMOTE: &str = "01AbCdEfGhJkMnPqRsTuVwXy";
    const LOCAL: &str = "12345678-1234-4abc-8def-0123456789ab";

    fn session() -> Session {
        Session {
            local: parse_uuid(LOCAL),
            remote: parse_remote_id(REMOTE),
        }
    }

    fn cairn_value(line: &str) -> &str {
        line.strip_prefix(CAIRN_TRAILER)
            .and_then(|value| value.strip_prefix(' '))
            .unwrap()
    }

    #[test]
    fn ids_round_trip() {
        assert_eq!(format_uuid(parse_uuid(LOCAL).unwrap()), LOCAL);
        assert_eq!(format_remote_id(parse_remote_id(REMOTE).unwrap()), REMOTE);
        assert_eq!(format_remote_id(u128::MAX).len(), V1_PLAINTEXT_LEN);
        assert_eq!(format_remote_id(1), "011111111111111111111112");
    }

    #[test]
    fn malformed_ids_are_rejected() {
        for text in [
            "",
            "1234567812344abc8def0123456789ab",
            "12345678-1234-4abc-8def-0123456789a",
            "+2345678-1234-4abc-8def-0123456789ab",
            "12345678-1234-4abc-8def-0123456789ag",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert_eq!(parse_uuid(text), None, "{text}");
        }
        for text in [
            "",
            "02AbCdEfGhJkMnPqRsTuVwXy",
            "01AbCdEfGhJkMnPqRsTuVwX",
            "01AbCdEfGhJkMnPqRsTuVwXyz",
            "010bCdEfGhJkMnPqRsTuVwXy",
            "01lbCdEfGhJkMnPqRsTuVwXy",
            "011111111111111111111111",
            "01zzzzzzzzzzzzzzzzzzzzzz",
        ] {
            assert_eq!(parse_remote_id(text), None, "{text}");
        }
    }

    #[test]
    fn sealed_session_opens_with_a_fixed_length() {
        let secret = SecretKey::generate(&mut OsRng);
        let full = session();
        for session in [
            full,
            Session {
                remote: None,
                ..full
            },
            Session {
                local: None,
                ..full
            },
        ] {
            let value = seal_session(&secret.public_key(), session).unwrap();
            assert_eq!(value.chars().count(), 80);
            assert_eq!(open_session(&secret, &value).unwrap(), session);
            assert_ne!(seal_session(&secret.public_key(), session).unwrap(), value);
        }
    }

    #[test]
    fn v1_sealed_session_opens() {
        let secret = SecretKey::generate(&mut OsRng);
        let value: String = secret
            .public_key()
            .seal(&mut OsRng, REMOTE.as_bytes())
            .unwrap()
            .into_iter()
            .map(|b| char::from_u32(BRAILLE_BASE + u32::from(b)).unwrap())
            .collect();
        assert_eq!(value.chars().count(), 72);
        let opened = open_session(&secret, &value).unwrap();
        assert_eq!(opened.lines().collect::<Vec<_>>(), [URL]);
    }

    #[test]
    fn sealed_session_does_not_open_with_another_key() {
        let key = SecretKey::generate(&mut OsRng).public_key();
        let value = seal_session(&key, session()).unwrap();
        assert!(open_session(&SecretKey::generate(&mut OsRng), &value).is_err());
    }

    #[test]
    fn seal_message_rewrites_only_the_session_trailer() {
        let secret = SecretKey::generate(&mut OsRng);
        let ambient = Session {
            remote: None,
            ..session()
        };
        let head = "fix: x\n\nbody\n\nCo-Authored-By: C <c@example.com>\n";
        let message = format!("{head}{SESSION_TRAILER} {URL}\r\n");
        let sealed = seal_message(&secret.public_key(), &message, ambient).unwrap();
        let value = sealed
            .strip_prefix(head)
            .and_then(|tail| tail.strip_suffix("\r\n"))
            .map(cairn_value)
            .unwrap();
        assert_eq!(open_session(&secret, value).unwrap(), session());
    }

    #[test]
    fn seal_message_matches_the_trailer_key_in_any_case() {
        let key = SecretKey::generate(&mut OsRng).public_key();
        for trailer in ["claude-session:", "CLAUDE-SESSION:"] {
            let message = format!("fix: x\n\n{trailer} {URL}\n");
            let sealed = seal_message(&key, &message, Session::default()).unwrap();
            assert!(!sealed.contains(URL), "{sealed}");
        }
    }

    #[test]
    fn seal_message_keeps_a_message_without_a_session() {
        let key = SecretKey::generate(&mut OsRng).public_key();
        let message = "fix: x\n";
        assert_eq!(
            seal_message(&key, message, Session::default()).unwrap(),
            message
        );
    }

    #[test]
    fn seal_message_keeps_a_sealed_message() {
        let key = SecretKey::generate(&mut OsRng).public_key();
        let message = "fix: x\n\ncairn: \u{2801}\n";
        assert_eq!(seal_message(&key, message, session()).unwrap(), message);
    }

    #[test]
    fn seal_message_appends_the_ambient_session() {
        let secret = SecretKey::generate(&mut OsRng);
        let sealed = seal_message(&secret.public_key(), "fix: x\n\nbody\n", session()).unwrap();
        let value = sealed
            .strip_prefix("fix: x\n\nbody\n\n")
            .and_then(|tail| tail.strip_suffix('\n'))
            .map(cairn_value)
            .unwrap();
        assert_eq!(open_session(&secret, value).unwrap(), session());
    }

    #[test]
    fn seal_message_checks_the_bridge_id() {
        let secret = SecretKey::generate(&mut OsRng);
        let message = format!("fix: x\n\n{SESSION_TRAILER} {URL}\n");
        let sealed = seal_message(&secret.public_key(), &message, session()).unwrap();
        let value = cairn_value(sealed.lines().last().unwrap());
        assert_eq!(open_session(&secret, value).unwrap(), session());

        let other = Session {
            remote: Some(parse_remote_id(REMOTE).unwrap() + 1),
            ..session()
        };
        assert!(seal_message(&secret.public_key(), &message, other).is_err());
    }

    #[test]
    fn seal_message_rejects_an_unknown_session_url() {
        let key = SecretKey::generate(&mut OsRng).public_key();
        for value in [
            "https://example.com/session_abc",
            SESSION_URL_PREFIX,
            "https://claude.ai/code/session_a/b",
            "https://claude.ai/code/session_01AbCdEfGhJkMnPqRsTuVwX0",
        ] {
            let message = format!("fix: x\n\n{SESSION_TRAILER} {value}\n");
            assert!(seal_message(&key, &message, Session::default()).is_err());
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
