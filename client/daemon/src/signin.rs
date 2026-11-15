//! Signing in through the browser (RFC 8252): the PC opens the account
//! website with a PKCE challenge, waits on a loopback port for the code, and
//! trades it for tokens. The password is typed on the website only.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use raye_account_common::api::TokenResponse;
use raye_account_common::{pkce, random_token, DESKTOP_CLIENT_ID};

use crate::api::{self, ApiError};
use crate::device::DeviceInfo;
use crate::keyring::Secrets;

// Long enough for a confirmation letter that takes its time.
const WAIT: Duration = Duration::from_secs(30 * 60);

pub struct Pending {
    verifier: String,
    state: String,
    redirect_uri: String,
    listener: TcpListener,
    port: u16,
    cancelled: Arc<AtomicBool>,
}

#[derive(Debug)]
pub enum SignInError {
    Cancelled,
    TimedOut,
    Io(String),
    Api(ApiError),
}

impl std::fmt::Display for SignInError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignInError::Cancelled => f.write_str("cancelled"),
            SignInError::TimedOut => f.write_str("the browser didn't answer in time"),
            SignInError::Io(e) => f.write_str(e),
            SignInError::Api(e) => write!(f, "{e}"),
        }
    }
}

/// Stops a pending sign-in from another thread by waking its accept().
#[derive(Clone)]
pub struct Canceller {
    port: u16,
    flag: Arc<AtomicBool>,
}

impl Canceller {
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

pub fn begin(server: &str, signup: bool) -> std::io::Result<(Pending, String)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let verifier = pkce::new_verifier();
    let state = random_token();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let url = format!(
        "{server}/oauth/authorize?response_type=code&client_id={DESKTOP_CLIENT_ID}&redirect_uri={}\
         &state={state}&code_challenge={}&code_challenge_method=S256{}",
        encode(&redirect_uri),
        pkce::challenge(&verifier),
        if signup { "&screen=signup" } else { "" }
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    Ok((Pending { verifier, state, redirect_uri, listener, port, cancelled }, url))
}

impl Pending {
    pub fn canceller(&self) -> Canceller {
        Canceller { port: self.port, flag: self.cancelled.clone() }
    }

    /// Blocks until the browser comes back with a code, the user cancels,
    /// or ten minutes pass.
    pub fn wait_for_code(&self) -> Result<String, SignInError> {
        let timer = self.canceller();
        let done = Arc::new(AtomicBool::new(false));
        let done_t = done.clone();
        std::thread::spawn(move || {
            std::thread::park_timeout(WAIT);
            if !done_t.load(Ordering::SeqCst) {
                let _ = TcpStream::connect(("127.0.0.1", timer.port));
            }
        });
        let started = std::time::Instant::now();
        let result = loop {
            let (stream, _) = match self.listener.accept() {
                Ok(s) => s,
                Err(e) => break Err(SignInError::Io(e.to_string())),
            };
            if self.cancelled.load(Ordering::SeqCst) {
                break Err(SignInError::Cancelled);
            }
            if started.elapsed() >= WAIT {
                break Err(SignInError::TimedOut);
            }
            if let Some(code) = self.answer(stream) {
                break Ok(code);
            }
        };
        done.store(true, Ordering::SeqCst);
        result
    }

    /// Reads one request; returns the code when it is the right callback.
    fn answer(&self, mut stream: TcpStream) -> Option<String> {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut line = String::new();
        BufReader::new(stream.try_clone().ok()?).take_line(&mut line);
        let target = line.split_whitespace().nth(1).unwrap_or("");
        let code = parse_callback(target, &self.state);
        let (status, body) = match code {
            Some(_) => ("200 OK", done_page()),
            None => ("404 Not Found", String::new()),
        };
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
             Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        code
    }

    pub fn exchange(&self, server: &str, code: &str, device: &DeviceInfo) -> Result<Secrets, SignInError> {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let resp: TokenResponse = api::agent()
            .post(&format!("{server}/v1/oauth/token"))
            .send_form(&[
                ("grant_type", "authorization_code"),
                ("client_id", DESKTOP_CLIENT_ID),
                ("code", code),
                ("redirect_uri", &self.redirect_uri),
                ("code_verifier", &self.verifier),
                ("device_name", &device.name),
                ("device_model", &device.model),
                ("raye_version", &device.raye_version),
                ("device_key", &URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())),
            ])
            .map_err(|e| SignInError::Api(ApiError::Offline(e.to_string())))?
            .into_json()
            .map_err(|e| SignInError::Io(e.to_string()))?;
        Ok(api::token_from(resp, URL_SAFE_NO_PAD.encode(key.to_bytes())))
    }
}

trait TakeLine {
    fn take_line(self, out: &mut String);
}

impl<R: std::io::Read> TakeLine for BufReader<R> {
    fn take_line(self, out: &mut String) {
        // A request line is short; anything longer is not ours.
        let _ = std::io::Read::take(self, 4096).read_line(out);
    }
}

/// "/callback?code=X&state=Y" with the expected state gives Some(X).
pub fn parse_callback(target: &str, want_state: &str) -> Option<String> {
    let query = target.strip_prefix("/callback?")?;
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        match pair.split_once('=') {
            Some(("code", v)) => code = Some(v),
            Some(("state", v)) => state = Some(v),
            _ => {}
        }
    }
    let state = state?;
    let same = state.len() == want_state.len()
        && state.bytes().zip(want_state.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0;
    let code = code?;
    (same && !code.is_empty() && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        .then(|| code.to_owned())
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn done_page() -> String {
    let fr = std::env::var("LANG").is_ok_and(|l| l.starts_with("fr"));
    let (title, text) = if fr {
        ("Vous êtes connecté", "Vous pouvez fermer cet onglet et revenir à Raye.")
    } else {
        ("You're signed in", "You can close this tab and go back to Raye.")
    };
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title>\
         <style>body{{background:#0e0a17;color:#f3eaff;font:16px Inter,sans-serif;display:grid;\
         place-items:center;height:100vh;margin:0}}h1{{font-weight:600;font-size:24px;margin:0 0 8px}}\
         p{{color:#b9a8d6;margin:0}}</style></head><body><main><h1>{title}</h1><p>{text}</p></main></body></html>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_needs_matching_state() {
        let s = "state-0123456789abcdefghij";
        assert_eq!(parse_callback(&format!("/callback?code=abc_DEF-1&state={s}"), s), Some("abc_DEF-1".into()));
        assert_eq!(parse_callback(&format!("/callback?state={s}&code=abc"), s), Some("abc".into()));
        assert_eq!(parse_callback("/callback?code=abc&state=other", s), None);
        assert_eq!(parse_callback(&format!("/callback?state={s}"), s), None);
        assert_eq!(parse_callback(&format!("/favicon.ico?code=abc&state={s}"), s), None);
        assert_eq!(parse_callback(&format!("/callback?code=<x>&state={s}"), s), None);
    }

    #[test]
    fn cancel_wakes_the_wait() {
        let (p, url) = begin("https://account.example", false).unwrap();
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains(&format!("redirect_uri=http%3A%2F%2F127.0.0.1%3A{}%2Fcallback", p.port)));
        let c = p.canceller();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c.cancel();
        });
        assert!(matches!(p.wait_for_code(), Err(SignInError::Cancelled)));
    }

    #[test]
    fn real_callback_over_tcp() {
        let (p, _) = begin("https://account.example", false).unwrap();
        let port = p.port;
        let state = p.state.clone();
        let t = std::thread::spawn(move || {
            let mut other = TcpStream::connect(("127.0.0.1", port)).unwrap();
            other.write_all(b"GET /favicon.ico HTTP/1.1\r\n\r\n").unwrap();
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(s, "GET /callback?code=thecode&state={state} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut resp = String::new();
            std::io::Read::read_to_string(&mut s, &mut resp).unwrap();
            resp
        });
        assert_eq!(p.wait_for_code().unwrap(), "thecode");
        let resp = t.join().unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(resp.contains("go back to Raye") || resp.contains("revenir à Raye"));
    }
}
