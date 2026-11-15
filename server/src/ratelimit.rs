//! In-memory token buckets. Enough for one server process; several
//! processes behind a balancer would need these counters in a shared store.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Copy)]
pub struct Rule {
    pub burst: f64,
    pub per_minute: f64,
}

/// Sign-in and sign-up attempts per address.
pub const SIGN_IN_IP: Rule = Rule { burst: 10.0, per_minute: 10.0 };
/// Wrong passwords per account, whatever the address: 5, then one every 3 minutes.
pub const SIGN_IN_ACCOUNT: Rule = Rule { burst: 5.0, per_minute: 1.0 / 3.0 };
pub const SIGN_UP_IP: Rule = Rule { burst: 5.0, per_minute: 5.0 / 60.0 };
pub const TOKEN_IP: Rule = Rule { burst: 30.0, per_minute: 30.0 };
pub const API_DEVICE: Rule = Rule { burst: 120.0, per_minute: 240.0 };
/// Letters per account (confirm an address, reset a password): 3, then one
/// an hour. Nobody needs more, and an unbounded "send it again" button is a
/// way to use this server to flood someone else's inbox.
pub const MAIL_PER_ACCOUNT: Rule = Rule { burst: 3.0, per_minute: 1.0 / 60.0 };
/// Reset requests per address: 5, then one every 6 minutes.
pub const RESET_IP: Rule = Rule { burst: 5.0, per_minute: 1.0 / 6.0 };
/// Codes tried per account. Six digits is a million, so this is the whole
/// strength of the second factor against guessing: 5, then one a minute.
/// 20 tries an hour against 10^6 is a 1 in 50 000 chance over a year.
/// Sign-in codes by email: a few, then one every two minutes.
pub const EMAIL_CODE_SEND: Rule = Rule { burst: 4.0, per_minute: 0.5 };
/// And no more than about twenty a day.
pub const EMAIL_CODE_DAY: Rule = Rule { burst: 20.0, per_minute: 20.0 / 1440.0 };
pub const TOTP_ACCOUNT: Rule = Rule { burst: 5.0, per_minute: 1.0 };

const PRUNE_ABOVE: usize = 50_000;

struct Bucket {
    tokens: f64,
    at: Instant,
}

#[derive(Default)]
pub struct Limits {
    buckets: Mutex<HashMap<(&'static str, String), Bucket>>,
}

impl Limits {
    /// Forgets every bucket, as a restart does.
    pub fn clear(&self) {
        self.buckets.lock().unwrap().clear();
    }

    /// Takes one token; false when the bucket is empty.
    pub fn take(&self, name: &'static str, key: &str, rule: Rule) -> bool {
        self.take_at(name, key, rule, Instant::now())
    }

    /// Looks without taking: used to refuse a sign-in before checking the
    /// password, while only wrong passwords spend tokens.
    pub fn has(&self, name: &'static str, key: &str, rule: Rule) -> bool {
        let now = Instant::now();
        let map = self.buckets.lock().unwrap();
        match map.get(&(name, key.to_owned())) {
            None => true,
            Some(b) => refill(b, rule, now) >= 1.0,
        }
    }

    fn take_at(&self, name: &'static str, key: &str, rule: Rule, now: Instant) -> bool {
        let mut map = self.buckets.lock().unwrap();
        if map.len() > PRUNE_ABOVE {
            // A bucket that has refilled says nothing more than a missing one.
            map.retain(|_, b| refill(b, rule, now) < rule.burst);
        }
        let b = map
            .entry((name, key.to_owned()))
            .or_insert(Bucket { tokens: rule.burst, at: now });
        b.tokens = refill(b, rule, now);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn refill(b: &Bucket, rule: Rule, now: Instant) -> f64 {
    let minutes = now.duration_since(b.at).as_secs_f64() / 60.0;
    (b.tokens + minutes * rule.per_minute).min(rule.burst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn empties_then_refills() {
        let l = Limits::default();
        let rule = Rule { burst: 3.0, per_minute: 1.0 };
        let t0 = Instant::now();
        assert!((0..3).all(|_| l.take_at("t", "a", rule, t0)));
        assert!(!l.take_at("t", "a", rule, t0));
        assert!(l.take_at("t", "b", rule, t0), "keys are separate");
        assert!(l.take_at("t", "a", rule, t0 + Duration::from_secs(61)));
        assert!(!l.take_at("t", "a", rule, t0 + Duration::from_secs(62)));
    }
}
