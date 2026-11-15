//! The two letters this server sends: "confirm your address" and "reset your
//! password", both from `bonjour@rayelinux.com`.
//!
//! There is no SMTP client here and no password anywhere. Mail leaves through
//! a local submission binary (`/usr/sbin/sendmail -i -f <from> -- <to>`), which is what the
//! lab's relay already offers: no TLS code of our own to get wrong, and no
//! credential to keep in a config file or a repository.
//!
//! With `RAYE_ACCOUNT_SENDMAIL` unset -- the default, and what the tests and
//! a developer's machine get -- nothing is sent. The letter goes to an
//! in-memory outbox instead, so a test can read the link it would have
//! mailed, and a prototype cannot quietly mail a stranger.

use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Where mail goes.
#[derive(Clone, Debug)]
pub enum Mailer {
    /// Kept in memory, nothing leaves the process.
    Outbox,
    /// Handed to a local submission binary, argv only, never a shell.
    Sendmail(std::path::PathBuf),
}

/// A letter that was not sent, for tests and local work. Bounded: a long-run
/// prototype must not grow a list of everyone's reset links in memory.
const OUTBOX_MAX: usize = 50;

#[derive(Default)]
pub struct Outbox(Mutex<Vec<Mail>>);

impl Outbox {
    pub fn push(&self, m: Mail) {
        let mut v = self.0.lock().unwrap();
        if v.len() >= OUTBOX_MAX {
            v.remove(0);
        }
        v.push(m);
    }

    pub fn all(&self) -> Vec<Mail> {
        self.0.lock().unwrap().clone()
    }

    pub fn last_to(&self, address: &str) -> Option<Mail> {
        self.0.lock().unwrap().iter().rev().find(|m| m.to == address).cloned()
    }
}

/// An address is put in a header, so it may not carry a line break or
/// anything that could start another header. `normalize_email` has already
/// refused whitespace and control characters; this is the second door, on the
/// side that actually writes the header.
fn header_safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= 254 && !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// An address must name exactly one mailbox: no list separator, no quoted or
/// commented part, no display name.
fn address_safe(s: &str) -> bool {
    header_safe(s) && s.matches('@').count() == 1 && !s.bytes().any(|b| b",;\"()<>[]:\\ ".contains(&b))
}

impl Mailer {
    /// Returns an error only when the local binary could not take the letter.
    /// A caller must not tell the user whether it worked: whether an address
    /// exists is exactly what the answer must not reveal.
    pub fn send(&self, from: &str, m: &Mail, outbox: &Outbox) -> Result<(), String> {
        if !address_safe(&m.to) || !address_safe(from) || !header_safe(&m.subject) {
            return Err("address or subject is not safe for a header".into());
        }
        match self {
            Mailer::Outbox => {
                outbox.push(m.clone());
                Ok(())
            }
            Mailer::Sendmail(path) => {
                use std::io::Write;
                use std::process::{Command, Stdio};
                let letter = format!(
                    "From: Raye <{from}>\r\nTo: {}\r\nSubject: {}\r\n\
                     MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
                     Auto-Submitted: auto-generated\r\n\r\n{}",
                    m.to,
                    m.subject,
                    m.body.replace('\n', "\r\n")
                );
                // The recipient is given on the command line, never read back
                // from the headers. -i: a lone dot in the body is not the end.
                let mut child = Command::new(path)
                    .args(["-i", "-f", from, "--", &m.to])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                child
                    .stdin
                    .take()
                    .ok_or("no stdin")?
                    .write_all(letter.as_bytes())
                    .map_err(|e| e.to_string())?;
                match child.wait().map_err(|e| e.to_string())?.success() {
                    true => Ok(()),
                    false => Err("the submission binary refused the message".into()),
                }
            }
        }
    }
}

/// English and French in one letter: the server does not know which the
/// reader prefers once the browser is gone, and guessing wrong on a password
/// reset is worse than two short paragraphs.
pub fn verify_email_letter(link: &str) -> Mail {
    Mail {
        to: String::new(),
        subject: "Confirm your email address - Confirmez votre adresse".into(),
        body: format!(
            "Hello,\n\n\
             Open this link to confirm this address belongs to your Raye account:\n\n\
             {link}\n\n\
             The link works once and stops working in 24 hours. If you did not\n\
             ask for this, you can ignore this message -- nothing changes.\n\n\
             --\n\n\
             Bonjour,\n\n\
             Ouvrez ce lien pour confirmer que cette adresse est bien celle de\n\
             votre compte Raye :\n\n\
             {link}\n\n\
             Le lien fonctionne une seule fois et expire dans 24 heures. Si vous\n\
             n'avez rien demande, ignorez ce message : rien ne change.\n"
        ),
    }
}

pub fn reset_password_letter(link: &str) -> Mail {
    Mail {
        to: String::new(),
        subject: "Reset your Raye password - Reinitialiser votre mot de passe".into(),
        body: format!(
            "Hello,\n\n\
             Open this link to choose a new password for your Raye account:\n\n\
             {link}\n\n\
             The link works once and stops working in 30 minutes. Every PC signed\n\
             in to the account will ask you to sign in again afterwards.\n\n\
             If you did not ask for this, ignore this message: your password has\n\
             not changed, and nobody learned anything about your account.\n\n\
             Raye never asks for your password inside an application.\n\n\
             --\n\n\
             Bonjour,\n\n\
             Ouvrez ce lien pour choisir un nouveau mot de passe :\n\n\
             {link}\n\n\
             Le lien fonctionne une seule fois et expire dans 30 minutes. Chaque PC\n\
             connecte au compte vous demandera ensuite de vous reconnecter.\n\n\
             Si vous n'avez rien demande, ignorez ce message : votre mot de passe\n\
             n'a pas change.\n\n\
             Raye ne demande jamais ce mot de passe dans une application.\n"
        ),
    }
}

pub fn confirm_signup_letter(link: &str) -> Mail {
    Mail {
        to: String::new(),
        subject: "Finish creating your Raye account - Terminez la creation de votre compte".into(),
        body: format!(
            "Hello,\n\n\
             Open this link to finish creating your Raye account:\n\n\
             {link}\n\n\
             The link works once and stops working in 24 hours. Whoever filled in\n\
             the sign-up form chose the password. If that wasn't you, don't open\n\
             the link: ignore this message and no account is made.\n\n\
             --\n\n\
             Bonjour,\n\n\
             Ouvrez ce lien pour terminer la creation de votre compte Raye :\n\n\
             {link}\n\n\
             Le lien fonctionne une seule fois et expire dans 24 heures. La personne\n\
             qui a rempli le formulaire a choisi le mot de passe. Si ce n'etait pas\n\
             vous, n'ouvrez pas le lien : ignorez ce message, aucun compte n'est cree.\n"
        ),
    }
}

pub fn sign_in_code_letter(code: &str) -> Mail {
    Mail {
        to: String::new(),
        subject: "Your Raye sign-in code - Votre code de connexion Raye".into(),
        body: format!(
            "Hello,\n\n\
             Your code to sign in to your Raye account is:\n\n    {code}\n\n\
             It works once, for 10 minutes. If you are not signing in right now,\n\
             someone has your password: change it from the sign-in page with\n\
             \"Forgot your password?\". Never give this code to anyone.\n\n\
             --\n\n\
             Bonjour,\n\n\
             Votre code pour vous connecter a votre compte Raye :\n\n    {code}\n\n\
             Il fonctionne une seule fois, pendant 10 minutes. Si vous n'etes pas\n\
             en train de vous connecter, quelqu'un connait votre mot de passe :\n\
             changez-le depuis la page de connexion avec \"Mot de passe oublie ?\".\n\
             Ne donnez jamais ce code a personne.\n"
        ),
    }
}

/// Sent when a reset is started with the authenticator app or a passkey,
/// which needs no mailbox: the owner hears of it anyway.
pub fn reset_started_letter() -> Mail {
    Mail {
        to: String::new(),
        subject: "A password reset was started - Reinitialisation du mot de passe".into(),
        body: "Hello,\n\n\
             Someone proved they are you with your authenticator app or a passkey\n\
             and is choosing a new password for your Raye account.\n\n\
             If it wasn't you, your phone or passkey may be in someone else's hands:\n\
             reset your password from the sign-in page, then remove that device\n\
             from Security on account.rayelinux.com.\n\n\
             --\n\n\
             Bonjour,\n\n\
             Quelqu'un a prouve etre vous avec votre application d'authentification\n\
             ou une cle d'acces, et choisit un nouveau mot de passe pour votre\n\
             compte Raye.\n\n\
             Si ce n'etait pas vous, reinitialisez votre mot de\n\
             passe depuis la page de connexion, puis retirez cet appareil dans\n\
             Securite sur account.rayelinux.com.\n"
            .into(),
    }
}

/// Sent instead of a confirmation when the address already has an account,
/// so the sign-up page can say the same thing in both cases.
pub fn already_registered_letter(reset_link: &str) -> Mail {
    Mail {
        to: String::new(),
        subject: "You already have a Raye account - Vous avez deja un compte Raye".into(),
        body: format!(
            "Hello,\n\n\
             Someone tried to create a Raye account with this address. There is\n\
             already one. Sign in with it, or choose a new password here:\n\n\
             {reset_link}\n\n\
             If it wasn't you, ignore this message: nothing changed.\n\n\
             --\n\n\
             Bonjour,\n\n\
             Quelqu'un a essaye de creer un compte Raye avec cette adresse. Il en\n\
             existe deja un. Connectez-vous avec, ou choisissez un nouveau mot de\n\
             passe ici :\n\n\
             {reset_link}\n\n\
             Si ce n'etait pas vous, ignorez ce message : rien n'a change.\n"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outbox_keeps_the_last_letter_for_an_address() {
        let o = Outbox::default();
        let m = Mailer::Outbox;
        for i in 0..3 {
            let mut mail = verify_email_letter(&format!("https://x/verify-email?token=t{i}"));
            mail.to = "ana@example.com".into();
            m.send("bonjour@rayelinux.com", &mail, &o).unwrap();
        }
        assert!(o.last_to("ana@example.com").unwrap().body.contains("token=t2"));
        assert!(o.last_to("nobody@example.com").is_none());
        assert_eq!(o.all().len(), 3);
    }

    #[test]
    fn the_outbox_is_bounded() {
        let o = Outbox::default();
        for i in 0..OUTBOX_MAX + 20 {
            o.push(Mail { to: format!("{i}@x.test"), subject: String::new(), body: String::new() });
        }
        assert_eq!(o.all().len(), OUTBOX_MAX);
        // The oldest went, the newest stayed.
        assert!(o.last_to("0@x.test").is_none());
        assert!(o.last_to(&format!("{}@x.test", OUTBOX_MAX + 19)).is_some());
    }

    #[test]
    fn an_address_cannot_smuggle_a_header() {
        let o = Outbox::default();
        let m = Mailer::Outbox;
        let mut mail = verify_email_letter("https://x/verify-email?token=t");
        mail.to = "ana@example.com\r\nBcc: thief@example.net".into();
        assert!(m.send("bonjour@rayelinux.com", &mail, &o).is_err());
        assert!(o.all().is_empty(), "nothing was queued");
        mail.to = "ana@example.com".into();
        assert!(m.send("bonjour@rayelinux.com\nX: y", &mail, &o).is_err(), "the sender too");
        mail.subject = "hi\r\nBcc: thief@example.net".into();
        assert!(m.send("bonjour@rayelinux.com", &mail, &o).is_err(), "and the subject");
    }

    #[test]
    fn one_letter_goes_to_one_address() {
        let o = Outbox::default();
        let m = Mailer::Outbox;
        let mut mail = verify_email_letter("https://x/verify-email?token=t");
        for to in ["a@x.com,b@y.com", "a@x.com;b@y.com", "\"a\" <a@x.com>", "a@x.com (b@y.com)"] {
            mail.to = to.into();
            assert!(m.send("bonjour@rayelinux.com", &mail, &o).is_err(), "{to}");
        }
        assert!(o.all().is_empty());
    }

    #[test]
    fn both_letters_carry_the_link_in_both_languages() {
        for mail in [
            verify_email_letter("https://a/x?token=K"),
            reset_password_letter("https://a/x?token=K"),
            confirm_signup_letter("https://a/x?token=K"),
            already_registered_letter("https://a/x?token=K"),
        ] {
            assert_eq!(mail.body.matches("https://a/x?token=K").count(), 2, "once per language");
            assert!(mail.body.contains("Hello,") && mail.body.contains("Bonjour,"));
            // Someone who did not ask for this must be told that ignoring it
            // is safe -- otherwise the letter reads like a break-in.
            assert!(mail.body.contains("ignore this message"), "{}", mail.subject);
            assert!(mail.body.contains("ignorez ce message"), "{}", mail.subject);
        }
    }
}
