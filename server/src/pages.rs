//! The account website's pages: sign in and create an account. Plain HTML,
//! no script, so the page that takes the password runs nothing it did not
//! need to.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

use crate::oauth::Flow;
use crate::Shared;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    En,
    Fr,
}

impl Lang {
    pub fn from_accept_language(v: &str) -> Lang {
        // The first language the browser names decides; good enough for two.
        match v.split(',').next().map(|s| s.trim().to_ascii_lowercase()) {
            Some(s) if s.starts_with("fr") => Lang::Fr,
            _ => Lang::En,
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Lang {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        // The switch in the top bar wins over the browser's languages.
        let chosen = parts.headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).find_map(|v| {
            v.split(';').filter_map(|p| p.trim().strip_prefix("raye_lang=")).next().map(str::to_owned)
        });
        match chosen.as_deref() {
            Some("fr") => return Ok(Lang::Fr),
            Some("en") => return Ok(Lang::En),
            _ => {}
        }
        Ok(parts
            .headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .map(Lang::from_accept_language)
            .unwrap_or(Lang::En))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    SignIn,
    SignUp,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Msg {
    BadLink,
    Expired,
    TooMany,
    BadEmail,
    NeedName,
    ShortPassword,
    WrongPassword,
    /// One message for every way a confirmation link can be refused -- spent,
    /// expired, unknown, someone else's. Which one it was goes to the log:
    /// telling whoever holds a link what is wrong with it only helps if that
    /// is not the person it was sent to.
    VerifyBad,
    VerifyDone,
    /// The same answer whether or not the address has an account.
    ResetSent,
    ResetBad,
    ResetDone,
    PasswordsDiffer,
    BadCode,
    SignUpSent,
    SignUpDone,
    BadEmailCode,
    CodeResent,
    ResetAppBad,
}

fn msg(lang: Lang, m: Msg) -> &'static str {
    use Lang::*;
    use Msg::*;
    match (m, lang) {
        (BadLink, En) => "This sign-in link doesn't work. Start again from your PC.",
        (BadLink, Fr) => "Ce lien de connexion ne fonctionne pas. Recommencez depuis votre PC.",
        (Expired, En) => "This page was open too long. Start again from your PC.",
        (Expired, Fr) => "Cette page est restée ouverte trop longtemps. Recommencez depuis votre PC.",
        (TooMany, En) => "Too many tries. Wait a few minutes and try again.",
        (TooMany, Fr) => "Trop de tentatives. Attendez quelques minutes, puis réessayez.",
        (BadEmail, En) => "Enter a valid email address.",
        (BadEmail, Fr) => "Entrez une adresse e-mail valide.",
        (NeedName, En) => "Enter your name.",
        (NeedName, Fr) => "Entrez votre nom.",
        (ShortPassword, En) => "Use at least 10 characters for your password.",
        (ShortPassword, Fr) => "Utilisez au moins 10 caractères pour votre mot de passe.",
        (WrongPassword, En) => "That email or password isn't right.",
        (WrongPassword, Fr) => "L'adresse e-mail ou le mot de passe est incorrect.",
        (VerifyBad, En) => "This confirmation link doesn't work any more. Ask for a new one from Settings on your PC.",
        (VerifyBad, Fr) => "Ce lien de confirmation ne fonctionne plus. Demandez-en un nouveau depuis les Réglages de votre PC.",
        (VerifyDone, En) => "Your email address is confirmed. You can close this tab.",
        (VerifyDone, Fr) => "Votre adresse e-mail est confirmée. Vous pouvez fermer cet onglet.",
        (ResetSent, En) => "If there's a Raye account with that address, a link is on its way. It works once and lasts 30 minutes.",
        (ResetSent, Fr) => "S'il existe un compte Raye avec cette adresse, un lien est en route. Il fonctionne une seule fois et expire dans 30 minutes.",
        (ResetBad, En) => "This link doesn't work any more. Ask for a new one.",
        (ResetBad, Fr) => "Ce lien ne fonctionne plus. Demandez-en un nouveau.",
        (ResetDone, En) => "Your password is changed. Every PC signed in to the account will ask you to sign in again.",
        (ResetDone, Fr) => "Votre mot de passe est changé. Chaque PC connecté au compte vous demandera de vous reconnecter.",
        (PasswordsDiffer, En) => "The two passwords are not the same.",
        (PasswordsDiffer, Fr) => "Les deux mots de passe ne sont pas identiques.",
        (BadCode, En) => "That code isn't right. Check your authenticator app, or use a recovery code.",
        (SignUpSent, En) => "Check your email. Open the link we sent to finish creating your account: it works for 24 hours. Then come back here and sign in.",
        (SignUpSent, Fr) => "Consultez vos e-mails. Ouvrez le lien envoyé pour terminer la création de votre compte : il fonctionne pendant 24 heures. Revenez ensuite ici pour vous connecter.",
        (SignUpDone, En) => "Your Raye account is ready. Go back to your PC and sign in.",
        (SignUpDone, Fr) => "Votre compte Raye est prêt. Retournez sur votre PC et connectez-vous.",
        (BadEmailCode, En) => "That code isn't right, or it has expired. Check the last email we sent, or send a new code.",
        (BadEmailCode, Fr) => "Ce code est incorrect ou a expiré. Vérifiez le dernier e-mail reçu, ou envoyez un nouveau code.",
        (CodeResent, En) => "A new code is on its way. The previous one no longer works.",
        (CodeResent, Fr) => "Un nouveau code est en route. Le précédent ne fonctionne plus.",
        (ResetAppBad, En) => "That didn't work. Check the address and the code from your authenticator app.",
        (ResetAppBad, Fr) => "Cela n'a pas fonctionné. Vérifiez l'adresse et le code de votre application d'authentification.",
        (BadCode, Fr) => "Ce code est incorrect. Vérifiez votre application d'authentification, ou utilisez un code de secours.",
    }
}

struct Words {
    title_in: &'static str,
    title_up: &'static str,
    lead_in: &'static str,
    lead_up: &'static str,
    email: &'static str,
    password: &'static str,
    name: &'static str,
    submit_in: &'static str,
    submit_up: &'static str,
    switch_to_up: &'static str,
    switch_to_up_link: &'static str,
    switch_to_in: &'static str,
    switch_to_in_link: &'static str,
    password_hint: &'static str,
    problem_title: &'static str,
    footer: &'static str,
    forgot: &'static str,
    reset_title: &'static str,
    reset_lead: &'static str,
    reset_submit: &'static str,
    new_password: &'static str,
    new_password_again: &'static str,
    set_password: &'static str,
    verify_title: &'static str,
    verify_lead: &'static str,
    verify_submit: &'static str,
    totp_title: &'static str,
    totp_lead: &'static str,
    totp_label: &'static str,
    totp_submit: &'static str,
    done_title: &'static str,
}

fn words(lang: Lang) -> Words {
    match lang {
        Lang::En => Words {
            title_in: "Sign in",
            title_up: "Create your Raye account",
            lead_in: "Use your Raye account on this PC.",
            lead_up: "One account for your settings, apps and devices.",
            email: "Email",
            password: "Password",
            name: "Your name",
            submit_in: "Sign in",
            submit_up: "Create account",
            switch_to_up: "No account?",
            switch_to_up_link: "Create one",
            switch_to_in: "Already have an account?",
            switch_to_in_link: "Sign in",
            password_hint: "At least 10 characters.",
            problem_title: "Something's wrong",
            footer: "Raye never asks for this password inside an app.",
            forgot: "Forgot your password?",
            reset_title: "Reset your password",
            reset_lead: "Enter the address of your Raye account and a link will be sent to it.",
            reset_submit: "Send the link",
            new_password: "New password",
            new_password_again: "New password again",
            set_password: "Change my password",
            verify_title: "Confirm your email address",
            verify_lead: "Confirm that this address belongs to your Raye account.",
            verify_submit: "Confirm this address",
            totp_title: "Two-step verification",
            totp_lead: "Enter the 6-digit code from your authenticator app, or one of your recovery codes.",
            totp_label: "Code",
            totp_submit: "Continue",
            done_title: "Raye account",
        },
        Lang::Fr => Words {
            title_in: "Se connecter",
            title_up: "Créer votre compte Raye",
            lead_in: "Utilisez votre compte Raye sur ce PC.",
            lead_up: "Un seul compte pour vos paramètres, vos applications et vos appareils.",
            email: "Adresse e-mail",
            password: "Mot de passe",
            name: "Votre nom",
            submit_in: "Se connecter",
            submit_up: "Créer le compte",
            switch_to_up: "Pas de compte ?",
            switch_to_up_link: "Créez-en un",
            switch_to_in: "Vous avez déjà un compte ?",
            switch_to_in_link: "Se connecter",
            password_hint: "Au moins 10 caractères.",
            problem_title: "Un problème est survenu",
            footer: "Raye ne demande jamais ce mot de passe dans une application.",
            forgot: "Mot de passe oublié ?",
            reset_title: "Réinitialiser votre mot de passe",
            reset_lead: "Entrez l'adresse de votre compte Raye : un lien y sera envoyé.",
            reset_submit: "Envoyer le lien",
            new_password: "Nouveau mot de passe",
            new_password_again: "Nouveau mot de passe, encore",
            set_password: "Changer mon mot de passe",
            verify_title: "Confirmer votre adresse e-mail",
            verify_lead: "Confirmez que cette adresse est bien celle de votre compte Raye.",
            verify_submit: "Confirmer cette adresse",
            totp_title: "Vérification en deux étapes",
            totp_lead: "Entrez le code à 6 chiffres de votre application d'authentification, ou un de vos codes de secours.",
            totp_label: "Code",
            totp_submit: "Continuer",
            done_title: "Compte Raye",
        },
    }
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn page(app: &Shared, lang: Lang, title: &str, body: &str, status: StatusCode) -> Response {
    page_with(app, lang, title, body, status, false)
}

/// `script` only for the reset page, where a passkey can stand in for the
/// link: the sign-in pages for the desktop run nothing.
fn page_with(app: &Shared, lang: Lang, title: &str, body: &str, status: StatusCode, script: bool) -> Response {
    let html = format!(
        "<!doctype html>\n<html lang=\"{lang}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\">\
         <title>{title} - Raye</title><link rel=\"stylesheet\" href=\"/static/account.css\">\
         {js}</head>\
         <body class=\"site\">{bar}<main class=\"card\">{body}</main></body></html>",
        lang = if lang == Lang::Fr { "fr" } else { "en" },
        title = escape(title),
        bar = flow_bar(lang),
        js = if script { "<script src=\"/static/account.js\" defer></script>" } else { "" },
    );
    let mut res = (status, Html(html)).into_response();
    let h = res.headers_mut();
    let upgrade = if app.config.https { "; upgrade-insecure-requests" } else { "" };
    // form-action has to name the loopback callback: browsers apply it to
    // the redirect that follows the form too.
    let js = if script { "script-src 'self'; connect-src 'self'; " } else { "" };
    // Only the desktop sign-in posts to the loopback callback.
    let forms = if script { "'self'" } else { "'self' http://127.0.0.1:*" };
    let csp = format!(
        "default-src 'none'; {js}style-src 'self'; img-src 'self'; \
         form-action {forms}; \
         frame-ancestors 'none'; base-uri 'none'{upgrade}"
    );
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&csp).unwrap());
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// The top bar on the sign-in and link pages: the eye and the language.
/// No account menu: these pages are the way in.
fn flow_bar(lang: Lang) -> String {
    let (code, name, brand) = if lang == Lang::Fr { ("en", "English", "Compte Raye") } else { ("fr", "Français", "Raye account") };
    format!(
        "<header class=\"bar\"><span class=\"brand\"><img src=\"/static/raye-eye.png\" alt=\"\" width=\"28\" height=\"28\">\
         <span>{brand}</span></span><nav class=\"tools\"><a class=\"lang\" href=\"/lang/{code}?back=/signin\" lang=\"{code}\">{name}</a></nav></header>"
    )
}

pub fn problem(app: &Shared, lang: Lang, m: Msg) -> Response {
    let w = words(lang);
    let body = format!("<h1>{}</h1><p class=\"lead\">{}</p>", w.problem_title, msg(lang, m));
    page(app, lang, w.problem_title, &body, StatusCode::BAD_REQUEST)
}

pub struct Prefill<'a> {
    pub email: &'a str,
    pub display_name: &'a str,
}

pub fn sign_in(
    app: &Shared,
    lang: Lang,
    flow: &Flow,
    screen: Screen,
    prefill: Prefill,
    error: Option<Msg>,
    status: StatusCode,
) -> Response {
    let w = words(lang);
    let up = screen == Screen::SignUp;
    let hidden = format!(
        "<input type=\"hidden\" name=\"redirect_uri\" value=\"{}\">\
         <input type=\"hidden\" name=\"state\" value=\"{}\">\
         <input type=\"hidden\" name=\"code_challenge\" value=\"{}\">\
         <input type=\"hidden\" name=\"ts\" value=\"{}\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        escape(&flow.redirect_uri),
        escape(&flow.state),
        escape(&flow.code_challenge),
        flow.ts,
        escape(&flow.csrf)
    );
    let switch_query = authorize_link(flow, if up { "signin" } else { "signup" });
    let error_html = error
        .map(|m| format!("<p class=\"error\" role=\"alert\">{}</p>", msg(lang, m)))
        .unwrap_or_default();
    let name_field = if up {
        format!(
            "<label for=\"display_name\">{}</label>\
             <input id=\"display_name\" name=\"display_name\" maxlength=\"64\" autocomplete=\"name\" required value=\"{}\">",
            w.name,
            escape(prefill.display_name)
        )
    } else {
        String::new()
    };
    let password_hint = if up {
        format!("<p class=\"hint\">{}</p>", w.password_hint)
    } else {
        String::new()
    };
    let body = format!(
        "<h1>{title}</h1><p class=\"lead\">{lead}</p>{error_html}\
         <form method=\"post\" action=\"/oauth/authorize\">{hidden}\
         <input type=\"hidden\" name=\"action\" value=\"{action}\">{name_field}\
         <label for=\"email\">{email}</label>\
         <input id=\"email\" name=\"email\" type=\"email\" maxlength=\"254\" autocomplete=\"username\" required value=\"{email_value}\">\
         <label for=\"password\">{password}</label>\
         <input id=\"password\" name=\"password\" type=\"password\" maxlength=\"1024\" autocomplete=\"{pw_auto}\" required>\
         {password_hint}<button type=\"submit\">{submit}</button></form>\
         {forgot_html}\
         <p class=\"switch\">{switch} <a href=\"{switch_query}\">{switch_link}</a></p>\
         <p class=\"footer\">{footer}</p>",
        title = if up { w.title_up } else { w.title_in },
        lead = if up { w.lead_up } else { w.lead_in },
        action = if up { "signup" } else { "signin" },
        email = w.email,
        email_value = escape(prefill.email),
        password = w.password,
        pw_auto = if up { "new-password" } else { "current-password" },
        submit = if up { w.submit_up } else { w.submit_in },
        switch = if up { w.switch_to_in } else { w.switch_to_up },
        switch_link = if up { w.switch_to_in_link } else { w.switch_to_up_link },
        footer = w.footer,
        // Only on the sign-in screen: nobody creating an account has a
        // password to have forgotten.
        forgot_html = if up {
            String::new()
        } else {
            format!("<p class=\"switch\"><a href=\"/reset-password\">{}</a></p>", w.forgot)
        },
    );
    page(app, lang, if up { w.title_up } else { w.title_in }, &body, status)
}

fn authorize_link(flow: &Flow, screen: &str) -> String {
    format!(
        "/oauth/authorize?response_type=code&amp;client_id={}&amp;redirect_uri={}&amp;state={}\
         &amp;code_challenge={}&amp;code_challenge_method=S256&amp;screen={}",
        raye_account_common::DESKTOP_CLIENT_ID,
        escape(&urlencode(&flow.redirect_uri)),
        escape(&flow.state),
        escape(&flow.code_challenge),
        screen
    )
}

/// After a sign-up: the same words whether the address was free or taken.
pub fn signup_sent(app: &Shared, lang: Lang, flow: &Flow) -> Response {
    let w = words(lang);
    let body = format!(
        "<h1>{}</h1><p class=\"lead\">{}</p><p class=\"switch\"><a href=\"{}\">{}</a></p>",
        w.title_up,
        msg(lang, Msg::SignUpSent),
        authorize_link(flow, "signin"),
        w.switch_to_in_link
    );
    page(app, lang, w.title_up, &body, StatusCode::OK)
}

/// A page that only says something: a confirmed address, a sent link, a
/// refused link. No form, nothing to submit.
pub fn notice(app: &Shared, lang: Lang, m: Msg, status: StatusCode) -> Response {
    let w = words(lang);
    let title = match m {
        Msg::VerifyDone | Msg::VerifyBad | Msg::SignUpDone => w.verify_title,
        Msg::ResetSent | Msg::ResetDone | Msg::ResetBad => w.reset_title,
        _ => w.done_title,
    };
    let body = format!("<h1>{title}</h1><p class=\"lead\">{}</p>", msg(lang, m));
    page(app, lang, title, &body, status)
}

/// `GET /verify-email?token=…`: a button, so that confirming is a POST.
///
/// Mail scanners and link previewers fetch every URL in a message. If the GET
/// confirmed the address it would also spend the token, and the person who
/// was written to would arrive at a link that no longer works.
pub fn confirm_button(app: &Shared, lang: Lang, token: &str) -> Response {
    let w = words(lang);
    let body = format!(
        "<h1>{}</h1><p class=\"lead\">{}</p>\
         <form method=\"post\" action=\"/verify-email\">\
         <input type=\"hidden\" name=\"token\" value=\"{}\">\
         <button type=\"submit\">{}</button></form>",
        w.verify_title,
        w.verify_lead,
        escape(token),
        w.verify_submit
    );
    page(app, lang, w.verify_title, &body, StatusCode::OK)
}

/// `GET /reset-password`: asks for the address.
pub fn reset_ask(app: &Shared, lang: Lang, error: Option<Msg>, status: StatusCode) -> Response {
    let w = words(lang);
    let body = format!(
        "<h1>{}</h1><p class=\"lead\">{}</p>{}\
         <form method=\"post\" action=\"/reset-password\">\
         <input type=\"hidden\" name=\"action\" value=\"request\">\
         <label for=\"email\">{}</label>\
         <input id=\"email\" name=\"email\" type=\"email\" maxlength=\"254\" autocomplete=\"username\" required>\
         <button type=\"submit\">{}</button></form>\
         <h2>{}</h2><p class=\"hint\">{}</p>\
         <form method=\"post\" action=\"/reset-password\">\
         <input type=\"hidden\" name=\"action\" value=\"app\">\
         <label for=\"email2\">{}</label>\
         <input id=\"email2\" name=\"email\" type=\"email\" maxlength=\"254\" autocomplete=\"username\" required>\
         <label for=\"code\">{}</label>\
         <input id=\"code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" maxlength=\"32\" required>\
         <button type=\"submit\" class=\"secondary\">{}</button></form>\
         <button type=\"button\" class=\"secondary\" data-passkey=\"reset\" hidden>{}</button>\
         <p class=\"footer\">{}</p>",
        w.reset_title,
        w.reset_lead,
        error.map(|m| error_line(lang, m)).unwrap_or_default(),
        w.email,
        w.reset_submit,
        if lang == Lang::Fr { "Ou prouvez que c'est vous" } else { "Or prove it's you" },
        if lang == Lang::Fr {
            "Avec le code de votre application d'authentification, ou avec une clé d'accès."
        } else {
            "With the code from your authenticator app, or with a passkey."
        },
        w.email,
        w.totp_label,
        if lang == Lang::Fr { "Continuer avec l'application" } else { "Continue with the app" },
        if lang == Lang::Fr { "Utiliser une clé d'accès" } else { "Use a passkey" },
        w.footer
    );
    page_with(app, lang, w.reset_title, &body, status, true)
}

/// `GET /reset-password?token=…`: choose the new password.
///
/// The token in the hidden field is the whole authorisation, so there is no
/// separate CSRF token here: a third-party page cannot post this form
/// usefully without already holding the link, and holding the link is the
/// one attack this page cannot defend against -- which is why the link is 32
/// random bytes, single use, and thirty minutes long.
pub fn reset_form(app: &Shared, lang: Lang, token: &str, error: Option<Msg>) -> Response {
    let w = words(lang);
    let status = if error.is_some() { StatusCode::BAD_REQUEST } else { StatusCode::OK };
    let body = format!(
        "<h1>{}</h1>{}\
         <form method=\"post\" action=\"/reset-password\">\
         <input type=\"hidden\" name=\"action\" value=\"set\">\
         <input type=\"hidden\" name=\"token\" value=\"{}\">\
         <label for=\"password\">{}</label>\
         <input id=\"password\" name=\"password\" type=\"password\" maxlength=\"1024\" autocomplete=\"new-password\" required>\
         <label for=\"password2\">{}</label>\
         <input id=\"password2\" name=\"password2\" type=\"password\" maxlength=\"1024\" autocomplete=\"new-password\" required>\
         <p class=\"hint\">{}</p><button type=\"submit\">{}</button></form>\
         <p class=\"footer\">{}</p>",
        w.reset_title,
        error.map(|m| error_line(lang, m)).unwrap_or_default(),
        escape(token),
        w.new_password,
        w.new_password_again,
        w.password_hint,
        w.set_password,
        w.footer
    );
    page(app, lang, w.reset_title, &body, status)
}

/// What a sign-in asks for once the password is right and the account has
/// two-step verification on.
///
/// `stage` is an HMAC the server made *after* checking the password, and it
/// names the account. Without it this page would be a way to try codes
/// against an account whose password nobody knows, so
/// `oauth::authorize_submit` verifies it before it looks at the code at all.
#[allow(clippy::too_many_arguments)]
pub fn totp_form(
    app: &Shared,
    lang: Lang,
    account_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
    ts: i64,
    stage: &str,
    error: Option<Msg>,
    status: StatusCode,
) -> Response {
    let w = words(lang);
    let body = format!(
        "<h1>{}</h1><p class=\"lead\">{}</p>{}\
         <form method=\"post\" action=\"/oauth/authorize\">\
         <input type=\"hidden\" name=\"action\" value=\"totp\">\
         <input type=\"hidden\" name=\"account\" value=\"{}\">\
         <input type=\"hidden\" name=\"redirect_uri\" value=\"{}\">\
         <input type=\"hidden\" name=\"state\" value=\"{}\">\
         <input type=\"hidden\" name=\"code_challenge\" value=\"{}\">\
         <input type=\"hidden\" name=\"ts\" value=\"{ts}\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <label for=\"code\">{}</label>\
         <input id=\"code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" \
         maxlength=\"32\" required autofocus>\
         <button type=\"submit\">{}</button></form>\
         <p class=\"footer\">{}</p>",
        w.totp_title,
        w.totp_lead,
        error.map(|m| error_line(lang, m)).unwrap_or_default(),
        escape(account_id),
        escape(redirect_uri),
        escape(state),
        escape(code_challenge),
        escape(stage),
        w.totp_label,
        w.totp_submit,
        w.footer
    );
    page(app, lang, w.totp_title, &body, status)
}

/// What a second-step screen carries back: the server's proof that the
/// password of this account was just checked for this sign-in.
pub struct Stage<'a> {
    pub account_id: &'a str,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub code_challenge: &'a str,
    pub ts: i64,
    pub mac: &'a str,
}

fn stage_fields(s: &Stage) -> String {
    format!(
        "<input type=\"hidden\" name=\"account\" value=\"{}\">\
         <input type=\"hidden\" name=\"redirect_uri\" value=\"{}\">\
         <input type=\"hidden\" name=\"state\" value=\"{}\">\
         <input type=\"hidden\" name=\"code_challenge\" value=\"{}\">\
         <input type=\"hidden\" name=\"ts\" value=\"{}\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        escape(s.account_id),
        escape(s.redirect_uri),
        escape(s.state),
        escape(s.code_challenge),
        s.ts,
        escape(s.mac)
    )
}

/// The code sent by email, asked after the password.
pub fn email_code_form(app: &Shared, lang: Lang, stage: &Stage, note: Option<Msg>, status: StatusCode) -> Response {
    let (title, lead, label, submit, resend) = match lang {
        Lang::En => (
            "Check your email",
            "We sent a 6-digit code to the address of your Raye account. Enter it to finish signing in.",
            "Code",
            "Sign in",
            "Send a new code",
        ),
        Lang::Fr => (
            "Consultez vos e-mails",
            "Un code à 6 chiffres a été envoyé à l'adresse de votre compte Raye. Entrez-le pour terminer la connexion.",
            "Code",
            "Se connecter",
            "Envoyer un nouveau code",
        ),
    };
    let fields = stage_fields(stage);
    let body = format!(
        "<h1>{title}</h1><p class=\"lead\">{lead}</p>{note}\
         <form method=\"post\" action=\"/oauth/authorize\">\
         <input type=\"hidden\" name=\"action\" value=\"emailcode\">{fields}\
         <label for=\"code\">{label}</label>\
         <input id=\"code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" \
         maxlength=\"12\" required autofocus>\
         <button type=\"submit\">{submit}</button></form>\
         <form method=\"post\" action=\"/oauth/authorize\" class=\"inline\">\
         <input type=\"hidden\" name=\"action\" value=\"emailcode-resend\">{fields}\
         <button type=\"submit\" class=\"link\">{resend}</button></form>\
         <p class=\"footer\">{footer}</p>",
        note = note.map(|m| error_line(lang, m)).unwrap_or_default(),
        footer = words(lang).footer,
    );
    page(app, lang, title, &body, status)
}

fn error_line(lang: Lang, m: Msg) -> String {
    format!("<p class=\"error\" role=\"alert\">{}</p>", msg(lang, m))
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

const CSS: &str = include_str!("../static/account.css");
const LOGO: &[u8] = include_bytes!("../static/raye-eye.png");

pub async fn css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8"), (header::CACHE_CONTROL, "public, max-age=86400")], CSS)
}

pub async fn logo() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "public, max-age=86400")], LOGO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html() {
        assert_eq!(escape("<a href=\"x\">'&'</a>"), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
    }

    #[test]
    fn picks_language() {
        assert_eq!(Lang::from_accept_language("fr-CA,fr;q=0.9,en;q=0.8"), Lang::Fr);
        assert_eq!(Lang::from_accept_language("en-US,fr;q=0.5"), Lang::En);
        assert_eq!(Lang::from_accept_language(""), Lang::En);
    }

    #[test]
    fn encodes_redirect() {
        assert_eq!(urlencode("http://127.0.0.1:5000/callback"), "http%3A%2F%2F127.0.0.1%3A5000%2Fcallback");
    }
}
