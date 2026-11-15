// Passkeys on the account website. Everything else on these pages works
// without this file.
"use strict";

(function () {
  if (!window.PublicKeyCredential || !navigator.credentials) return;

  function b64(buf) {
    let s = "";
    new Uint8Array(buf).forEach(function (b) { s += String.fromCharCode(b); });
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function unb64(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  async function post(url, body, csrf) {
    const headers = { "Content-Type": "application/json" };
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const res = await fetch(url, { method: "POST", headers: headers, body: JSON.stringify(body || {}), credentials: "same-origin" });
    if (!res.ok) throw new Error(String(res.status));
    return res.json();
  }

  function fail(button) {
    const box = button.parentElement.querySelector(".error");
    if (box) box.hidden = false;
    if (box) box.textContent = document.documentElement.lang === "fr"
      ? "La clé d'accès n'a pas fonctionné. Réessayez."
      : "The passkey didn't work. Try again.";
    button.disabled = false;
  }

  async function signIn(button, kind) {
    button.disabled = true;
    try {
      const start = await post("/signin/passkey/" + kind);
      const o = start.options.publicKey;
      o.challenge = unb64(o.challenge);
      (o.allowCredentials || []).forEach(function (c) { c.id = unb64(c.id); });
      const cred = await navigator.credentials.get({ publicKey: o });
      const r = cred.response;
      const done = await post(kind === "reset" ? "/reset-password/passkey" : "/signin/passkey/finish", {
        ceremony: start.ceremony,
        next: button.dataset.next || "",
        credential: {
          id: cred.id,
          rawId: b64(cred.rawId),
          type: cred.type,
          extensions: cred.getClientExtensionResults(),
          response: {
            authenticatorData: b64(r.authenticatorData),
            clientDataJSON: b64(r.clientDataJSON),
            signature: b64(r.signature),
            userHandle: r.userHandle ? b64(r.userHandle) : null,
          },
        },
      });
      location.assign(done.next);
    } catch (e) {
      fail(button);
    }
  }

  async function register(button) {
    const csrf = document.querySelector("main[data-csrf]").dataset.csrf;
    const name = document.getElementById("pkname").value;
    button.disabled = true;
    try {
      const start = await post("/account/security/passkeys/start", {}, csrf);
      const o = start.options.publicKey;
      o.challenge = unb64(o.challenge);
      o.user.id = unb64(o.user.id);
      (o.excludeCredentials || []).forEach(function (c) { c.id = unb64(c.id); });
      const cred = await navigator.credentials.create({ publicKey: o });
      const done = await post("/account/security/passkeys/finish", {
        ceremony: start.ceremony,
        name: name,
        credential: {
          id: cred.id,
          rawId: b64(cred.rawId),
          type: cred.type,
          extensions: cred.getClientExtensionResults(),
          response: {
            attestationObject: b64(cred.response.attestationObject),
            clientDataJSON: b64(cred.response.clientDataJSON),
          },
        },
      }, csrf);
      location.assign(done.next);
    } catch (e) {
      // A sign-in from a while ago: prove the password again first.
      if (e.message === "403") { location.assign("/signin?next=/account/security"); return; }
      fail(button);
    }
  }

  document.querySelectorAll("[data-passkey]").forEach(function (button) {
    const kind = button.dataset.passkey;
    if (kind === "register") {
      button.parentElement.hidden = false;
      document.querySelectorAll(".nojs").forEach(function (n) { n.hidden = true; });
      button.addEventListener("click", function () { register(button); });
    } else {
      button.hidden = false;
      button.addEventListener("click", function () { signIn(button, kind); });
    }
  });
})();
