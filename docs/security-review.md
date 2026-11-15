# Raye account: security review of the prototype

Reviewed against the OWASP API Security Top 10 (2023), on the code in this
repository (server, common, client). Fixed means fixed in the code and
covered by a test; open means it must be done before real accounts.

## API1 Broken object level authorization

Every query takes the account from the access token, never from the
request: `WHERE account_id = $1` (settings, library, export), device
removal checks `id AND account_id`, `GET /v1/devices/{id}/installs`
checks the device belongs to the caller first.
Test: `removing_a_device_signs_it_out_and_stays_in_the_account` (another
account gets 404 on someone else's device). **No finding.**

## API2 Broken authentication

- Authorization code + PKCE S256 only ("plain" refused), loopback
  redirect on `/callback` only, code 60 s and single use (deleted before
  checking, so two racing redemptions cannot both win). Tests:
  `codes_are_single_use_and_need_the_verifier`,
  `authorize_refuses_foreign_redirects_and_forged_forms`.
- Refresh tokens rotate on every use, are bound to the device's Ed25519
  key (signed proof, 5 min clock window), and a reused one ends the
  device. Test: `refresh_rotates_and_a_reused_token_ends_the_device`.
- Tokens and codes stored as SHA-256; access tokens checked in the
  database each request, so removal is immediate.
- Argon2id, OWASP parameters, run off the async threads with at most two
  at once. Unknown email costs the same hash as a wrong password.
- Rate limits on sign-in per address and per account. Test:
  `wrong_passwords_lock_the_account_for_a_while`.
- **Finding (low, accepted)**: the sign-in form's CSRF token is an HMAC
  over the flow, not bound to a browser cookie, so another site could
  post a form to sign a victim's browser into an attacker's account. The
  code would go to the victim's loopback port with a `state` the victim's
  PC did not make, and the PC drops it. No impact while the only client
  is the desktop app; bind to a cookie if a web client is ever added.
- **Fixed (2026-11-06)**: address confirmation, password reset and TOTP are
  built (design section 6). Each refusal has a test, and each test was proved
  red by breaking the guard it watches - see "Dependencies and proofs" below.
  - confirmation and reset links: 32 random bytes, the row keyed by their
    SHA-256, expiring (24 h / 30 min), spent once via `used_at`, and tied to
    one account. A link presented by another signed-in account is refused,
    and so is one mailed to an address that has since changed.
  - a reset sends every PC back behind the new password (access and refresh
    tokens of the account deleted, codes in flight deleted) while leaving the
    device rows, so the owner can still see and remove them.
  - `GET` on a confirmation link shows a button and changes nothing: mail
    scanners fetch links, and a confirming GET would spend the token before
    the reader ever saw it.
  - TOTP: RFC 6238, drift bounded to ±1 step, and **a step is spent once**
    (`accounts.totp_last_step` only moves forward), so a code is dead the
    moment it is used - and so is every earlier code, not just its own.
    Secret sealed with XChaCha20-Poly1305 under a key from the environment.
  - **Finding (high, fixed during the work)**: the first version put the
    second-stage branch *after* `Flow::verify`, which checks the first
    stage's HMAC. The two screens carry different proofs in the same field,
    so every valid code screen was reported expired. Caught by
    `a_code_is_asked_after_the_password_and_works_once`, not by reading.
    Same family as the extractor-ordering note in the design doc: what runs
    first is rarely what the code looks like it does.
- **Fixed (2026-11-14)**: sign-up needs the address confirmed. A sign-up
  waits in `pending_signups` (password already hashed, 24-hour expiry) and
  the account row is only made when its link is opened, so an unconfirmed
  sign-up cannot sign in, sync, or hold the address: the real owner signs up
  too, confirms first, and the other waiting sign-ups for that address are
  dropped. The page says "check your email" whether the address is free or
  taken; a taken address gets a letter pointing at the reset page instead
  (no link that could make a second account). The password is hashed before
  the lookup so both paths cost the same, and letters are limited per
  address (3, then one an hour) with the same page shown when the limit
  is hit. Sign-in and every API call also refuse an account whose address is
  not confirmed. Tests: `tests/signup.rs`,
  `an_unconfirmed_account_cannot_use_the_api_or_sign_in`.
  Review of the change (2026-11-14), done: an old unconfirmed account no
  longer holds its address (the new sign-up is treated as free and replaces
  it on confirmation); the per-address limit runs before Argon2; index on the
  expiry; the letter says whoever filled the form chose the password; `%`,
  `!`, `|` and `/` refused in the local part. **Left open (medium)**: the
  per-address letter limit can be drained by someone else, and the real
  owner then sees "check your email" with no letter for up to an hour;
  telling them apart would say the address is in use. **Left open (low)**:
  sendmail is waited for on the request's thread.
- **Added (2026-11-14)**: a code sent by email is the second step of every
  sign-in, on by default for accounts without an authenticator app (those
  are asked for the app's code instead). Six digits, one live code per
  account, 10 minutes, five wrong tries and it is gone, compared in
  constant time against an HMAC under the server's in-memory key (a copy of
  the table is not a list of codes; a restart voids the codes in flight).
  The screen carries a MAC made after the password check with its own
  domain ("email"), so it cannot be reached without the password and the
  TOTP screen's proof does not open it. Tries are limited per account and
  per address, new codes 4 then one every 2 minutes. Turning it off needs
  the password again (`POST /v1/me/email-code`). Tests: `tests/emailcode.rs`.
  Review of the change, done before deploying: wrong codes are counted on
  the account across every code sent (10 in an hour closes the step for the
  hour, kept in the database so a restart does not reset it); the screen's
  proof keeps the time of the password check (10 minutes, retries do not
  extend it); a code under a minute old is not replaced, and letters are
  capped at about 20 a day; a refused send says so; turning on the app
  after the password check closes the email screen; the code is in the
  letter, not in its subject (lock-screen previews).
- **Added (2026-11-14)**: the account website (`src/web.rs`). Session in a
  `__Host-` cookie (HttpOnly, Secure, SameSite=Lax), row keyed by SHA-256,
  new token at every sign-in, deleted server-side at sign-out. Every POST
  carries the session's CSRF token, and any POST whose `Origin` is not this
  site is refused before it is read (login CSRF). Sign-in is the password
  then the app's code or the emailed code, or a passkey (webauthn-rs,
  discoverable, user verification required and checked). "Recent" (signed
  in, both steps, in the last 10 minutes) is needed to add or remove a
  second factor or passkey, make new recovery codes, turn the email code
  off, download the data and close the account; changing the password does
  not make a session recent. A password reset, by any path, now signs out
  every browser as well as every PC. Reset can be proven with the
  authenticator app or a passkey instead of the mailed link; the owner is
  mailed when that happens, and wrong app codes are counted on the account
  across every path (10 an hour, kept in the database). Review findings
  fixed before the deploy: H1 (reset left web sessions), H2 (separate,
  volatile guess budgets for the app code), M1 (login CSRF), M2/M6 (adding
  a factor, export and delete without a recent sign-in), M3 (password
  change refreshed "recent"), L1 (language cookie Secure), L2 (UV checked,
  refused assertions logged, a passkey already registered elsewhere is an
  error), L5 (reset page form-action), L6 (export not cached). **Left open**:
  M4 timing difference between "no such account/app" and "wrong code" on
  reset-by-app (same page, same status); M5 three password buckets per
  account (web password change, delete, sign-in); L3 the passkey reset
  returns the reset URL to the page (it is the same link a letter carries);
  L7 the photo form is read before its CSRF field is checked (bounded by
  the 2 MiB limit). Tests: `tests/web.rs`, `wrong_app_codes_count_on_every_path_and_survive_a_restart`,
  `the_authenticator_app_can_stand_in_for_the_reset_link`.
- **Finding (low, open)**: the per-account lockout lets someone keep a
  known email's sign-in slowed (one try per 3 minutes). Standard
  trade-off; the per-address limit and later TOTP reduce the value of
  guessing, and an unlock link by email can be added with email.

## API3 Broken object property level authorization

Request bodies are fixed structs (`PatchMe { display_name }`,
`PatchDevice { name, raye_version }`); there is no field to set
`email_verified`, `settings_rev` or anything else. Responses are built
field by field; the export has no password hash (asserted in
`export_then_delete_the_account`). **No finding.**

## API4 Unrestricted resource consumption

- Body limit 64 KiB everywhere, 2 MiB for the picture; picture decoding
  limited to 4096 px a side and 96 MiB of allocation, then re-encoded at
  256 px. Test: `profile_picture_and_name` (3 MiB → 413), unit tests on
  huge dimensions.
- At most 64 setting changes per request, keys from a list of 12, values
  typed and bounded; 2000 installed apps per device; 20 devices per
  account; per-device API limit.
- **Fixed**: requests are cut off after 30 s (`TimeoutLayer`).
- In-memory rate-limit table pruned above 50 000 entries.
- New limits, all in the same in-memory buckets: 3 letters per account then
  one an hour (`MAIL_PER_ACCOUNT`, so this server cannot be used to flood
  someone's inbox), 5 reset requests per address then one every 6 minutes,
  and 5 code tries per account then one a minute (`TOTP_ACCOUNT`). That last
  one is the whole strength of six digits against guessing: ~20 tries an hour
  against 10^6. Test: `guessing_codes_is_rate_limited`, which also checks the
  limit does not step aside for a correct code.
- **Finding (low, open)**: counters live in one process; behind several
  processes they must move to the database or Redis.

## API5 Broken function level authorization

There are no admin endpoints. Deleting the account asks for the password
again, so a stolen access token cannot wipe it. Removing any device of
your own account is intended (Windows does the same). **No finding.**

## API6 Unrestricted access to sensitive business flows

**Finding (medium, open)**: account creation is limited only by address
(5 an hour). Mass sign-up from many addresses is possible until email
verification exists. Options: email verification before devices can
sync, Cloudflare rate rules on `/oauth/authorize` POST. A CAPTCHA would
need script on the sign-in page, which this design avoids.

## API7 Server side request forgery

The server makes no outbound request. The client only talks to the
configured server: `https://` or loopback, redirects off, so a bad
configuration cannot send tokens in clear or elsewhere. **No finding.**

## API8 Security misconfiguration

- Pages: CSP `default-src 'none'`, `frame-ancestors 'none'`,
  `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `no-store`, no
  script, every value escaped. Test: `pages_carry_safe_headers_and_speak_french`.
- Errors carry a code and a short message; database errors stay in the
  server log.
- `CF-Connecting-IP` is trusted only with `RAYE_ACCOUNT_TRUST_PROXY=1`,
  otherwise anyone could pick their own address and skip the limits.
- **Fixed**: `Strict-Transport-Security` when `RAYE_ACCOUNT_HTTPS=1`.
- **Finding (medium, open)**: sqlx is built without TLS; fine on a local
  socket or a VM-local PostgreSQL, but turn on `tls-rustls` and
  `sslmode=verify-full` if the database is ever across the network.
- The headless demo's plain-file token store is behind a cargo feature
  (`insecure-test-keyring`) that a package build does not enable. Test:
  `the_environment_alone_cannot_divert_secrets_to_a_file` - setting
  `RAYE_ACCOUNT_TEST_KEYRING_FILE` on a normal build does nothing, so one
  environment variable cannot have the tokens written where they can be read.
- **`RAYE_ACCOUNT_TOTP_KEY` is required, and its absence refuses enrolment**
  rather than inventing a key at startup. A key made per process would stop
  opening the stored secrets at the next restart, and people would find out
  only when they next needed their second factor. `Config`'s `Debug` redacts
  it (test: `the_config_debug_does_not_print_the_totp_key`) because one
  `tracing::debug!(?config)` would otherwise put it in a log.
- **`RAYE_ACCOUNT_BASE_URL` is required and must be https or loopback.** It
  is what the links in mail point at; over plain http a reset token would be
  handed to the network. Test: `links_must_not_go_out_in_the_clear`.
- **No SMTP client and no mail password.** Mail goes to a local submission
  binary by argv (`sendmail -t -i`); unset, nothing is sent and the letter
  goes to a bounded in-memory outbox. A prototype cannot quietly mail a
  stranger, and there is no credential to leak. An address or subject
  carrying a line break is refused before anything is queued (test:
  `an_address_cannot_smuggle_a_header`).

## API9 Improper inventory management

One version (`/v1`), every route listed in the design doc (section 10),
`/healthz` returns `ok` and nothing else. **No finding.**

## API10 Unsafe consumption of APIs

The desktop client treats the server as untrusted input before touching
the PC:

- **Fixed during the review**: values pulled from the server are checked
  against the key list again before being applied (a hostile server could
  otherwise hand a wallpaper name like `../../etc` to the path lookup).
  Identifiers can no longer start with a dot. Test:
  `values_from_the_server_are_checked_before_applying`.
- Values are applied with `kwriteconfig6` and Plasma tools through argv,
  never a shell; the taskbar script embeds pins through JSON encoding.
- The loopback callback reads one request line of at most 4 KiB, checks
  `state` in constant time, accepts only `[A-Za-z0-9_-]` codes.
- The picture download is capped at 1 MiB.

## Outside the Top 10

- **Secrets on the PC**: tokens and the device key in the keyring (Secret
  Service, DH session); state file 0600 holds nothing usable.
- **Local processes**: another program of the same user can call
  `org.raye.Account1` (D-Bus session bus) and, for example, read the
  device list or sign the PC out. Same trust level as the user's keyring;
  no extra boundary is claimed.
## Dependencies and proofs (2026-11-06)

**`cargo audit` has now been run** - it was listed here as unavailable. 315
crates, 1409 advisories loaded. Four findings, all examined rather than
waved through; the reasons and the commands that re-measure them are in
`.cargo/audit.toml`:

| Finding | What it is | Verdict |
|---|---|---|
| RUSTSEC-2023-0071 | `rsa` 0.9.10, Marvin timing side channel, **no fix exists** | reaches the lockfile through `sqlx-mysql` only, which this server never enables. Measured: `cargo tree -i rsa -e normal` prints "nothing to print", and the only sqlx backends with build artefacts are `sqlx_core`, `sqlx_macros`, `sqlx_postgres` - zero `rsa` objects. Listed, never compiled, never shipped. |
| RUSTSEC-2026-0370/1/2 | `zvariant`, `zbus_names`, `zvariant_derive` unmaintained (no flaw alleged) | they come from `zbus` 5.19 in the desktop daemon. `zbus` 6.2.1 depends on none of them, but `secret-service` 5.2.0 - the newest release, and how tokens reach KWallet - requires `zbus ^5`. Forcing zbus 6 alongside it would put two D-Bus stacks in one binary. **Blocked upstream**; lifts when secret-service ships on zbus 6. |

**An ignore nobody re-checks is how a real advisory gets silenced**, so the
premise of the first one is enforced by the suite:
`sqlx_pulls_in_no_other_backend` reads `server/Cargo.toml` and fails if
`mysql`, `sqlite` or sqlx's default features are ever turned on. Proved red
by turning `mysql` on.

`cargo deny` is still not run (licence and duplicate-version policy, not
vulnerabilities).

### Every new guard was proved red

A guard that has never failed a test proves nothing: it may be dead code, or
the test may be asserting something else. Each of the 20 regressions below
was applied to the source, the suite run, and the file restored and its md5
checked - the method this tree uses throughout.

One nuance worth keeping: the first run expected
`a_spent_step_stays_spent_even_inside_the_window` to go red when the
write-back in `check_second_factor` was removed, and it stayed green. The
expectation was wrong, not the test: that test is satisfied by the write
`confirm` does at enrolment, which the patch left alone. Only the replay test
exercises the sign-in write-back. An expectation nobody checks is the same
mistake as an ignore nobody checks.

And two runs reported eleven unrelated tests as "also red". That was an
artefact of `cargo test` stopping after the first failing target, so the
integration binaries never ran at all; with `--no-fail-fast` there is no
collateral. Measured, not assumed: the first guess was connection exhaustion
in the throwaway database, and the log had zero "too many clients".

| Break this | These go red |
|---|---|
| sign-up makes the account before the link | `no_account_until_the_link_is_opened` |
| sign-up link never expires | `a_sign_up_link_expires` |
| sign-up link is reusable | `no_account_until_the_link_is_opened` |
| a waiting sign-up holds the address | `a_pending_sign_up_does_not_hold_the_address` |
| sign-up says an address is used | `a_taken_address_gets_the_same_page_and_a_letter` |
| sign-up letters unlimited | `sign_up_letters_are_rate_limited_per_address` |
| an unconfirmed account can sign in or use the API | `an_unconfirmed_account_cannot_use_the_api_or_sign_in` |
| a link to the old address confirms a new one | `a_link_mailed_to_the_old_address_cannot_confirm_a_new_one` |
| reset link is reusable | `a_reset_link_changes_the_password_once_and_signs_every_pc_out` |
| reset link never expires | `a_reset_link_expires_and_a_stranger_token_is_refused` |
| reset works on an unconfirmed address | `the_answer_says_nothing_about_who_has_an_account` |
| a reset leaves the old sessions alive | `a_reset_link_changes_the_password_once_and_signs_every_pc_out` |
| the spent TOTP step is not written back | `a_code_is_asked_after_the_password_and_works_once` |
| the drift window is three steps wide | `the_drift_window_is_bounded`, `the_window_is_one_step_either_side` |
| the code screen takes any form | `the_code_screen_cannot_be_reached_without_the_password` |
| two-step turned off with a token alone | `turning_two_step_off_needs_the_password` |
| a recovery code may be used twice | `a_recovery_code_works_once` |
| the TOTP secret stored in the clear | `the_secret_is_never_stored_in_the_clear_and_is_handed_out_once` |
| sqlx pulls in another backend | `sqlx_pulls_in_no_other_backend` |
| the page forgets a table | `the_page_names_every_table_and_counts_them_right` |
| the page forgets a synced setting | `the_page_lists_exactly_the_settings_that_sync` |
| a column starts holding an IP address | `no_column_anywhere_holds_an_ip_address` |
| a table stops cascading from the account | `every_table_cascades_from_the_account` |
| the password column holds a password | `the_password_is_only_ever_a_hash` |

## The privacy page is tied to the code

`docs/privacy.md` says what an account keeps. `server/tests/privacy.rs` (7
checks, no database, no network) reads the migrations and
`common/src/keys.rs` and refuses to let the page drift from them: every table
named, the count right, every synced key listed, no column anywhere that
holds a network address, the password column a hash, every token table keyed
by a hash, the TOTP secret a sealed blob, and every table cascading from
`accounts` so that "every row goes at once" is true.

That last one is the kind of promise that quietly stops being true: a table
added later without `ON DELETE CASCADE` would leave rows behind after a
delete, and nothing else in the suite would notice.

## Deliberate divergences from the design

- **Recovery codes are SHA-256, not Argon2** (design section 6 says Argon2).
  They are 80 random bits that no person chooses, so there is no password to
  grind: a 19 MiB KDF would buy nothing and would cost up to ten hashes per
  attempt - 190 MiB on a path an attacker can call. Looked up by hash, like
  every other token here. Recorded in the migration too.
- **Enrolling cannot also sign you in.** Confirming two-step verification
  spends a real code, and a spent step stays spent, so the code that turned
  it on will not then open a session. RFC 6238 section 5.2 asks for exactly
  that refusal; it is a real, small inconvenience, not a bug. Pinned by
  `a_spent_step_stays_spent_even_inside_the_window`.

## What the client keeps, measured

The claim "state file 0600 holds nothing usable" is now a test rather than a
sentence. `the_state_file_holds_nothing_that_could_act_as_the_account` fills
every field, writes the file, and checks the mode is `0600` and that no field
of the keyring's `Secrets` (`access_token`, `refresh_token`, `device_key`)
appears in it. `signing_out_drops_the_address_and_the_revisions` checks that
signing out leaves no address, etag or key name behind.

Measured contents:

| What | Where | Rights |
|---|---|---|
| access token, refresh token, device private key, device id | the keyring, Secret Service with a DH session | the keyring's |
| server, address, display name, device name, switches, revision, per-key revision and hash, etags, the pre-account name and icon path, last sync, last error | `~/.local/state/raye-account/state.json` | `0600`, written to a temp file then renamed |
| the local picture from before the account | `~/.local/state/raye-account/picture-before-raye-account` | default umask; a copy of a file already in the home |
| the account picture | `~/.cache/raye-account/picture-<etag>.png` | default umask; a cache, re-downloadable |

Nothing secret is on disk outside the keyring. `Secrets`' own `Debug` is
redacted (test: `the_debug_of_secrets_shows_no_secret`), because it is the
kind of value that ends up in an error path.
