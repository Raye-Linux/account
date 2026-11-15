-- Email verification, password reset and two-step verification (TOTP).
--
-- Every token here follows the rule the first migration set: what the user
-- receives is never stored. The row is keyed by the SHA-256 of the token, so
-- a database dump cannot be replayed, and a lookup is an index probe on the
-- hash of what was presented -- never a string comparison against a secret.
--
-- Single use is `used_at`, not deletion: a token that comes back after use
-- has to be distinguishable from one that never existed, so the reuse can be
-- logged instead of looking like a typo.

-- Proves one address, the one the link was sent to. Keeping the address on
-- the row means a link mailed to the old address cannot verify a new one.
CREATE TABLE email_tokens (
    token_hash   bytea PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    email        text NOT NULL,
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_tokens_account ON email_tokens (account_id);

CREATE TABLE password_resets (
    token_hash   bytea PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_resets_account ON password_resets (account_id);

ALTER TABLE accounts
    -- XChaCha20-Poly1305 over the RFC 6238 secret, under the server key.
    -- NULL until the user starts enrolling.
    ADD COLUMN totp_secret bytea,
    ADD COLUMN totp_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN totp_confirmed_at timestamptz,
    -- Anti-replay. The highest 30 s step this account has ever spent. A code
    -- is accepted only for a LATER step, so a code caught on the wire (or
    -- shoulder-read) is dead the moment the real owner has used it -- and
    -- dead for the whole drift window, not just for its own step.
    ADD COLUMN totp_last_step bigint NOT NULL DEFAULT 0;

-- Ten per account, shown once at enrolment. High-entropy random strings, so
-- SHA-256 is enough and the design's Argon2 would only buy a 19 MiB cost per
-- try for no gain: there is no password to grind. Deliberate divergence from
-- design section 6, recorded in docs/security-review.md.
CREATE TABLE totp_recovery_codes (
    code_hash    bytea PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    used_at      timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX totp_recovery_account ON totp_recovery_codes (account_id);
