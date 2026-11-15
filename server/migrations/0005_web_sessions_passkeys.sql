-- The account website: sessions in a cookie, and passkeys.

-- The cookie holds a random token; the row is keyed by its SHA-256.
-- `auth_at` is when the password (or a passkey) was last proven: changing
-- the password or turning a protection off needs it to be recent.
CREATE TABLE web_sessions (
    token_hash   bytea PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    csrf         text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    auth_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX web_sessions_account ON web_sessions (account_id);
CREATE INDEX web_sessions_expiry ON web_sessions (expires_at);

CREATE TABLE passkeys (
    id            uuid PRIMARY KEY,
    account_id    uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    -- The library's own record of the credential (public key, counter).
    passkey       jsonb NOT NULL,
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX passkeys_account ON passkeys (account_id);

-- A ceremony in flight: what the server asked the authenticator, kept
-- server-side for two minutes and used once.
CREATE TABLE webauthn_ceremonies (
    id          uuid PRIMARY KEY,
    kind        text NOT NULL CHECK (kind IN ('register', 'sign-in', 'reset')),
    account_id  uuid REFERENCES accounts (id) ON DELETE CASCADE,
    state       jsonb NOT NULL,
    expires_at  timestamptz NOT NULL
);
CREATE INDEX webauthn_ceremonies_expiry ON webauthn_ceremonies (expires_at);
