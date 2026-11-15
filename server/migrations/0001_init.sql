-- Raye account, first schema.
-- Tokens and codes are stored as SHA-256 hashes, never as sent.

CREATE TABLE accounts (
    id               uuid PRIMARY KEY,
    email            text NOT NULL,
    email_verified   boolean NOT NULL DEFAULT false,
    password_hash    text NOT NULL,
    display_name     text NOT NULL,
    avatar_png       bytea,
    avatar_etag      text,
    -- Highest settings revision handed out for this account.
    settings_rev     bigint NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (email = lower(email)),
    CHECK (length(display_name) BETWEEN 1 AND 64)
);
CREATE UNIQUE INDEX accounts_email ON accounts (email);

CREATE TABLE devices (
    id             uuid PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name           text NOT NULL,
    model          text NOT NULL,
    raye_version   text NOT NULL,
    public_key     bytea NOT NULL CHECK (length(public_key) = 32),
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX devices_account ON devices (account_id);

-- Authorization codes live a minute and are used once.
CREATE TABLE oauth_codes (
    code_hash       bytea PRIMARY KEY,
    account_id      uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    redirect_uri    text NOT NULL,
    code_challenge  text NOT NULL,
    expires_at      timestamptz NOT NULL
);

CREATE TABLE access_tokens (
    token_hash   bytea PRIMARY KEY,
    device_id    uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    account_id   uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    expires_at   timestamptz NOT NULL
);
CREATE INDEX access_tokens_device ON access_tokens (device_id);

-- One live refresh token per device. A used one is kept (used_at set) until
-- it expires, so presenting it again is seen as theft and ends the device.
CREATE TABLE refresh_tokens (
    token_hash   bytea PRIMARY KEY,
    device_id    uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz
);
CREATE INDEX refresh_tokens_device ON refresh_tokens (device_id);

CREATE TABLE settings (
    account_id    uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    key           text NOT NULL,
    value         jsonb,               -- NULL: removed, kept so other devices learn it
    rev           bigint NOT NULL,
    modified_at   timestamptz NOT NULL,
    device_id     uuid REFERENCES devices (id) ON DELETE SET NULL,
    PRIMARY KEY (account_id, key)
);
CREATE INDEX settings_rev ON settings (account_id, rev);

CREATE TABLE store_library (
    account_id   uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    app_id       text NOT NULL,
    source       text NOT NULL,
    added_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, app_id)
);

CREATE TABLE device_installs (
    device_id      uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    app_id         text NOT NULL,
    PRIMARY KEY (device_id, app_id)
);
