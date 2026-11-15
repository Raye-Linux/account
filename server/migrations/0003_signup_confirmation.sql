-- An account only exists once its address is confirmed. Until then the
-- sign-up waits here: it cannot sign in, cannot sync, and does not hold the
-- address against its real owner, who can sign up too and confirm first.
-- Several pending sign-ups for one address may coexist; the first link that
-- is opened wins and the others are dropped with it.
CREATE TABLE pending_signups (
    token_hash      bytea PRIMARY KEY,
    email           text NOT NULL CHECK (email = lower(email)),
    password_hash   text NOT NULL,
    display_name    text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 64),
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX pending_signups_email ON pending_signups (email);
CREATE INDEX pending_signups_expiry ON pending_signups (expires_at);
