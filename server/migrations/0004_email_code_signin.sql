-- A code sent by email as the second step of a sign-in, on unless the
-- account has an authenticator app or turned it off.
ALTER TABLE accounts
    ADD COLUMN email_code_signin boolean NOT NULL DEFAULT true,
    -- Wrong codes across every code sent, so asking for a new code does not
    -- buy new guesses. Cleared by a right code.
    ADD COLUMN email_code_failures integer NOT NULL DEFAULT 0,
    ADD COLUMN email_code_failed_at timestamptz;

-- One live code per account; asking again overwrites it. The code is kept
-- as an HMAC under a key the running server holds in memory only.
CREATE TABLE signin_codes (
    account_id   uuid PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    code_hash    bytea NOT NULL,
    expires_at   timestamptz NOT NULL,
    tries        integer NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now()
);
