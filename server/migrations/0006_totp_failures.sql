-- Wrong second-factor codes across every way of presenting one (desktop
-- sign-in, website sign-in, reset with the app), kept so a restart does not
-- hand out new guesses.
ALTER TABLE accounts
    ADD COLUMN totp_failures integer NOT NULL DEFAULT 0,
    ADD COLUMN totp_failed_at timestamptz;
