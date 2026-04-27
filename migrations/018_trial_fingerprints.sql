CREATE TABLE trial_fingerprints (
    fingerprint TEXT PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
