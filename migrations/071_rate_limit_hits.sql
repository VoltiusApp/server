CREATE TABLE rate_limit_hits (
    bucket TEXT NOT NULL,
    key TEXT NOT NULL,
    at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX rate_limit_hits_bucket_key_at ON rate_limit_hits (bucket, key, at);
