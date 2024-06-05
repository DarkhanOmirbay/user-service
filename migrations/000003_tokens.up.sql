CREATE TABLE IF NOT EXISTS tokens
(
    hash    bytea PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE ,
    expiry  TIMESTAMP(0) WITH TIME ZONE NOT NULL
                             );