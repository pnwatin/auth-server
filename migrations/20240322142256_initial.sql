DROP TABLE IF EXISTS users;
-- DROP TABLE IF EXISTS refresh_tokens;

create table users(
  id UUID PRIMARY KEY NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL
);

CREATE TABLE refresh_tokens(
  id UUID PRIMARY KEY NOT NULL,
  user_id UUID NOT NULL
    REFERENCES users (id),
  jit UUID NOT NULL UNIQUE,
  family UUID NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

