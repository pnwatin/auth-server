DROP TABLE IF EXISTS users;

create table users(
  id UUID PRIMARY KEY NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL
);
