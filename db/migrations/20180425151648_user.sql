
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

create table users
(
  id              int unsigned auto_increment
    primary key,
  created_at      timestamp    null,
  updated_at      timestamp    null,
  deleted_at      timestamp    null,
  name            varchar(255) null,
  email           varchar(255) null,
  password        varchar(255) null,
  hashed_password varchar(255) null,
  token           varchar(255) null
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE users;