create table if exists users
(
    id         bigserial primary key,
    name       text not null,
    email      text not null,
    role       text not null,
    password   text not null,
    created_at timestamp default current_timestamp,
    updated_at timestamp default current_timestamp
);