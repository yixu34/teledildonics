drop table if exists users;
create table users (
  id integer primary key autoincrement,
  name text not null,
  email text not null,
  pw_hash text not null
);

drop table if exists orders;
create table orders (
  id integer primary key autoincrement,
  user_id integer not null,
  item_name text not null
);
