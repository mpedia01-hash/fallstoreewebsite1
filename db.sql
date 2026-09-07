create extension if not exists pgcrypto;
create table if not exists users (
  user_id text primary key,
  username text not null unique,
  password_hash text not null,
  role text not null default 'user' check (role in ('user','admin','developer')),
  status text not null default 'active' check (status in ('active','blacklisted')),
  protected boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_login_at timestamptz
);
create table if not exists sessions (
  token text primary key,
  user_id text not null references users(user_id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create table if not exists products (
  id text primary key,
  name text not null,
  price numeric(14,2) not null,
  wa text not null,
  category text not null,
  description text default '',
  qris text not null,
  stock text not null default 'UNLIMITED',
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists orders (
  id text primary key,
  product_id text not null references products(id),
  product_name text not null,
  price numeric(14,2) not null,
  quantity integer not null,
  total numeric(14,2) not null,
  user_id text not null references users(user_id),
  username text not null,
  name text not null,
  customer_wa text not null,
  target text not null,
  note text default '',
  seller_wa text not null,
  qris text not null,
  status text not null default 'PENDING' check (status in ('PENDING','DONE')),
  processed_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists backups (
  id text primary key,
  number text not null,
  label text not null default 'Backup',
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create index if not exists users_role_idx on users(role);
create index if not exists sessions_user_idx on sessions(user_id);
create index if not exists orders_user_idx on orders(user_id);
create index if not exists orders_created_idx on orders(created_at desc);
create index if not exists products_active_idx on products(active);

-- IMPORTANT: create the protected Developer account manually after setting your password hash.
-- Hashing used by the bundled API is SHA-256 for this starter build. For production-grade
-- authentication, replace it with Argon2id/bcrypt before exposing the service publicly.
