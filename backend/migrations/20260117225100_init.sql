create table if not exists comments (
  id uuid primary key,
  post_slug text not null,
  display_name text not null,
  email text not null,
  content text not null,
  created_at timestamptz not null default now(),
  is_hidden boolean not null default false,
  ip_hash text
);

create index if not exists comments_post_slug_created_at_idx
  on comments (post_slug, created_at);
