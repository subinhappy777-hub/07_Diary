create table if not exists public.diary_users (
  id uuid primary key,
  username text not null,
  username_norm text not null unique,
  password_hash text not null,
  salt text not null,
  created_at timestamptz not null
);

create table if not exists public.diary_sessions (
  token_hash text primary key,
  user_id uuid not null references public.diary_users(id) on delete cascade,
  expires_at timestamptz not null
);
create index if not exists diary_sessions_expiry_idx on public.diary_sessions(expires_at);

create table if not exists public.diary_data (
  user_id uuid primary key references public.diary_users(id) on delete cascade,
  data_json jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null
);

alter table public.diary_users enable row level security;
alter table public.diary_sessions enable row level security;
alter table public.diary_data enable row level security;
revoke all on public.diary_users, public.diary_sessions, public.diary_data from anon, authenticated;
grant all on public.diary_users, public.diary_sessions, public.diary_data to service_role;

create or replace function public.create_diary_account(
  p_id uuid,
  p_username text,
  p_username_norm text,
  p_password_hash text,
  p_salt text,
  p_created_at timestamptz,
  p_data jsonb
) returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  insert into public.diary_users(id, username, username_norm, password_hash, salt, created_at)
  values (p_id, p_username, p_username_norm, p_password_hash, p_salt, p_created_at);
  insert into public.diary_data(user_id, data_json, updated_at)
  values (p_id, coalesce(p_data, '{}'::jsonb), p_created_at);
end;
$$;

revoke all on function public.create_diary_account(uuid, text, text, text, text, timestamptz, jsonb) from public, anon, authenticated;
grant execute on function public.create_diary_account(uuid, text, text, text, text, timestamptz, jsonb) to service_role;
