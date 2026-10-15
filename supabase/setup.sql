-- Backend Lembar Kerja TEGAR (Supabase)
--
-- Cara memasang (sekali saja):
--  1. Buat project di https://supabase.com (gratis).
--  2. Buka SQL Editor > New query, tempel seluruh isi file ini, klik Run.
--  3. Di query baru, atur password admin (jangan simpan baris ini di GitHub):
--        select private.tegar_set_admin_password('PASSWORD_ANDA');
--  4. Buka Project Settings > API (atau tombol Connect), salin Project URL dan
--     kunci publik (anon / publishable key). Tempel ke SUPABASE_URL dan
--     SUPABASE_KEY di index.html. Kunci publik memang aman ditaruh di halaman:
--     tabel dikunci, peserta hanya bisa memakai fungsi tegar_submit di bawah.
--
-- File ini aman dijalankan ulang; data yang sudah masuk tidak terhapus. Semua objek
-- memakai awalan tegar_, jadi aman dipasang di project yang berisi aplikasi lain.
-- Jawaban peserta bisa dilihat juga di Table Editor > tegar_submissions.

create extension if not exists pgcrypto with schema extensions;

create schema if not exists private;
revoke all on schema private from public;

create table if not exists private.settings (
  key text primary key,
  value text not null
);
alter table private.settings enable row level security;

-- One row per participant device; re-sending updates the same row.
create table if not exists public.tegar_submissions (
  id text primary key check (id ~* '^[a-z0-9-]{8,64}$'),
  nama text not null,
  unit text not null default '',
  jabatan text not null default '',
  data jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- No policies: the table is closed to the public API; access goes through the functions below.
alter table public.tegar_submissions enable row level security;
revoke all on table public.tegar_submissions from anon, authenticated;

create or replace function private.tegar_set_admin_password(p text)
returns void
language sql
security definer
set search_path = ''
as $$
  insert into private.settings (key, value)
  values ('tegar_admin_password_hash', extensions.crypt(p, extensions.gen_salt('bf')))
  on conflict (key) do update set value = excluded.value;
$$;

create or replace function private.tegar_check_admin(p_key text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  h text;
begin
  select value into h from private.settings where key = 'tegar_admin_password_hash';
  if h is null then
    raise exception 'no_password';
  end if;
  if p_key is null or extensions.crypt(p_key, h) <> h then
    perform pg_sleep(0.8);
    raise exception 'unauthorized';
  end if;
end;
$$;

-- Participant: send (or re-send) the whole worksheet.
create or replace function public.tegar_submit(p_id text, p_data jsonb)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  clean jsonb := '{}'::jsonb;
  k text;
  v jsonb;
  ts timestamptz := now();
begin
  if p_id is null or p_id !~* '^[a-z0-9-]{8,64}$' then
    raise exception 'bad_id';
  end if;
  if jsonb_typeof(p_data) is distinct from 'object' then
    raise exception 'bad_request';
  end if;
  -- Keep only worksheet fields, as short strings or true.
  for k, v in select * from jsonb_each(p_data) loop
    if k ~ '^(r|l[0-9])_[a-z0-9]+$' then
      if v = 'true'::jsonb then
        clean := clean || jsonb_build_object(k, true);
      elsif jsonb_typeof(v) in ('string', 'number') and length(v #>> '{}') > 0 then
        clean := clean || jsonb_build_object(k, left(v #>> '{}', 3000));
      end if;
    end if;
  end loop;
  if coalesce(btrim(clean ->> 'r_nama'), '') = '' then
    raise exception 'no_name';
  end if;
  if length(clean::text) > 60000 then
    raise exception 'too_large';
  end if;
  if not exists (select 1 from public.tegar_submissions where id = p_id)
     and (select count(*) from public.tegar_submissions) >= 3000 then
    raise exception 'full';
  end if;
  insert into public.tegar_submissions (id, nama, unit, jabatan, data, updated_at)
  values (p_id, left(clean ->> 'r_nama', 300), left(coalesce(clean ->> 'r_unit', ''), 300),
          left(coalesce(clean ->> 'r_jabatan', ''), 300), clean, ts)
  on conflict (id) do update
    set nama = excluded.nama, unit = excluded.unit, jabatan = excluded.jabatan,
        data = excluded.data, updated_at = excluded.updated_at;
  return ts;
end;
$$;

-- Admin: all submissions.
create or replace function public.tegar_admin_list(p_key text)
returns table (id text, updated_at timestamptz, data jsonb)
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.tegar_check_admin(p_key);
  return query select s.id, s.updated_at, s.data from public.tegar_submissions s order by s.nama;
end;
$$;

-- Admin: cheap "has anything changed?" check for live polling.
create or replace function public.tegar_admin_stamp(p_key text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  r text;
begin
  perform private.tegar_check_admin(p_key);
  select count(*)::text || '|' || coalesce(max(s.updated_at)::text, '') into r from public.tegar_submissions s;
  return r;
end;
$$;

-- Admin: remove one submission (e.g. a test entry).
create or replace function public.tegar_admin_delete(p_key text, p_id text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.tegar_check_admin(p_key);
  delete from public.tegar_submissions where id = p_id;
  return found;
end;
$$;

revoke all on function private.tegar_set_admin_password(text) from public;
revoke all on function private.tegar_check_admin(text) from public;
revoke all on function public.tegar_submit(text, jsonb) from public, anon, authenticated;
revoke all on function public.tegar_admin_list(text) from public, anon, authenticated;
revoke all on function public.tegar_admin_stamp(text) from public, anon, authenticated;
revoke all on function public.tegar_admin_delete(text, text) from public, anon, authenticated;
grant execute on function public.tegar_submit(text, jsonb) to anon, authenticated;
grant execute on function public.tegar_admin_list(text) to anon, authenticated;
grant execute on function public.tegar_admin_stamp(text) to anon, authenticated;
grant execute on function public.tegar_admin_delete(text, text) to anon, authenticated;

notify pgrst, 'reload schema';
