-- MapLink · справочная схема Supabase
-- ---------------------------------------------------------------------------
-- ВНИМАНИЕ: это восстановленная по коду приложения схема, а не дамп живой базы.
-- Нужна она для одного: чтобы проект можно было поднять заново (новая база,
-- другая ссылка, миграция на свой домен) и не гадать о колонках.
--
-- ПЕРЕД ПРИМЕНЕНИЕМ сверь с живой базой (Supabase → Table Editor, или
-- \d+ users в SQL Editor) — имена/типы могли уехать.
-- ЭТОТ ФАЙЛ НЕ ПРИМЕНЯЙ ПОВЕРХ ЖИВОЙ БАЗЫ: в нём create table без
-- «if not exists» там, где это было бы безопасно.
-- ---------------------------------------------------------------------------

create extension if not exists pgcrypto;

-- пользователи; identity = telegram_id (Supabase Auth не используется)
create table users (
  id           uuid primary key default gen_random_uuid(),
  telegram_id  text not null unique,
  username     text,
  avatar_url   text,
  invite_code  text unique,
  is_private   boolean not null default false,
  created_at   timestamptz not null default now()
);

-- места: посещённые (is_wishlist=false) и мечты (true)
create table places (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references users(id) on delete cascade,
  country     text not null,
  city        text,
  visit_date  date,
  note        text,
  is_wishlist boolean not null default false,
  lat         double precision,
  lon         double precision,
  created_at  timestamptz not null default now()
);
create index places_user_created_idx on places (user_id, created_at desc);
create index places_user_country_idx on places (user_id, country);

-- фото прикреплены к месту; файлы лежат в storage-бакете place-photos
create table photos (
  id         uuid primary key default gen_random_uuid(),
  place_id   uuid not null references places(id) on delete cascade,
  url        text not null,
  created_at timestamptz not null default now()
);
create index photos_place_idx on photos (place_id);

create table friendships (
  id           uuid primary key default gen_random_uuid(),
  requester_id uuid not null references users(id) on delete cascade,
  addressee_id uuid not null references users(id) on delete cascade,
  status       text not null default 'pending'
                 check (status in ('pending','accepted','blocked')),
  created_at   timestamptz not null default now(),
  unique (requester_id, addressee_id)
);

-- достижения: приложение пишет в таблицу, но фича по умолчанию выключена,
-- поэтому все обращения к ней обёрнуты в try/catch
create table achievements (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references users(id) on delete cascade,
  code       text not null,
  created_at timestamptz not null default now(),
  unique (user_id, code)
);

create table reactions (
  id         uuid primary key default gen_random_uuid(),
  place_id   uuid not null references places(id) on delete cascade,
  user_id    uuid not null references users(id) on delete cascade,
  emoji      text not null,
  created_at timestamptz not null default now(),
  unique (place_id, user_id)
);

create table comments (
  id         uuid primary key default gen_random_uuid(),
  place_id   uuid not null references places(id) on delete cascade,
  user_id    uuid not null references users(id) on delete cascade,
  body       text not null,
  created_at timestamptz not null default now()
);
create index comments_place_idx on comments (place_id, created_at);

-- ---------------------------------------------------------------------------
-- Доступ. Ключ у клиента anon, субъекта в JWT нет, поэтому «только свои строки»
-- политикой не выразить (см. docs/SECURITY.md). Ниже — ровно то поведение, на
-- которое приложение рассчитано сегодня.
-- ---------------------------------------------------------------------------
alter table users        enable row level security;
alter table places       enable row level security;
alter table photos       enable row level security;
alter table friendships  enable row level security;
alter table achievements enable row level security;
alter table reactions    enable row level security;
alter table comments     enable row level security;

do $$
declare t text;
begin
  foreach t in array array['users','places','photos','friendships','achievements','reactions','comments']
  loop
    execute format('create policy "%s_anon_all" on %I for all to anon using (true) with check (true);', t, t);
  end loop;
end $$;

-- storage: бакет публичный на чтение, запись/удаление — по тому же anon-правилу
insert into storage.buckets (id, name, public)
values ('place-photos', 'place-photos', true)
on conflict (id) do nothing;

create policy "place_photos_anon_read"
  on storage.objects for select to anon
  using (bucket_id = 'place-photos');

create policy "place_photos_anon_write"
  on storage.objects for insert to anon
  with check (bucket_id = 'place-photos');

create policy "place_photos_anon_delete"
  on storage.objects for delete to anon
  using (bucket_id = 'place-photos');
