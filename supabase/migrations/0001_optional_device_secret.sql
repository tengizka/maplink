-- MapLink · 0001 (ОПЦИОНАЛЬНО) per-install секрет вместо «всем можно писать»
-- ===========================================================================
-- НИЧЕГО ЗДЕСЬ НЕ ПРИМЕНЕНО ПО УМОЛЧАНИЮ. Файл — заготовка на случай, если в
-- приложение придут чужие люди и спам/порча чужих строк станет проблемой.
--
-- Идея: у каждой установки свой секрет (генерируется приложением, хранится в
-- localStorage WebView). Каждый запрос идёт с заголовком `x-ml-secret`, в базе
-- лежит его sha256. Политики разрешают запись только тому, кто предъявил секрет
-- владельца строки. Чтение остаётся публичным — на нём построены лента и рейтинг.
--
-- Почему это не «настоящая» аутентификация: секрет не доказывает, что перед
-- нами именно этот telegram_id, он доказывает лишь «тот, кто пишет, ранее
-- создал эту установку». Злоумышленник не сможет ни читать чужое (и так
-- открыто), ни писать от чужого имени. Для настоящего субъекта нужен
-- verify-telegram + Supabase Auth (см. docs/SECURITY.md и supabase/functions/).
--
-- ПОРЯДОК ВКЛЮЧЕНИЯ (строго по шагам, на своей базе, с бэкапом):
--   1) supabase → SQL Editor: `create extension if not exists pgcrypto;`
--   2) выполнить «ЧАСТЬ 1» этого файла
--   3) проверить, что PostgREST пропускает кастомный заголовок (CORS):
--        curl -i -X OPTIONS 'https://<ref>.supabase.co/rest/v1/places' \
--          -H 'Origin: https://tengizka.github.io' \
--          -H 'Access-Control-Request-Method: POST' \
--          -H 'Access-Control-Request-Headers: x-ml-secret'
--      в ответе `access-control-allow-headers` должен перечисляться x-ml-secret.
--      Если его нет — подход не годится, дальше не идти.
--   4) в index.html поставить USE_INSTALL_SECRET = true, залить на Pages
--   5) зайти в Telegram-приложение НОВОЙ установкой (или очистить данные WebView),
--      чтобы секрет зарегистрировался; проверить, что места добавляются/правятся
--   6) только теперь выполнить «ЧАСТЬ 2» (она закрывает запись для всех, у кого
--      нет секрета) и проверить ещё раз: чужую строку изменить нельзя, свои — можно.
--
-- ОТКАТ: `drop policy ... ` из «ЧАСТИ 2» (они все с префиксом ml_secret_),
-- флаг в index.html → false.
-- ===========================================================================

-- ---------------------------------------------------------------- ЧАСТЬ 1
alter table users add column if not exists access_secret_hash text;
create unique index if not exists users_access_secret_hash_uidx
  on users (access_secret_hash) where access_secret_hash is not null;

-- секреты, предъявленные в текущем запросе (один вычисленный хэш на запрос)
create or replace function ml_current_secret_hash()
returns text
language sql
stable
as $$
  select encode(
    digest(coalesce(current_setting('request.headers', true)::json ->> 'x-ml-secret', ''), 'sha256'),
    'hex'
  );
$$;

-- «этот запрос предъявил секрет владельца user_id»
create or replace function ml_owns_as_user(p_user_id uuid)
returns boolean
language sql
stable security definer
set search_path = public
as $$
  select p_user_id is not null and exists (
    select 1 from users u
    where u.id = p_user_id
      and u.access_secret_hash = ml_current_secret_hash()
  );
$$;

-- регистрация секрета: разрешена, пока своего секрета нет (или предъявлен верный)
drop policy if exists ml_secret_users_update on public.users;
create policy ml_secret_users_update on public.users
  for update to anon
  using (access_secret_hash is null or access_secret_hash = ml_current_secret_hash())
  with check (access_secret_hash is null or access_secret_hash = ml_current_secret_hash());

-- ---------------------------------------------------------------- ЧАСТЬ 2
-- Места
drop policy if exists places_anon_all on public.places;
create policy ml_secret_places_select on public.places
  for select to anon using (true);
create policy ml_secret_places_insert on public.places
  for insert to anon with check (ml_owns_as_user(user_id));
create policy ml_secret_places_update on public.places
  for update to anon
  using (ml_owns_as_user(user_id)) with check (ml_owns_as_user(user_id));
create policy ml_secret_places_delete on public.places
  for delete to anon using (ml_owns_as_user(user_id));

-- Фото (строки)
drop policy if exists photos_anon_all on public.photos;
create policy ml_secret_photos_select on public.photos
  for select to anon using (true);
create policy ml_secret_photos_insert on public.photos
  for insert to anon with check (
    exists (select 1 from places p where p.id = place_id and ml_owns_as_user(p.user_id))
  );
create policy ml_secret_photos_delete on public.photos
  for delete to anon using (
    exists (select 1 from places p where p.id = place_id and ml_owns_as_user(p.user_id))
  );

-- Комментарии и реакции: писать может только владелец секрета, трогать свои
drop policy if exists comments_anon_all on public.comments;
create policy ml_secret_comments_select on public.comments
  for select to anon using (true);
create policy ml_secret_comments_insert on public.comments
  for insert to anon with check (ml_owns_as_user(user_id));
create policy ml_secret_comments_delete on public.comments
  for delete to anon using (ml_owns_as_user(user_id));

drop policy if exists reactions_anon_all on public.reactions;
create policy ml_secret_reactions_select on public.reactions
  for select to anon using (true);
create policy ml_secret_reactions_insert on public.reactions
  for insert to anon with check (ml_owns_as_user(user_id));
create policy ml_secret_reactions_delete on public.reactions
  for delete to anon using (ml_owns_as_user(user_id));

-- Друзья: заявки и удаления только от своего имени
drop policy if exists friendships_anon_all on public.friendships;
create policy ml_secret_friendships_select on public.friendships
  for select to anon using (true);
create policy ml_secret_friendships_insert on public.friendships
  for insert to anon with check (ml_owns_as_user(requester_id));
create policy ml_secret_friendships_update on public.friendships
  for update to anon
  using (ml_owns_as_user(addressee_id) or ml_owns_as_user(requester_id))
  with check (ml_owns_as_user(addressee_id) or ml_owns_as_user(requester_id));
create policy ml_secret_friendships_delete on public.friendships
  for delete to anon using (ml_owns_as_user(requester_id) or ml_owns_as_user(addressee_id));

-- Достижения
drop policy if exists achievements_anon_all on public.achievements;
create policy ml_secret_achievements_select on public.achievements
  for select to anon using (true);
create policy ml_secret_achievements_write on public.achievements
  for insert to anon with check (ml_owns_as_user(user_id));
create policy ml_secret_achievements_delete on public.achievements
  for delete to anon using (ml_owns_as_user(user_id));

-- users: чтение как было (иначе не работают лента, рейтинг и «общие страны»)
drop policy if exists users_anon_all on public.users;
create policy ml_secret_users_select on public.users
  for select to anon using (true);
create policy ml_secret_users_insert on public.users
  for insert to anon with check (access_secret_hash is null);

-- storage: загрузка/удаление только в «свою» папку (путь = user_id/файл)
drop policy if exists place_photos_anon_write on storage.objects;
drop policy if exists place_photos_anon_delete on storage.objects;
create policy ml_secret_storage_insert on storage.objects
  for insert to anon
  with check (
    bucket_id = 'place-photos'
    and ml_owns_as_user(nullif(split_part(name, '/', 1), '')::uuid)
  );
create policy ml_secret_storage_delete on storage.objects
  for delete to anon
  using (
    bucket_id = 'place-photos'
    and ml_owns_as_user(nullif(split_part(name, '/', 1), '')::uuid)
  );
