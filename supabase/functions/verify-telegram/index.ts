// MapLink · заготовка Edge Function: честная проверка initData вместо доверия клиенту
// -----------------------------------------------------------------------------------
// Это НЕ подключено и НЕ работает «само по себе»: файл описывает единственный путь
// к настоящей аутентификации в Supabase без собственного бэкенда. Читать вместе с
// docs/SECURITY.md → «Чего этот проект закрыть на клиенте не может».
//
// Что происходит:
//   клиент (Telegram) присылает rawData.initData целиком;
//   функция пересчитывает HMAC-подпись ключом, который знает только бот,
//   и если подпись валидна и auth_date свежий — выпускает JWT Supabase Auth;
//   дальше RLS работает по auth.uid(), и никакой anon key не даёт права записи.
//
// Деплой (когда решение будет принято):
//   supabase functions deploy verify-telegram --no-verify-jwt
//   supabase secrets set TELEGRAM_BOT_TOKEN=<токен @MapLinkAppbot>
// и в index.html: включить проверку в initUser() + завести пользователя через auth,
// а не через upsert по telegram_id.
//
// Ключ бота НИКОГДА не должен попадать на клиент.

// deno-lint-ignore-file no-explicit-any
import { createHmac, timingSafeEqual } from 'https://deno.land/std@0.224.0/crypto/mod.ts';
import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';

const MAX_AGE_SEC = 24 * 3600; // initData старше суток не принимаем

function utf8(s: string) {
  return new TextEncoder().encode(s);
}

function hmacHex(key: Uint8Array, data: string) {
  const h = createHmac('sha256', key);
  h.update(utf8(data));
  return Array.from(h.digest()).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Ключ конкретного пользователя: HMAC_SHA256(key="WebAppData", msg=botToken) */
function userSecretKey(botToken: string, userId: string) {
  return hmacBytes(utf8('WebAppData'), botToken);
}
function hmacBytes(key: Uint8Array, data: string): Uint8Array {
  const h = createHmac('sha256', key);
  h.update(utf8(data));
  return h.digest();
}

/** Разбирает и проверяет initData по схеме Telegram. Возвращает payload или null. */
export function verifyInitData(initData: string, botToken: string): Record<string, string> | null {
  const parts = new URLSearchParams(initData);
  const hash = parts.get('hash');
  if (!hash) return null;
  parts.delete('hash');

  // data_check_string = отсортированные по ключу k=v, склеенные '&', без hash
  const pairs: string[] = [];
  for (const [k, v] of Array.from(parts.entries()).sort((a, b) => a[0].localeCompare(b[0]))) {
    pairs.push(`${k}=${v}`);
  }
  const dataCheckString = pairs.join('\n');

  const secret = userSecretKey(botToken, '');
  const expected = Array.from(hmacBytes(secret, dataCheckString))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const a = utf8(expected);
  const b = utf8(hash);
  if (a.length !== b.length) return null;
  if (!timingSafeEqual(a, b)) return null;

  const authDate = Number(parts.get('auth_date') || '0');
  if (!authDate || Date.now() / 1000 - authDate > MAX_AGE_SEC) return null;

  let user: any = null;
  try {
    user = JSON.parse(parts.get('user') || 'null');
  } catch {
    return null;
  }
  if (!user || !user.id) return null;
  return { telegram_id: String(user.id), username: user.username || user.first_name || 'user' };
}

serve(async (req: Request) => {
  const cors = {
    'Access-Control-Allow-Origin': req.headers.get('origin') || '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  };
  if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
  const json = (obj: any, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

  const botToken = Deno.env.get('TELEGRAM_BOT_TOKEN');
  if (!botToken) return json({ error: 'TELEGRAM_BOT_TOKEN is not set' }, 500);

  let body: any;
  try {
    body = await req.json();
  } catch {
    return json({ error: 'expected json { initData }' }, 400);
  }
  const payload = typeof body?.initData === 'string' ? verifyInitData(body.initData, botToken) : null;
  if (!payload) return json({ error: 'invalid initData' }, 401);

  // Дальше — типовая схема «Telegram → Supabase Auth»:
  //   1) upsert пользователя по telegram_id (service role key, только на сервере);
  //   2) supabase.auth.admin.generateLink({ email: `${telegram_id}@maplink.local` })
  //      и отдать клиенту signed token;
  //   3) клиент делает signInWithToken, и RLS работает по auth.uid().
  // Здесь оставлено псевдокодом намеренно: конкретные вызовы зависят от того,
  // включён ли в проекте Auth и как устроена миграция users.
  //
  // return json({ token: <signed access_token>, user_id: <uuid из users> })
  return json({
    ok: true,
    verified: payload,
    next: 'upsert by telegram_id with service role, then mint auth token (see docs/SECURITY.md)',
  });
});
