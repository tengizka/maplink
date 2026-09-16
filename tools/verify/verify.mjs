#!/usr/bin/env node
// =============================================================================
//  MapLink · проверки
//  npm run verify
//
//  Дёргает настоящий index.html в jsdom в трёх режимах и на каждой сборке
//  проверяет:
//    · синтаксис инлайнового JS и валидность CSS (postcss)
//    · что каждый getElementById/querySelector('#…') ссылается на id, который
//      есть в разметке (ловит «удалил блок — а код за ним всё ещё дёргает»)
//    · что приложение стартует без исключений в трёх окружениях
//    · stored XSS: в username/note/country/avatar_url/display_name подсовывается
//      payload; проверка падает, если из него собирается живой элемент с
//      обработчиком или происходит breakout из атрибута. Плюс статический
//      scan-xss.mjs: любое `…${u.username}…` без esc() — провал сборки
//    · read-only guard: вне Telegram ни одна запись не должна уйти в Supabase,
//      а в Telegram guard обязан быть выключен
//
//  Заглушки CDN (supabase/maplibre/telegram) намеренно простые: цель — прогнать
//  код приложения по реальным веткам, а не протестировать библиотеки.
// =============================================================================
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import { JSDOM, VirtualConsole } from 'jsdom';
import postcss from 'postcss';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FILE = path.resolve(HERE, '../../index.html');
const src = fs.readFileSync(FILE, 'utf8');
const MODE = process.env.ML_MODE || 'tg';

const problems = [];
const fail = (what, detail) => problems.push(`${what}: ${detail}`);

// ---------------------------------------------------------------- static checks
const inlineJs = [...src.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n');
try { new vm.Script(inlineJs, { filename: 'index.inline.js' }); }
catch (e) { fail('JS-SYNTAX', e.message); }

for (const [, css] of [...src.matchAll(/<style>([\s\S]*?)<\/style>/g)]) {
  try { postcss.parse(css, { from: 'inline' }); }
  catch (e) { fail('CSS-PARSE', String(e.message).split('\n')[0]); }
}

// статический сканер сырых вставок (ловит отсутствующий esc() даже там, куда
// клики в этом прогоне не дошли) — отдельный скрипт, чтобы его можно было
// запускать и руками: node scan-xss.mjs index.html
{
  const scan = spawnSync(process.execPath, [path.join(HERE, 'scan-xss.mjs'), FILE, '--json'], { encoding: 'utf8' });
  let out = null;
  try { out = JSON.parse(scan.stdout); } catch (e) { /* разобралим ниже */ }
  if (!out) fail('SCAN', 'scan-xss.mjs не вернул JSON: ' + String(scan.stdout || scan.stderr).slice(0, 200));
  else if (out.hits.length) fail('RAW-XSS', out.hits.length + ' мест вставляют данные в HTML без экранирования: ' + out.hits[0].sn);
}

{
  const markup = src.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '');
  const declared = new Set([...markup.matchAll(/\bid\s*=\s*"([^"{]+)"/g)].map(m => m[1]));
  const created = new Set([...inlineJs.matchAll(/\.id\s*=\s*['"]([A-Za-z0-9_-]+)['"]/g)].map(m => m[1]));
  const missing = new Set();
  for (const re of [/getElementById\(\s*['"]([A-Za-z0-9_-]+)['"]\s*\)/g, /querySelector(?:All)?\(\s*['"]#([A-Za-z0-9_-]+)['"]\s*\)/g]) {
    for (const m of inlineJs.matchAll(re)) {
      if (!declared.has(m[1]) && !created.has(m[1])) missing.add(m[1]);
    }
  }
  if (missing.size) fail('DOM-IDS', 'нет таких id в разметке: ' + [...missing].join(', '));
}

{
  const open = (src.match(/<script\b/g) || []).length;
  const close = (src.match(/<\/script>/g) || []).length;
  if (open !== close) fail('MARKUP', `дисбаланс <script>: ${open} против ${close}`);
}

// подарок + чистота после выноса письма
{
  const asset = path.resolve(HERE, '../../assets/puzzle.jpg');
  if (!fs.existsSync(asset)) fail('GIFT', 'нет файла assets/puzzle.jpg');
  else {
    const buf = fs.readFileSync(asset);
    if (!(buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff)) fail('GIFT', 'assets/puzzle.jpg не похож на JPEG');
    if (buf.length < 20000) fail('GIFT', 'assets/puzzle.jpg подозрительно маленький: ' + buf.length + ' B');
  }
  if (!src.includes('assets/puzzle.jpg')) fail('GIFT', 'в index.html нет ссылки на assets/puzzle.jpg');
  if (!src.includes("getElementById('giftRowBtn')") || !src.includes('openPuzzle()')) {
    fail('GIFT', 'строка «Подарок» в настройках не ведёт на головоломку');
  }
  if (!/id="puzzleModal"/.test(src)) fail('GIFT', 'пропала разметка головоломки');
  if (src.includes('checkLetterPass') || src.includes('letterPass')) fail('GIFT', 'остался код пароля письма');
  if (/<div class="letter-|id="letterSection/.test(src)) fail('GIFT', 'осталась разметка секретного письма');
  if (/\.letter-(wrap|card|head|kicker|note|text|hint|stamp|body|inner|paper|row|year)\b/.test(src)) fail('GIFT', 'остались CSS-правила письма');
  if (!/id="postcardBtn"[^>]*display:none/.test(src)) fail('NOTE', 'postcardBtn снова видима — это незавершённая фича, её показывать рано');
  // внешний код разрешён только CDN-ный; локальные <script src> сломали бы деплой одним файлом
  const ext = [...src.matchAll(/<script\s+[^>]*src="([^"]+)"/g)].map(m => m[1]);
  const local = ext.filter(u => !/^(https?:)?\/\//.test(u));
  if (local.length) fail('MARKUP', 'локальный <script src> — приложение должно оставаться одним файлом: ' + local.join(', '));
  if (!ext.some(u => /telegram-web-app\.js$/.test(u))) fail('MARKUP', 'пропал SDK Telegram');
}

// ---------------------------------------------------------------- fixtures
// payload'ы: текст-в-разметку и breakout из атрибута
const MAL = 'x"><img src=1 onerror="window.__pwned=1">y';
const ROWS = {
  users: [
    { id: 'u-self', telegram_id: '123', username: MAL, avatar_url: null, invite_code: 'AAAAAA1111', is_private: false },
    { id: 'u-friend', telegram_id: '456', username: MAL, avatar_url: 'https://x.test/" onload="window.__pwned=1', invite_code: 'BBBBBB2222', is_private: false },
  ],
  places: [
    { id: 'p1', user_id: 'u-self', country: 'Italy' + MAL, city: 'Rome' + MAL, note: MAL, visit_date: '2026-08-01',
      is_wishlist: false, lat: 41.9, lon: 12.5, created_at: '2026-08-01' },
    { id: 'p2', user_id: 'u-friend', country: MAL, city: MAL, note: null, visit_date: '2026-08-02',
      is_wishlist: true, lat: 41.9, lon: 12.5, created_at: '2026-08-02' },
  ],
  photos: [{ id: 'ph1', place_id: 'p1', url: 'https://example.com/a.jpg' },
           { id: 'ph2', place_id: 'p2', url: 'https://example.com/b.jpg' }],
  friendships: [
    { id: 'f1', requester_id: 'u-friend', addressee_id: 'u-self', status: 'pending', created_at: '2026-01-01',
      requester: { id: 'u-friend', username: MAL, avatar_url: null } },
    { id: 'f2', requester_id: 'u-self', addressee_id: 'u-friend', status: 'accepted', created_at: '2026-01-01',
      addressee: { id: 'u-friend', username: MAL, avatar_url: null } },
  ],
  reactions: [{ id: 'r1', place_id: 'p1', user_id: 'u-friend', emoji: '❤', created_at: '2026-08-03' }],
  comments: [{ id: 'c1', place_id: 'p1', user_id: 'u-friend', body: MAL, created_at: '2026-08-03', users: { username: MAL } }],
  achievements: [],
};

function builder(table, mode) {
  const self = {};
  for (const m of ['eq', 'neq', 'is', 'in', 'or', 'gte', 'lte', 'gt', 'lt', 'ilike', 'like', 'not', 'filter', 'contains',
                   'order', 'limit', 'range', 'select', 'insert', 'update', 'upsert', 'delete']) self[m] = () => self;
  self.single = () => { mode.single = true; return self; };
  self.maybeSingle = () => { mode.single = true; return self; };
  self.then = (resolve, reject) => {
    const all = ROWS[table] || [];
    const out = mode.single ? { data: all[0] ?? null, error: null } : { data: all, error: null, count: all.length };
    return Promise.resolve(out).then(resolve, reject);
  };
  return self;
}

function makeStubs(window) {
  const noop = () => {};
  window.HTMLCanvasElement.prototype.getContext = function () {
    const grad = { addColorStop: noop };
    const ctx = {
      canvas: this, fillStyle: '', strokeStyle: '', lineWidth: 1, font: '', textAlign: '', globalAlpha: 1,
      fillRect: noop, clearRect: noop, beginPath: noop, moveTo: noop, lineTo: noop, closePath: noop, stroke: noop,
      fill: noop, arc: noop, save: noop, restore: noop, translate: noop, scale: noop, rotate: noop, drawImage: noop,
      setTransform: noop, fillText: noop, measureText: () => ({ width: 10 }), createLinearGradient: () => grad,
      createRadialGradient: () => grad, getImageData: () => ({ data: new Uint8ClampedArray(4) }), putImageData: noop,
      createPattern: () => null, clip: noop, rect: noop, quadraticCurveTo: noop, bezierCurveTo: noop,
      setLineDash: noop, arcTo: noop, ellipse: noop,
    };
    return ctx;
  };
  class FakeMap {
    constructor() {
      this.style = { getPropertyValue: () => '', setProperty: noop };
      this.handlers = {};
    }
    on(ev, cb) { (this.handlers[ev] ||= []).push(cb); return this; }
    off() { return this; } once() { return this; } fire(ev, d) { (this.handlers[ev] || []).forEach(cb => { try { cb(d || {}); } catch (e) {} }); return this; }
    addSource() { return this; } removeSource() { return this; } getSource() { return null; }
    addLayer() { return this; } getLayer() { return null; } removeLayer() { return this; }
    setLayoutProperty() { return this; } setPaintProperty() { return this; }
    fitBounds() { return this; } fitCamera() { return this; } flyTo() { return this; } easeTo() { return this; }
    jumpTo() { return this; } animate() { return this; } stop() { return this; } setProjection() { return this; }
    remove() { return this; } resize() { return this; } queryRenderedFeatures() { return []; }
    getCanvas() { return window.document.createElement('canvas'); } getMapCanvas() { return window.document.createElement('canvas'); }
    getCenter() { return { lng: 0, lat: 0 }; } getZoom() { return 2; } getBearing() { return 0 }; getPitch() { return 0 };
    getBounds() { return { getSouth: () => -80, getNorth: () => 80, getWest: () => -180, getEast: () => 180, contains: () => true }; }
    project() { return { x: 10, y: 10 }; } unproject() { return { lng: 0, lat: 0 }; }
    loaded() { return true; } isStyleLoaded() { return true; } showsGlyphs() { return true; }
    addControl() { return this; } removeControl() { return this; }
  }
  window.maplibregl = {
    Map: FakeMap,
    Marker: class {
      constructor() { this._el = window.document.createElement('div'); }
      setLngLat() { return this; } addTo() { return this; } remove() { return this; }
      getElement() { return this._el; } setOffset() { return this; } setPopup() { return this; } on() { return this; }
      getLngLat() { return { lng: 0, lat: 0 }; }
    },
    Popup: class { setText() { return this; } setHTML() { return this; } addTo() { return this; } remove() { return this; } },
    NavigationControl: class { onAdd() { return window.document.createElement('div'); } },
    AttributionControl: class {}, ScaleControl: class {}, GeolocateControl: class {},
    supported: () => true,
  };
  window.supabase = {
    createClient() {
      return {
        from: (t) => builder(t, {}),
        storage: { from: () => ({
          upload: () => Promise.resolve({ data: { path: 'x' }, error: null }),
          remove: () => Promise.resolve({ data: [], error: null }),
          list: () => Promise.resolve({ data: [], error: null }),
          getPublicUrl: () => ({ data: { publicUrl: 'https://example.com/pub.jpg' } }),
        }) },
        functions: { invoke: () => Promise.resolve({ data: null, error: new Error('stub') }) },
        auth: {
          getUser: () => Promise.resolve({ data: { user: null }, error: null }),
          signInWithToken: () => Promise.resolve({ data: null, error: new Error('stub') }),
          onAuthStateChange: () => ({ data: { subscription: { unsubscribe: noop } } }),
        },
        channel: () => ({ on: () => ({ subscribe: () => ({ unsubscribe: noop }) }), subscribe: () => ({ unsubscribe: noop }) }),
        realtime: { removeChannel: noop },
      };
    },
  };
  if (MODE === 'tg') {
    window.Telegram = {
      WebApp: {
        ready: noop, expand: noop, close: noop, isVersionAtLeast: () => true,
        initDataUnsafe: { user: { id: 123, first_name: 'Tengiz', username: 'tengizka', photo_url: '' }, start_param: null },
        initData: 'query_id=AAA&user=%7B%22id%22%3A123%7D&auth_date=' + Math.floor(Date.now() / 1000) + '&hash=deadbeef',
        setHeaderColor: noop, setBackgroundColor: noop, disableVerticalSwipes: noop,
        HapticFeedback: { impactOccurred: noop, notificationOccurred: noop, selectionChanged: noop },
        CloudStorage: {
          set: (k, v, cb) => cb && cb(null, true), get: (k, cb) => cb && cb(null, null),
          remove: (k, cb) => cb && cb(null, true), getKeys: (cb) => cb && cb(null, []),
        },
        openTelegramLink: noop, openLink: noop, showAlert: noop, showPopup: noop, sendData: noop,
        BackButton: { isVisible: false, show: noop, hide: noop, onClick: noop, offClick: noop },
        MainButton: { text: '', isVisible: true, show: noop, hide: noop, onClick: noop, offClick: noop, setText: noop },
        ThemeParams: { bg_color: '#FBF3EE' },
      },
    };
  }
  const ctxNode = new (class { constructor() { this.state = 'running'; this.destination = {}; this.sampleRate = 44100; } })();
  const param = () => ({ value: 0, setValueAtTime() {}, linearRampToValueAtTime() {}, exponentialRampToValueAtTime() {}, setTargetAtTime() {}, cancelScheduledValues() {} });
  const node = () => ({ gain: param(), frequency: param(), Q: param(), delayTime: param(), pan: param(), playbackRate: param(),
    type: '', curve: null, buffer: null, loop: false, onended: null, connect() {}, disconnect() {}, start() {}, stop() {} });
  window.AudioContext = class {
    constructor() { this.currentTime = 0; this.destination = {}; this.state = 'running'; this.sampleRate = 44100; }
    createGain = node; createOscillator = node; createBiquadFilter = node; createDelay = node; createStereoPanner = node;
    createDynamicsCompressor = node; createBufferSource = node; createWaveShaper = node; createConvolver = node;
    createAnalyser = node; createPanner = node; createChannelMerger = node; createChannelSplitter = node;
    createPeriodicWave = () => ({});
    createBuffer = (ch, len) => ({ length: len, sampleRate: 44100, getChannelData: () => new Float32Array(len) });
    resume = () => Promise.resolve(); suspend = () => Promise.resolve(); close = () => Promise.resolve();
  };
  window.webkitAudioContext = window.AudioContext;
  window.IntersectionObserver = class { constructor() {} observe() {} unobserve() {} disconnect() {} takeRecords() { return []; } };
  window.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
  window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
  window.requestIdleCallback = window.requestIdleCallback || (cb => setTimeout(() => cb({ didTimeout: false, timeRemaining: () => 8 }), 1));
  window.scrollTo = () => {};
  window.Image = class { set src(v) { this._src = v; setTimeout(() => this.onload && this.onload(), 0); } get src() { return this._src; } };
  window.URL.createObjectURL = () => 'blob:stub';
  window.URL.revokeObjectURL = () => {};
  window.alert = () => {}; window.confirm = () => true;
  window.navigator.clipboard = { writeText: () => Promise.resolve() };
  const supa = [];
  window.__supa = supa;
  window.fetch = (url, opts) => {
    const u = String(url);
    const method = String((opts && opts.method) || (typeof url === 'object' && url.method) || 'GET').toUpperCase();
    if (/supabase/.test(u)) supa.push(method);
    if (/nominatim/.test(u)) return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([
      { lat: '41.90', lon: '12.50', display_name: 'Roma, Lazio, Italia', importance: 0.6, type: 'city',
        addresstype: 'city', address: { country: 'Italia', country_code: 'it' }, boundingbox: ['41', '42', '12', '13'] }]) });
    if (/restcountries/.test(u)) return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([{ flags: { png: 'https://flagcdn.com/w320/it.png' }, name: { common: 'Italy' } }]) });
    if (/wikipedia|wikimedia/.test(u)) return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ thumbnail: { source: 'https://example.com/wiki.jpg' }, pageid: 1, title: 'x' }) });
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}), text: () => Promise.resolve('{}') });
  };
  return supa;
}

// ---------------------------------------------------------------- boot
const htmlForDom = src
  .replace(/<script[^>]*\bsrc=[^>]*><\/script>/gi, '')
  .replace(/<link[^>]*(fonts|maplibre)[^>]*>/gi, '');

const vc = new VirtualConsole();
const consoleErrors = [];
vc.on('error', (...a) => consoleErrors.push(a.map(String).join(' ')));
vc.on('jsdomError', e => consoleErrors.push('jsdomError: ' + (e && e.message)));

const url = MODE === 'tg' ? 'https://tengizka.github.io/MapLink/'
  : MODE === 'webdemo' ? 'https://tengizka.github.io/MapLink/?demo=1'
  : 'https://tengizka.github.io/MapLink/';

const dom = new JSDOM(htmlForDom, {
  runScripts: 'dangerously', pretendToBeVisual: true, url, virtualConsole: vc,
  beforeParse(window) {
    window.addEventListener('error', e => consoleErrors.push('window.onerror: ' + e.message));
    makeStubs(window);
  },
});
const win = dom.window;
const wait = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  await wait(1800);
  for (const sel of ['#navFeed', '#navFriends', '#navProfile', '#navHome', '.navitem', '.tab']) {
    for (const el of win.document.querySelectorAll(sel)) {
      try { el.dispatchEvent(new win.MouseEvent('click', { bubbles: true })); } catch {}
    }
  }
  await wait(900);
  try { win.__openPlaceView && win.__openPlaceView('p1'); } catch (e) { fail('NAV', '__openPlaceView: ' + e.message); }
  await wait(400);
  try {
    const fab = win.document.getElementById('fabAdd');
    if (fab) fab.dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
    const nb = win.document.getElementById('addNextBtn');
    if (nb) nb.dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  } catch (e) { fail('NAV', 'add modal: ' + e.message); }
  await wait(400);

  // прокликиваем нижнюю навигацию: каждый экран должен отрисоваться без падения,
  // иначе проверка ниже смотрит только на стартовый вью
  try {
    const items = [...win.document.querySelectorAll('.navitem')];
    if (items.length < 3) fail('NAV', 'внизу только ' + items.length + ' вкладок — проверь разметку навигации');
    for (const b of items) {
      b.dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
      await wait(150);
    }
  } catch (e) { fail('NAV', 'прокликать экраны не вышло: ' + e.message); }
  await wait(200);

  // XSS: живой элемент-обработчик или исполнение payload = провал
  const liveHandlers = win.document.querySelectorAll('[onerror],[onload],[onmouseover],iframe,object,embed').length;
  if (liveHandlers) fail('XSS', liveHandlers + ' живой(ых) элемент(ов) с обработчиком собраны из пользовательских данных');
  if (win.__pwned) fail('XSS', 'payload выполнился (window.__pwned=' + win.__pwned + ')');

  // read-only guard. Снимок ДО пробного запроса: сам зонд тоже идёт через window.fetch,
  // и без снимка он выглядел бы как «приложение тронуло базу».
  const appReqs = (win.__supa || []).slice();
  const appWrites = appReqs.filter(m => m !== 'GET' && m !== 'HEAD').length;
  const probe = await win.fetch('https://wfepsxuvvgfloatrfqba.supabase.co/rest/v1/places', { method: 'POST', body: '{}' });
  if (MODE === 'tg') {
    if (probe.status === 405) fail('GUARD', 'read-only guard активен внутри Telegram — приложение не сможет сохранять');
    if (appWrites) fail('GUARD', 'в telegram-режиме приложение сделало ' + appWrites + ' записей — так и должно быть, но проверь, что читается');
  } else if (MODE === 'webdemo') {
    if (probe.status !== 405) fail('GUARD', 'POST к Supabase прошёл в демо-режиме (status ' + probe.status + ')');
    if (appWrites) fail('GUARD', appWrites + ' записей ушло в Supabase в read-only');
    if (win.document.getElementById('tgGate')) fail('GATE', 'гейт показан при ?demo=1');
  } else {
    if (!win.document.getElementById('tgGate')) fail('GATE', 'вне Telegram нет экрана-приглашения');
    if (appReqs.length) fail('GATE', 'без Telegram приложение тронуло Supabase (' + appReqs.length + ' запросов)');
  }

  const SEL = { ticket: '.journal-ticket', diary: '.diary-entry', friend: '.friend-row', ig: '.ig-cell', rank: '.rank-row', card: '.ticket-card' };
  const rendered = {};
  for (const [k, s] of Object.entries(SEL)) rendered[k] = win.document.querySelectorAll(s).length;
  const total = Object.values(rendered).reduce((a, b) => a + b, 0);
  if (MODE === 'tg' && !rendered.ticket) fail('BOOT', 'в telegram-режиме нет ни одной карточки пути');
  if (MODE === 'webdemo' && !total) fail('BOOT', 'в демо не отрисована ни одна карточка — проверь, что ?demo=1 вообще что-то загружает');

  const noise = /Could not parse CSS|Not implemented|navigation|Read from origin|favicon/i;
  const errs = consoleErrors.filter(e => !noise.test(e));
  if (errs.length) fail('BOOT-ERRORS', errs.slice(0, 3).join(' ;; ').slice(0, 400));

  console.log(JSON.stringify({ mode: MODE, ok: problems.length === 0, problems, rendered, requests: (win.__supa || []).length }, null, 2));
  dom.window.close();
  process.exit(problems.length ? 1 : 0);
})();
