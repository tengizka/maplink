// Статический сканер: сырые данные пользователя, вставленные прямо в HTML.
// Ловит именно то, что нельзя увидеть глазами: пропавший esc()/escAttr() в шаблоне.
// Запуск: node scan-xss.mjs [файл]   (по умолчанию ../../index.html)
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const file = process.argv[2] || path.resolve(HERE, '../../index.html');
const src = fs.readFileSync(file, 'utf8');
const js = [...src.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n');

const RISKY = /\b[A-Za-z_$][\w$.?]*\.(?:username|display_name|full_name|note|body|caption|bio|city|country|label|text|message|quote_text)\b/g;
const SAFE = /(?:^|[^A-Za-z0-9_$])(?:esc|escAttr|escMultiline|escHtml|clip|clean[A-Za-z]*|safeId|safeImgUrl|Number|String|encodeURIComponent|escape|fmt)\s*[(.]/;
const HTMLISH = /(?:innerHTML|insertAdjacentHTML|outerHTML|<div|<span|<b>|<\/|class="|style="|url\()/;

const hits = [];
let m;
while ((m = RISKY.exec(js))) {
  const i = m.index;
  const before = js.slice(Math.max(0, i - 60), i);
  const after = js.slice(i + m[0].length, i + m[0].length + 90);
  const interp = /\$\{\s*$/.test(before) || /['"`]\s*\+{1,2}\s*\(?\s*$/.test(before) || /\+\s*$/.test(before);
  if (!interp || SAFE.test(before) || !HTMLISH.test(before + after)) continue;
  hits.push({ line: js.slice(0, i).split('\n').length, sn: (before + m[0] + after).replace(/\s+/g, ' ').slice(-130) });
}

if (process.argv[3] === '--json') {
  console.log(JSON.stringify({ file, hits }));
} else {
  console.log(file + ': сырых вставок — ' + hits.length);
  for (const h of hits.slice(0, 40)) console.log('  строка ' + h.line + ': …' + h.sn);
}
process.exit(hits.length ? 1 : 0);
