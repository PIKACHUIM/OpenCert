// scripts/check-i18n-keys.mjs
// 校验 zh-CN.json 与 en-US.json 的 key 集合是否完全一致。
// 用法：node scripts/check-i18n-keys.mjs
// 退出码：0=一致，1=有差异
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const localesDir = path.resolve(__dirname, '../src/locales');

function flattenKeys(obj, prefix = '') {
  const keys = [];
  for (const [k, v] of Object.entries(obj)) {
    const full = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      keys.push(...flattenKeys(v, full));
    } else {
      keys.push(full);
    }
  }
  return keys;
}

function loadJSON(file) {
  const raw = fs.readFileSync(file, 'utf8');
  try {
    return JSON.parse(raw);
  } catch (e) {
    console.error(`[i18n-check] JSON 解析失败: ${file}`);
    console.error(e.message);
    process.exit(2);
  }
}

const zh = loadJSON(path.join(localesDir, 'zh-CN.json'));
const en = loadJSON(path.join(localesDir, 'en-US.json'));

const zhKeys = new Set(flattenKeys(zh));
const enKeys = new Set(flattenKeys(en));

const missingInEn = [...zhKeys].filter((k) => !enKeys.has(k)).sort();
const missingInZh = [...enKeys].filter((k) => !zhKeys.has(k)).sort();

if (missingInEn.length === 0 && missingInZh.length === 0) {
  console.log(`[i18n-check] OK: zh-CN 与 en-US key 完全一致（共 ${zhKeys.size} 个）`);
  process.exit(0);
}

if (missingInEn.length > 0) {
  console.error(`[i18n-check] en-US.json 缺少 ${missingInEn.length} 个 key:`);
  missingInEn.forEach((k) => console.error(`  - ${k}`));
}
if (missingInZh.length > 0) {
  console.error(`[i18n-check] zh-CN.json 缺少 ${missingInZh.length} 个 key:`);
  missingInZh.forEach((k) => console.error(`  - ${k}`));
}
process.exit(1);
