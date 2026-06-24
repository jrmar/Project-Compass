import puppeteer from 'puppeteer';
import { writeFileSync, mkdirSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const dir = join(__dirname, 'temporary screenshots');
mkdirSync(dir, { recursive: true });

const url    = process.argv[2] || 'http://localhost:3000';
const label  = process.argv[3] || '';

// auto-increment
const existing = readdirSync(dir).filter(f => f.endsWith('.png'));
const nums = existing.map(f => parseInt(f.match(/^screenshot-(\d+)/)?.[1] ?? '0')).filter(Boolean);
const n = nums.length ? Math.max(...nums) + 1 : 1;
const filename = label ? `screenshot-${n}-${label}.png` : `screenshot-${n}.png`;
const outPath = join(dir, filename);

const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox','--disable-setuid-sandbox'] });
const page    = await browser.newPage();
await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1.5 });
await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 });
await new Promise(r => setTimeout(r, 800));
const full = process.argv[4] === 'full';
await page.screenshot({ path: outPath, fullPage: full });
await browser.close();

console.log('Saved:', outPath);
