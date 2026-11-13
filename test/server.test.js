import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { demo } from '../src/demo.js';

test('HTTP 导入、审核门禁、并发保护、历史和 SQLite 重启持久化', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kotoba-test-'));
  let child;
  const start = async () => {
    child = spawn(process.execPath, ['src/server.js'], { env: { ...process.env, PORT: '4179', KOTOBA_DATA_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe'] });
    await new Promise((resolve, reject) => {
      child.once('error', reject); child.once('exit', code => reject(Error(`server exit ${code}`)));
      child.stdout.once('data', resolve);
    });
  };
  const stop = async () => { const done = once(child, 'exit'); child.kill(); await done; child = null; };
  const get = path => fetch(`http://127.0.0.1:4179/api/${path}`);
  let revision = 0;
  const post = (path, body, extra = {}) => fetch(`http://127.0.0.1:4179/api/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Kotoba': 'workbench', ...extra }, body: JSON.stringify({ revision, ...body }) });
  try {
    await start();
    assert.equal((await get('project')).status, 200);
    assert.equal((await post('demo', {}, { Origin: 'https://other.invalid' })).status, 403);
    let r = await post('import', { project: demo }); assert.equal(r.status, 200); revision = (await r.json()).revision;
    assert.equal((await get('export')).status, 409);
    const first = structuredClone(demo.lines[0]);
    assert.equal((await post('line', { ...first, reviewed: true })).status, 400);
    assert.equal((await post('line', { ...first, revision: 0 })).status, 409);
    const lines = structuredClone(demo.lines);
    lines[0].target = '秋还没来。[wait]';
    lines[1].target = '我在等那个人。'; Object.assign(lines[1].mentions[0], { entity: 'aki', resolved: true, evidence: '人工核对', expected: '那个人' });
    lines[2].target = '莲，等很久了吗？[pause]';
    for (const l of lines) { r = await post('line', { ...l, reviewed: true }); assert.equal(r.status, 200); revision = (await r.json()).revision; }
    r = await get('export'); assert.equal(r.status, 200); assert.equal((await r.json()).lines[1].target, lines[1].target);
    await stop(); await start();
    assert.equal((await (await get('project')).json()).revision, revision);
    r = await post('character', { id: 'aki', character: { ...demo.characters[0], name: '小秋' } }); assert.equal(r.status, 200);
    assert.equal((await get('export')).status, 409);
    assert.equal((await (await get('history')).json()).length, 5);
    const invalid = structuredClone(demo); invalid.lines[0].mentions[0].entity = 'missing'; revision = (await r.json()).revision;
    assert.equal((await post('import', { project: invalid })).status, 400);
  } finally { if (child) await stop(); await rm(dir, { recursive: true, force: true }); }
});
