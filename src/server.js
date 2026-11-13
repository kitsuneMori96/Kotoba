import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { audit, validateProject, reviseCharacter } from './quality.js';
import { demo } from './demo.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const data = process.env.KOTOBA_DATA_DIR || join(root, 'data');
mkdirSync(data, { recursive: true });
const db = new DatabaseSync(join(data, 'kotoba.sqlite'));
db.exec('PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS versions (revision INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT NOT NULL, action TEXT NOT NULL, document TEXT NOT NULL)');
const latest = () => { const r = db.prepare('SELECT * FROM versions ORDER BY revision DESC LIMIT 1').get(); return r ? { revision: r.revision, project: JSON.parse(r.document) } : { revision: 0, project: null }; };
const save = (p, action) => { validateProject(p); db.prepare('INSERT INTO versions(created,action,document) VALUES(?,?,?)').run(new Date().toISOString(), action, JSON.stringify(p)); return latest(); };
const port = Number(process.env.PORT || 4173);
const origin = `http://127.0.0.1:${port}`;
const assets = { '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'] };
const server = http.createServer(async (req, res) => {
  const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(body)); };
  try {
    if (req.headers.host !== `127.0.0.1:${port}` || (req.headers.origin && req.headers.origin !== origin)) return send(403, { error: '仅允许本地工作台访问' });
    const path = new URL(req.url, origin).pathname;
    if (req.method === 'GET' && assets[path]) {
      const [name, type] = assets[path];
      res.writeHead(200, { 'Content-Type': type, 'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'", 'X-Content-Type-Options': 'nosniff' });
      return res.end(readFileSync(join(root, 'public', name)));
    }
    if (req.method === 'GET' && path === '/api/project') { const state = latest(); return send(200, { ...state, issues: state.project ? audit(state.project) : [] }); }
    if (req.method === 'GET' && path === '/api/history') return send(200, db.prepare('SELECT revision,created,action FROM versions ORDER BY revision DESC LIMIT 50').all());
    if (req.method === 'GET' && path === '/api/export') {
      const { project } = latest();
      if (!project) return send(404, { error: '尚未导入剧本' });
      const issues = audit(project);
      if (issues.length) return send(409, { error: '存在未解决问题，禁止导出', issues });
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="kotoba-reviewed.json"' });
      return res.end(JSON.stringify(project, null, 2));
    }
    if (req.method !== 'POST' || req.headers['x-kotoba'] !== 'workbench') return send(404, { error: '接口不存在' });
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > 2_000_000) return send(413, { error: '导入上限为 2 MB' }); chunks.push(chunk); }
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
    const state = latest();
    if (body.revision !== state.revision) return send(409, { error: '数据已更新，请刷新后重试' });
    let p = state.project;
    if (path === '/api/import' || path === '/api/demo') {
      p = structuredClone(path === '/api/demo' ? demo : body.project);
      validateProject(p);
      for (const l of p.lines) l.reviewed = false;
    } else {
      if (!p) return send(404, { error: '尚未导入剧本' });
      if (path === '/api/character') reviseCharacter(p, body.id, body.character);
      else if (path === '/api/line') {
        const l = p.lines.find(l => l.id === body.id);
        if (!l) return send(404, { error: '句子不存在' });
        if (typeof body.target !== 'string' || !Array.isArray(body.mentions)) throw Error('译文数据无效');
        if (JSON.stringify(body.mentions.map(m => [m.id, m.source, m.kind])) !== JSON.stringify(l.mentions.map(m => [m.id, m.source, m.kind]))) throw Error('不允许修改原文提及定义');
        l.target = body.target; l.mentions = body.mentions; l.reviewed = body.reviewed === true;
        validateProject(p);
        if (l.reviewed && audit(p).some(i => i.line === l.id)) throw Error('请先解决本句规则问题，再确认审核');
      } else return send(404, { error: '接口不存在' });
    }
    send(200, save(p, path.slice(5)));
  } catch (error) { send(400, { error: error.message }); }
});
server.listen(port, '127.0.0.1', () => console.log(`Kotoba: ${origin}`));
