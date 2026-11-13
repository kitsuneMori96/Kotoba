const $ = s => document.querySelector(s);
let state = { project: null, revision: 0, issues: [] }, selected = null;
const el = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; };
const notify = text => { $('#notice').textContent = text; };
async function api(path, body) {
  const r = await fetch(`/api/${path}`, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Kotoba': 'workbench' }, body: JSON.stringify({ ...body, revision: state.revision }) });
  const data = await r.json(); if (!r.ok) throw Error(data.error); return data;
}
const safe = fn => async (...args) => { try { await fn(...args); } catch (e) { notify(e.message); } };
async function refresh() {
  const route = $('#route').value;
  state = await api('project');
  $('#title').textContent = state.project?.name || '让每一句，都有据可依。';
  $('#stats').replaceChildren();
  for (const [v, label] of [[state.project?.lines.length || 0, '剧本句数'], [state.issues.length, '待处理问题'], [state.revision, '修订版本']]) { const d = el('div'); d.append(el('strong', v), el('span', label)); $('#stats').append(d); }
  $('#route').replaceChildren(new Option('全部路线', ''));
  for (const r of new Set(state.project?.lines.map(l => l.route))) $('#route').add(new Option(r, r));
  if ([...$('#route').options].some(o => o.value === route)) $('#route').value = route;
  $('#export').disabled = !state.project || state.issues.length > 0;
  renderLines(); renderCharacters();
}
function renderLines() {
  if (!state.project) return;
  const lines = state.project.lines.filter(l => (!$('#route').value || l.route === $('#route').value) && (!$('#errors-only').checked || state.issues.some(i => i.line === l.id)));
  if (!lines.some(l => l.id === selected)) selected = lines[0]?.id;
  $('#count').textContent = `${lines.length} 句`;
  $('#line-list').replaceChildren();
  for (const l of lines) {
    const n = el('button', undefined, `line-item ${l.id === selected ? 'active' : ''}`);
    const count = state.issues.filter(i => i.line === l.id).length;
    n.append(el('small', `${l.route} / ${l.scene} · ${l.id}`), el('p', l.source), el('span', count ? `${count} 个待处理` : '已审核', `badge ${count ? '' : 'good'}`));
    n.onclick = () => { selected = l.id; renderLines(); }; $('#line-list').append(n);
  }
  renderEditor();
}
function field(label, input) { const n = el('label', label, 'field'); n.append(input); return n; }
function text(value, placeholder = '') { const n = el('input'); n.type = 'text'; n.value = value; n.placeholder = placeholder; return n; }
function renderEditor() {
  const host = $('#editor'); host.replaceChildren();
  const l = state.project.lines.find(l => l.id === selected);
  if (!l) { host.append(el('p', '此筛选下没有待处理句子。', 'empty')); return; }
  const speaker = state.project.characters.find(c => c.id === l.speaker)?.name || '旁白 / 未知';
  host.append(el('h2', `${speaker} · ${l.scene}`));
  const scene = state.project.lines.filter(n => n.route === l.route && n.scene === l.scene);
  const index = scene.findIndex(n => n.id === l.id);
  host.append(el('div', `同路线场景上下文：${scene.slice(Math.max(0, index - 1), index + 2).map(n => n.source).join(' / ')}`, 'context'));
  host.append(el('h3', '日文原文'), el('div', l.source, 'source'), el('h3', '中文译文'));
  const target = el('textarea'); target.value = l.target; target.setAttribute('aria-label', '中文译文'); host.append(target);
  const issues = state.issues.filter(i => i.line === l.id);
  if (issues.length) { const ul = el('ul', undefined, 'issues'); for (const i of issues) ul.append(el('li', i.message)); host.append(ul); }
  host.append(el('h3', '实体与指代裁决'));
  const mentions = structuredClone(l.mentions);
  for (const m of mentions) {
    const box = el('div', undefined, 'mention'); box.append(el('b', `${m.source} · ${m.kind === 'name' ? '人名' : '指代'}`));
    const grid = el('div', undefined, 'mention-grid');
    const entity = el('select'); entity.add(new Option('尚未确定', ''));
    for (const c of state.project.characters) entity.add(new Option(`${c.name} (${c.id})`, c.id));
    entity.value = m.entity || ''; entity.onchange = () => { m.entity = entity.value || null; m.resolved = false; resolved.checked = false; };
    const expected = text(m.expected, m.kind === 'name' ? '留空使用人物标准译名' : '如：她 / 那个人（必须明确）'); expected.oninput = () => { m.expected = expected.value; };
    grid.append(field('指向人物', entity), field('本处允许表达', expected)); box.append(grid);
    const evidence = text(m.evidence, '填写当前路线内的原文证据，或人工裁决依据'); evidence.oninput = () => { m.evidence = evidence.value; }; box.append(field('裁决证据', evidence));
    const resolved = el('input'); resolved.type = 'checkbox'; resolved.checked = m.resolved; resolved.onchange = () => { m.resolved = resolved.checked; };
    const check = el('label'); check.append(resolved, document.createTextNode(' 已确认实体与当前语境表达')); box.append(check); host.append(box);
  }
  const actions = el('div', undefined, 'editor-actions');
  for (const [label, reviewed] of [['保存草稿', false], ['确认审核', true]]) {
    const b = el('button', label, reviewed ? 'primary' : ''); b.onclick = safe(async () => {
      await api('line', { id: l.id, target: target.value, mentions, reviewed });
      notify(reviewed ? '审核已确认并保存；修订可追溯。' : '草稿已保存。'); await refresh();
    }); actions.append(b);
  }
  host.append(actions);
}
function renderCharacters() {
  const host = $('#characters-view'); host.replaceChildren();
  for (const c of state.project?.characters || []) {
    const card = el('div', undefined, 'character'); card.append(el('h2', c.name), el('p', `稳定实体 ID：${c.id}`));
    const name = text(c.name), aliases = text(c.aliases.join('、')), pronoun = el('select');
    for (const p of ['未知', '他', '她', '它']) pronoun.add(new Option(p, p)); pronoun.value = c.pronoun;
    card.append(field('标准译名', name), field('原文别名（顿号分隔）', aliases), field('人物默认代词（不自动覆盖语境）', pronoun));
    const b = el('button', '保存人物并标记关联句待审'); b.onclick = safe(async () => {
      await api('character', { id: c.id, character: { name: name.value, aliases: aliases.value.split('、').map(s => s.trim()).filter(Boolean), pronoun: pronoun.value } });
      notify('人物已保存，受影响句子需要重新审核。'); await refresh();
    }); card.append(b); host.append(card);
  }
}
$('#demo').onclick = safe(async () => { if (state.project && !confirm('载入演示会替换当前工作稿，旧版本仍保留在本地数据库。继续？')) return; await api('demo', {}); selected = null; await refresh(); notify('演示已载入：请修复错译名、未决指代和缺失控制码。'); });
$('#import').onchange = safe(async e => { const f = e.target.files[0]; if (!f) return; try { if (f.size > 2_000_000) throw Error('导入上限为 2 MB'); const project = JSON.parse(await f.text()); if (state.project && !confirm('导入将替换当前工作稿，旧版本保留。继续？')) return; await api('import', { project }); selected = null; await refresh(); notify('导入成功，所有句子需重新审核。'); } finally { e.target.value = ''; } });
$('#export').onclick = safe(async () => { const r = await fetch('/api/export'); if (!r.ok) throw Error((await r.json()).error); const url = URL.createObjectURL(await r.blob()); const a = el('a'); a.href = url; a.download = 'kotoba-reviewed.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
$('#history').onclick = safe(async () => { const rows = await api('history'); $('#history-list').replaceChildren(...rows.map(r => el('div', `v${r.revision} · ${r.created} · ${r.action}`))); $('#history-dialog').showModal(); });
$('#close-history').onclick = () => $('#history-dialog').close();
$('#route').onchange = renderLines; $('#errors-only').onchange = renderLines;
for (const tab of ['lines', 'characters']) $(`#tab-${tab}`).onclick = () => { for (const t of ['lines', 'characters']) { $(`#${t}-view`).hidden = tab !== t; $(`#tab-${t}`).classList.toggle('selected', tab === t); } };
safe(refresh)();
