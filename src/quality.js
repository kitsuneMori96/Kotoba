export function validateProject(p) {
  if (!p || typeof p.name !== 'string' || !Array.isArray(p.characters) || !Array.isArray(p.lines) || !p.lines.length) throw Error('需要 name、characters 和非空 lines');
  const ids = new Set();
  for (const c of p.characters) {
    if (!c.id || typeof c.id !== 'string' || ids.has(c.id) || typeof c.name !== 'string' || !c.name || !Array.isArray(c.aliases) || c.aliases.some(a => typeof a !== 'string' || !a) || !['他', '她', '它', '未知'].includes(c.pronoun)) throw Error('人物字段或 ID 无效');
    ids.add(c.id);
  }
  const lines = new Set();
  for (const l of p.lines) {
    if (!l.id || typeof l.id !== 'string' || lines.has(l.id) || typeof l.source !== 'string' || !l.source || typeof l.target !== 'string' || typeof l.route !== 'string' || typeof l.scene !== 'string' || typeof l.speaker !== 'string' || (l.speaker && !ids.has(l.speaker)) || !Array.isArray(l.mentions)) throw Error('剧本行无效或 ID 重复');
    lines.add(l.id);
    const mentions = new Set();
    for (const m of l.mentions) {
      if (typeof m.id !== 'string' || !m.id || mentions.has(m.id) || !['name', 'pronoun'].includes(m.kind) || typeof m.source !== 'string' || !m.source || !l.source.includes(m.source) || (m.entity !== null && !ids.has(m.entity)) || typeof m.resolved !== 'boolean' || (m.resolved && !m.entity) || typeof m.evidence !== 'string' || typeof m.expected !== 'string') throw Error('提及标注无效');
      mentions.add(m.id);
    }
  }
  return p;
}

export function controls(text) {
  return text.match(/\[[^\]\r\n]+\]|\{[^}\r\n]+\}|%\d*\$?[sd]|\\[nrt]/g) ?? [];
}

export function audit(p) {
  const issues = [];
  const add = (line, code, message, mention = null) => issues.push({ line: line.id, code, message, mention, severity: 'error' });
  for (const l of p.lines) {
    if (!l.target.trim()) add(l, 'empty', '缺少译文');
    if (JSON.stringify(controls(l.source)) !== JSON.stringify(controls(l.target))) add(l, 'controls', '控制码内容或顺序不一致');
    for (const m of l.mentions) {
      if (!m.resolved || !m.entity || !m.evidence.trim()) { add(l, 'ambiguous', `「${m.source}」缺少指代裁决或证据`, m.id); continue; }
      const c = p.characters.find(c => c.id === m.entity);
      const expected = m.expected || (m.kind === 'name' ? c.name : '');
      if (m.kind === 'pronoun' && !m.expected) add(l, 'pronoun-policy', `「${m.source}」需要当前语境的明确表达，不从人物属性自动推定`, m.id);
      if (expected && !l.target.includes(expected)) add(l, 'expression', `「${m.source}」应表达为「${expected}」`, m.id);
    }
    if (l.reviewed !== true) add(l, 'review', '需要人工确认完整译文，规则检查不等于语义正确');
  }
  return issues;
}

export function reviseCharacter(p, id, patch) {
  const c = p.characters.find(c => c.id === id);
  if (!c) throw Error('人物不存在');
  const next = { ...c, name: patch.name, pronoun: patch.pronoun, aliases: patch.aliases };
  const changed = JSON.stringify(c) !== JSON.stringify(next);
  Object.assign(c, next);
  if (changed) for (const l of p.lines) if (l.speaker === id || l.mentions.some(m => m.entity === id)) l.reviewed = false;
  return validateProject(p);
}
