import test from 'node:test';
import assert from 'node:assert/strict';
import { audit, validateProject, reviseCharacter, controls } from '../src/quality.js';
import { demo } from '../src/demo.js';
const copy = () => structuredClone(demo);
function reviewed() {
  const p = copy();
  p.lines[0].target = '秋还没来。[wait]';
  p.lines[1].target = '我在等那个人。';
  Object.assign(p.lines[1].mentions[0], { entity: 'aki', resolved: true, evidence: '人工核对同场景上下文，保留原文中性表达', expected: '那个人' });
  p.lines[2].target = '莲，等很久了吗？[pause]';
  p.lines.forEach(l => l.reviewed = true);
  return p;
}
test('演示发现译名、指代、控制码与人工审核问题', () => {
  const codes = new Set(audit(validateProject(copy())).map(i => i.code));
  for (const code of ['expression', 'ambiguous', 'controls', 'review']) assert(codes.has(code));
});
test('正确审核稿通过检查', () => assert.deepEqual(audit(reviewed()), []));
test('人物属性不会代替语境代词裁决', () => {
  const p = reviewed(); p.lines[1].mentions[0].expected = '';
  assert(audit(p).some(i => i.code === 'pronoun-policy'));
});
test('修改人物仅使相关句子待审', () => {
  const p = reviewed(); reviseCharacter(p, 'aki', { ...p.characters[0], name: '小秋' });
  assert(p.lines.every(l => !l.reviewed));
});
test('无关人物修改不影响审核，重复保存不影响审核', () => {
  const p = reviewed(); p.characters.push({ id: 'other', name: '路人', aliases: [], pronoun: '未知' });
  reviseCharacter(p, 'other', { ...p.characters[2], name: '游客' });
  reviseCharacter(p, 'aki', { ...p.characters[0] });
  assert(p.lines.every(l => l.reviewed));
});
test('重复行 ID 和无效实体被拒绝', () => {
  const p = copy(); p.lines[1].id = p.lines[0].id; assert.throws(() => validateProject(p));
  const q = copy(); q.lines[0].mentions[0].entity = 'missing'; assert.throws(() => validateProject(q));
});
test('保留控制码顺序和重复次数', () => {
  assert.deepEqual(controls('[wait][wait]{name}%s\\n'), ['[wait]', '[wait]', '{name}', '%s', '\\n']);
  const p = reviewed(); p.lines[0].target += '[wait]'; assert(audit(p).some(i => i.code === 'controls'));
});
test('确认指代必须有证据', () => {
  const p = reviewed(); p.lines[1].mentions[0].evidence = ' '; assert(audit(p).some(i => i.code === 'ambiguous'));
});
