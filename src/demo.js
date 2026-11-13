export const demo = {
  name: '雨后的约定 · 质量演示',
  characters: [
    { id: 'aki', name: '秋', aliases: ['アキ', '秋'], pronoun: '她' },
    { id: 'ren', name: '莲', aliases: ['レン'], pronoun: '他' }
  ],
  lines: [
    { id: 'common-001', route: '共通线', scene: '车站', speaker: 'ren', source: 'アキはまだ来ていない。[wait]', target: '阿琪还没来。[wait]', reviewed: false, mentions: [{ id: 'm1', source: 'アキ', kind: 'name', entity: 'aki', resolved: true, evidence: '本句明确点名アキ，对应人物秋。', expected: '' }] },
    { id: 'common-002', route: '共通线', scene: '车站', speaker: 'ren', source: 'あの人を待っている。', target: '我在等他。', reviewed: false, mentions: [{ id: 'm1', source: 'あの人', kind: 'pronoun', entity: null, resolved: false, evidence: '', expected: '' }] },
    { id: 'aki-001', route: '秋线', scene: '重逢', speaker: 'aki', source: 'レン、待った？[pause]', target: '莲，等很久了吗？', reviewed: false, mentions: [{ id: 'm1', source: 'レン', kind: 'name', entity: 'ren', resolved: true, evidence: '本句直接呼唤レン。', expected: '' }] }
  ]
};
