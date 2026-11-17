import os
from pathlib import Path
import re
import subprocess
import tempfile

source = (Path(__file__).parent / 'src/gdi.c').read_text(encoding='utf-8')
jp = re.search(r'k_legacy_jp_w\[\] = \{(.*?)\};', source, re.S).group(1)
strings = re.findall(r'L"([^"]+)"', jp)
zh = re.search(r'k_legacy_zh\[\] = \{(.*?)\};', source, re.S).group(1)
translations = re.findall(r'L"([^"]+)"', zh)
assert len(strings) == len(translations)
assert 'ゲームを終了します。よろしいですか？' in strings
assert translations[strings.index('ゲームを終了します。よろしいですか？')] == '要退出游戏吗？'
encoded = [text.encode('cp932') for text in strings]
table = ',\n'.join('"' + ''.join(f'\\x{b:02x}' for b in text) + '"' for text in encoded)
start = source.index('static const char *k_legacy_source')
end = source.index('\n/*', start)
matcher = source[start:end]
draw = source[source.index('static BOOL draw_legacy'):source.index('\nstatic BOOL WINAPI my_textout_a')]
program = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef wchar_t WCHAR;
typedef int BOOL;
#define TRUE 1
TABLE
WIDE_TABLES
MATCHER
DRAW
int main(void) {
  char buffers[sizeof(k_legacy_jp) / sizeof(k_legacy_jp[0])][64];
  char reused[64];
  WCHAR glyph[2], rendered[64];
  int i, j, off, w, written;
  for (i = 0; i < k_legacy_n; i++) {
    strcpy(buffers[i], k_legacy_jp[i]);
    assert(find_legacy(buffers[i], strlen(buffers[i])) == i);
    written = 0;
    for (off = 0; off < (int)strlen(buffers[i]); off += 2) {
      assert(draw_legacy(strlen(buffers[i]) - off, 2, i, glyph, &w));
      assert(w == 0 || w == 1);
      if (w) rendered[written++] = glyph[0];
    }
    rendered[written] = 0;
    assert(wcscmp(rendered, k_legacy_zh[i]) == 0);
    assert(draw_legacy(strlen(buffers[i]), strlen(buffers[i]), i, glyph, &w));
    assert(w == 0);
  }
  for (off = 0; off < 64; off += 2)
    for (i = 0; i < k_legacy_n; i++) {
      int n = strlen(buffers[i]);
      if (off < n) assert(find_legacy(buffers[i] + off, n - off) == i);
    }
  for (j = 0; j < k_legacy_n; j++) {
    strcpy(reused, k_legacy_jp[j]);
    assert(find_legacy(reused, strlen(reused)) == j);
    for (off = 0; off < (int)strlen(reused); off += 2)
      assert(find_legacy(reused + off, strlen(reused) - off) == j);
  }
  memset(k_legacy_source, 0, sizeof(k_legacy_source));
  strcpy(reused, k_legacy_jp[7]);
  assert(find_legacy(reused + 2, strlen(reused) - 2) == -1);
  printf("PASS: all %d banners, glyph output, interleaved suffixes, reused buffer, unbound suffix\n", k_legacy_n);
}
'''.replace('TABLE\n', f'static const char k_legacy_jp[{len(strings)}][64] = {{{table}}};\nstatic const int k_legacy_n = {len(strings)};\n', 1)
program = program.replace('WIDE_TABLES', f'static const WCHAR *const k_legacy_jp_w[] = {{{jp}}};\nstatic const WCHAR *const k_legacy_zh[] = {{{zh}}};')
program = program.replace('MATCHER', matcher).replace('DRAW', draw)
with tempfile.TemporaryDirectory(prefix='kotoba-legacy-') as tmp:
    c = Path(tmp) / 'test.c'
    exe = Path(tmp) / 'test'
    c.write_text(program, encoding='utf-8')
    subprocess.run([os.environ.get('CC', 'gcc'), '-Wall', '-Wextra', '-Werror', '-o', str(exe), str(c)], check=True)
    subprocess.run([str(exe)], check=True)
