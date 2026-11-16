import os
from pathlib import Path
import re
import subprocess
import tempfile

source = (Path(__file__).parent / 'src/gdi.c').read_text(encoding='utf-8')
jp = re.search(r'k_legacy_jp_w\[\] = \{(.*?)\};', source, re.S).group(1)
strings = re.findall(r'L"([^"]+)"', jp)
encoded = [text.encode('cp932') for text in strings]
table = ',\n'.join('"' + ''.join(f'\\x{b:02x}' for b in text) + '"' for text in encoded)
start = source.index('static const char *k_legacy_source')
end = source.index('\n/*', start)
matcher = source[start:end]
program = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
TABLE
MATCHER
int main(void) {
  char buffers[9][64];
  char reused[64];
  int i, j, off;
  for (i = 0; i < 9; i++) {
    strcpy(buffers[i], k_legacy_jp[i]);
    assert(find_legacy(buffers[i], strlen(buffers[i])) == i);
  }
  for (off = 0; off < 64; off += 2)
    for (i = 0; i < 9; i++) {
      int n = strlen(buffers[i]);
      if (off < n) assert(find_legacy(buffers[i] + off, n - off) == i);
    }
  for (j = 0; j < 9; j++) {
    strcpy(reused, k_legacy_jp[j]);
    assert(find_legacy(reused, strlen(reused)) == j);
    for (off = 0; off < (int)strlen(reused); off += 2)
      assert(find_legacy(reused + off, strlen(reused) - off) == j);
  }
  memset(k_legacy_source, 0, sizeof(k_legacy_source));
  strcpy(reused, k_legacy_jp[7]);
  assert(find_legacy(reused + 2, strlen(reused) - 2) == -1);
  puts("PASS: all 9 banners, interleaved suffixes, reused buffer, unbound suffix");
}
'''.replace('TABLE', f'static const char k_legacy_jp[9][64] = {{{table}}};\nstatic const int k_legacy_n = 9;').replace('MATCHER', matcher)
with tempfile.TemporaryDirectory(prefix='kotoba-legacy-') as tmp:
    c = Path(tmp) / 'test.c'
    exe = Path(tmp) / 'test'
    c.write_text(program, encoding='utf-8')
    subprocess.run([os.environ.get('CC', 'gcc'), '-Wall', '-Wextra', '-Werror', '-o', str(exe), str(c)], check=True)
    subprocess.run([str(exe)], check=True)
