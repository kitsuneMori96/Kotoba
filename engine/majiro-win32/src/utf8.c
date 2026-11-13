#include "majiro.h"
#include <stdarg.h>
#include <stdio.h>

uint32_t g_last_key = 0;
uint32_t g_char_len = 0;
char g_char_buf[8] = {0};

static int cp932_lead(unsigned char c) {
  return (c >= 0x81 && c <= 0x9F) || (c >= 0xE0 && c <= 0xFC);
}

/* One engine character: UTF-8 when the bytes are valid, otherwise the
   original CP932 2-byte cell so untouched scripts keep working. */
int k_decode(const unsigned char *p, uint32_t *cp) {
  unsigned char c = p[0];
  if (c == 0) { *cp = 0; return 0; }
  if (c < 0x80) { *cp = c; return 1; }
  if ((c & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) {
    *cp = ((uint32_t)(c & 0x1F) << 6) | (p[1] & 0x3F);
    return 2;
  }
  if ((c & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
    *cp = ((uint32_t)(c & 0x0F) << 12) | ((uint32_t)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
    return 3;
  }
  if ((c & 0xF8) == 0xF0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 &&
      (p[3] & 0xC0) == 0x80) {
    *cp = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(p[1] & 0x3F) << 12) |
          ((uint32_t)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
    return 4;
  }
  if (cp932_lead(c) && p[1]) { *cp = ((uint32_t)p[1] << 8) | c; return 2; }
  *cp = c;
  return 1;
}

static void remember(const char *p, uint32_t cp, int n) {
  g_last_key = cp > 0xFFFF ? 0xFFFD : cp;
  g_char_len = (uint32_t)n;
  n = n > 6 ? 6 : n;
  for (int i = 0; i < n; i++) g_char_buf[i] = p[i];
  g_char_buf[n] = 0;
}

const char *__cdecl k_next(const char *p) {
  uint32_t cp;
  int n;
  if (!p) return p;
  n = k_decode((const unsigned char *)p, &cp);
  if (n == 0) { remember(p, 0, 0); return p; }
  remember(p, cp, n);
  return p + n;
}

int __cdecl k_count(const char *p) {
  int n = 0;
  uint32_t cp;
  int len;
  if (!p) return 0;
  while ((len = k_decode((const unsigned char *)p, &cp)) > 0) {
    p += len;
    n++;
  }
  return n;
}

const char *__cdecl k_skip(const char *p, int n) {
  uint32_t cp;
  int len;
  if (!p || n <= 0) return p;
  while (n-- > 0) {
    len = k_decode((const unsigned char *)p, &cp);
    if (len == 0) break;
    p += len;
  }
  return p;
}

int __cdecl k_is_lead(int b) {
  b &= 0xFF;
  return (b >= 0x81 && b <= 0x9F) || (b >= 0xC0 && b <= 0xFC);
}

char *__cdecl k_lower(char *p) {
  unsigned char *q = (unsigned char *)p;
  uint32_t cp;
  int n;
  if (!p) return p;
  while ((n = k_decode(q, &cp)) > 0) {
    if (n == 1 && cp >= 'A' && cp <= 'Z') q[0] = (unsigned char)(cp + 0x20);
    q += n;
  }
  return p;
}

static uint32_t unit_of(const unsigned char *p, int n, uint32_t cp) {
  WCHAR w[2];
  if (n == 2 && cp932_lead(p[0]) && cp == (((uint32_t)p[1] << 8) | p[0]) &&
      MultiByteToWideChar(932, 0, (const char *)p, 2, w, 2) == 1)
    return w[0];
  return cp;
}

/* _mbschr replacement: callers pass CP932 codes such as 0x8175 for 「, so
   compare by Unicode to match the same character in UTF-8 text too. */
const char *__cdecl k_strchr(const char *s, unsigned int ch) {
  const unsigned char *p = (const unsigned char *)s;
  uint32_t want = ch, cp;
  int n;
  if (!p) return NULL;
  if (ch >= 0x100) {
    unsigned char b[2] = {(unsigned char)(ch >> 8), (unsigned char)ch};
    WCHAR w[2];
    if (MultiByteToWideChar(932, 0, (const char *)b, 2, w, 2) != 1) return NULL;
    want = w[0];
  }
  while ((n = k_decode(p, &cp)) > 0) {
    if (unit_of(p, n, cp) == want) return (const char *)p;
    p += n;
  }
  return ch == 0 ? (const char *)p : NULL;
}
