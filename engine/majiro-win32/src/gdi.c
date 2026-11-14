#include "majiro.h"
#include <string.h>
#include <wchar.h>

typedef BOOL (WINAPI *textout_w_t)(HDC, int, int, LPCWSTR, int);
typedef BOOL (WINAPI *extent_w_t)(HDC, LPCWSTR, int, LPSIZE);
typedef BOOL (WINAPI *metrics_w_t)(HDC, LPTEXTMETRICW);
typedef HFONT (WINAPI *font_w_t)(const LOGFONTW *);
typedef int (WINAPI *addfont_w_t)(LPCWSTR);

typedef BOOL (WINAPI *textout_a_t)(HDC, int, int, LPCSTR, int);
typedef BOOL (WINAPI *extent_a_t)(HDC, LPCSTR, int, LPSIZE);
typedef BOOL (WINAPI *metrics_a_t)(HDC, LPTEXTMETRICA);
typedef HFONT (WINAPI *font_a_t)(const LOGFONTA *);
typedef int (WINAPI *addfont_a_t)(LPCSTR);

static textout_w_t real_textout_w;
static extent_w_t real_extent_w;
static metrics_w_t real_metrics_w;
static font_w_t real_font_w;
static addfont_w_t real_addfont_w;

static textout_a_t real_textout_a;
static extent_a_t real_extent_a;
static metrics_a_t real_metrics_a;
static font_a_t real_font_a;
static addfont_a_t real_addfont_a;

static WCHAR g_face[LF_FACESIZE];

/* UTF-8 first; fall back to CP932 per string so legacy scripts still render. */
static int to_wide(const char *s, int n, WCHAR *out, int cap) {
  int w;
  if (n <= 0 || !s) return 0;
  if (n > cap) n = cap;
  w = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, n, out, cap);
  if (w > 0) return w;
  w = MultiByteToWideChar(932, 0, s, n, out, cap);
  if (w > 0) return w;
  w = MultiByteToWideChar(CP_ACP, 0, s, n, out, cap);
  return w > 0 ? w : 0;
}

/* Engine-native UI strings arrive as CP932; log each distinct one once so the
   remaining untranslated labels (menus, dialogs) can be collected from a run. */
static char g_seen[96][128];
static int g_seen_n;

static void log_legacy(const char *s, int n) {
  char tmp[128];
  int i, len = n < 127 ? n : 127;
  if (len <= 0) return;
  memcpy(tmp, s, len);
  tmp[len] = 0;
  for (i = 0; i < g_seen_n; i++)
    if (strcmp(g_seen[i], tmp) == 0) return;
  if (g_seen_n >= 96) return;
  memcpy(g_seen[g_seen_n], tmp, len + 1);
  g_seen_n++;
  k_log("legacy: %s", s);
}

static int g_trace;

static void trace_out(int x, int y, const WCHAR *s, int n) {
  char utf8[512];
  int k;
  if (!g_trace) return;
  k = WideCharToMultiByte(CP_UTF8, 0, s, n, utf8, sizeof(utf8) - 1, NULL, NULL);
  if (k <= 0) return;
  utf8[k] = 0;
  k_log("out(%d,%d): %s", x, y, utf8);
}

/* The engine's typewriter redraws a message by advancing the pointer two
   bytes (one CP932 char) per frame, so byte-swapping the literals to UTF-8
   would split multibyte sequences. Translate any full or suffix match
   instead; the animation only erases glyphs, so the full line stays right. */
static const char *const k_legacy_jp[] = {
  "クイックロードします。よろしいですか？",
  "クイックセーブします。よろしいですか？",
  "クイックセーブしました",
  "クイックセーブされていません",
  "ロードに失敗しました",
  "ロードするデータを選択してください",
  "セーブする場所を選択してください",
  "タイトルに戻ります。よろしいですか？",
  "終了してよろしいですか？",
};
static const WCHAR *const k_legacy_zh[] = {
  L"要读取快速存档吗？",
  L"要快速保存吗？",
  L"快速保存完毕。",
  L"没有快速存档。",
  L"读取失败。",
  L"请选择要读取的数据。",
  L"请选择要保存的位置。",
  L"要返回标题画面吗？",
  L"要退出游戏吗？",
};
static const int k_legacy_n = sizeof(k_legacy_jp) / sizeof(k_legacy_jp[0]);

static const WCHAR *match_legacy(const char *s, int n) {
  int i;
  for (i = 0; i < k_legacy_n; i++) {
    int L = (int)strlen(k_legacy_jp[i]);
    if (n == L && memcmp(s, k_legacy_jp[i], L) == 0) return k_legacy_zh[i];
    if (n < L && (L - n) % 2 == 0 && memcmp(s, k_legacy_jp[i] + (L - n), n) == 0)
      return k_legacy_zh[i];
  }
  return NULL;
}

static BOOL WINAPI my_textout_a(HDC hdc, int x, int y, LPCSTR s, int n) {
  WCHAR buf[2048];
  int w, raw_n;
  if (!s) return real_textout_a ? real_textout_a(hdc, x, y, s, n) : 0;
  raw_n = n < 0 ? (int)strlen(s) : n;
  w = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, raw_n, buf, 2048);
  if (w <= 0) {
    const WCHAR *zh = match_legacy(s, raw_n);
    log_legacy(s, raw_n);
    if (zh) {
      w = (int)wcslen(zh);
      if (w > 2048) w = 2048;
      memcpy(buf, zh, (size_t)w * sizeof(WCHAR));
    } else {
      w = to_wide(s, raw_n, buf, 2048);
      if (w <= 0) return real_textout_a ? real_textout_a(hdc, x, y, s, n) : 0;
    }
  }
  if (w >= 9 && wcsncmp(buf, L"文字サンプルです。", 9) == 0) {
    const WCHAR sample[] = L"中文字体示例。１２３４";
    memcpy(buf, sample, sizeof(sample));
    w = (int)wcslen(sample);
  }
  trace_out(x, y, buf, w);
  return real_textout_w(hdc, x, y, buf, w);
}

static BOOL WINAPI my_extent_a(HDC hdc, LPCSTR s, int n, LPSIZE size) {
  WCHAR buf[2048];
  int w;
  if (!s || !size) return 0;
  if (n < 0) n = (int)strlen(s);
  w = to_wide(s, n, buf, 2048);
  if (w <= 0) return real_extent_a ? real_extent_a(hdc, s, n, size) : 0;
  return real_extent_w(hdc, buf, w, size);
}

static BOOL WINAPI my_metrics_a(HDC hdc, LPTEXTMETRICA m) {
  TEXTMETRICW w;
  if (!m || !real_metrics_w) return 0;
  if (!real_metrics_w(hdc, &w)) return 0;
  memset(m, 0, sizeof(*m));
  m->tmHeight = w.tmHeight;
  m->tmAscent = w.tmAscent;
  m->tmDescent = w.tmDescent;
  m->tmInternalLeading = w.tmInternalLeading;
  m->tmExternalLeading = w.tmExternalLeading;
  m->tmAveCharWidth = w.tmAveCharWidth;
  m->tmMaxCharWidth = w.tmMaxCharWidth;
  m->tmWeight = w.tmWeight;
  m->tmOverhang = w.tmOverhang;
  m->tmDigitizedAspectX = w.tmDigitizedAspectX;
  m->tmDigitizedAspectY = w.tmDigitizedAspectY;
  m->tmFirstChar = (CHAR)w.tmFirstChar;
  m->tmLastChar = (CHAR)w.tmLastChar;
  m->tmDefaultChar = (CHAR)w.tmDefaultChar;
  m->tmBreakChar = (CHAR)w.tmBreakChar;
  m->tmItalic = w.tmItalic;
  m->tmUnderlined = w.tmUnderlined;
  m->tmStruckOut = w.tmStruckOut;
  m->tmPitchAndFamily = w.tmPitchAndFamily;
  m->tmCharSet = w.tmCharSet;
  return TRUE;
}

static HFONT WINAPI my_font_a(const LOGFONTA *lf) {
  LOGFONTW w;
  if (!lf) return 0;
  memset(&w, 0, sizeof(w));
  w.lfHeight = lf->lfHeight;
  /* An explicit width from another face distorts the replacement font. */
  w.lfWidth = 0;
  w.lfEscapement = lf->lfEscapement;
  w.lfOrientation = lf->lfOrientation;
  w.lfWeight = lf->lfWeight;
  w.lfItalic = lf->lfItalic;
  w.lfUnderline = lf->lfUnderline;
  w.lfStrikeOut = lf->lfStrikeOut;
  w.lfOutPrecision = lf->lfOutPrecision;
  w.lfClipPrecision = lf->lfClipPrecision;
  w.lfQuality = lf->lfQuality;
  w.lfPitchAndFamily = lf->lfPitchAndFamily;
  MultiByteToWideChar(CP_ACP, 0, lf->lfFaceName, -1, w.lfFaceName, LF_FACESIZE);
  if (g_face[0]) memcpy(w.lfFaceName, g_face, sizeof(g_face));
  w.lfCharSet = GB2312_CHARSET;
  return real_font_w(&w);
}

static int WINAPI my_addfont_a(LPCSTR path) {
  WCHAR buf[MAX_PATH * 2];
  if (!path) return 0;
  if (!MultiByteToWideChar(CP_ACP, 0, path, -1, buf, MAX_PATH * 2)) return 0;
  return real_addfont_w(buf);
}

static FARPROC gdi_proc(HMODULE gdi, const char *name) {
  return GetProcAddress(gdi, name);
}

void k_gdi_init(void) {
  HMODULE gdi = GetModuleHandleA("gdi32.dll");
  if (!gdi) return;

  real_textout_w = (textout_w_t)gdi_proc(gdi, "TextOutW");
  real_extent_w = (extent_w_t)gdi_proc(gdi, "GetTextExtentPoint32W");
  real_metrics_w = (metrics_w_t)gdi_proc(gdi, "GetTextMetricsW");
  real_font_w = (font_w_t)gdi_proc(gdi, "CreateFontIndirectW");
  real_addfont_w = (addfont_w_t)gdi_proc(gdi, "AddFontResourceW");

  real_textout_a = (textout_a_t)gdi_proc(gdi, "TextOutA");
  real_extent_a = (extent_a_t)gdi_proc(gdi, "GetTextExtentPoint32A");
  real_metrics_a = (metrics_a_t)gdi_proc(gdi, "GetTextMetricsA");
  real_font_a = (font_a_t)gdi_proc(gdi, "CreateFontIndirectA");
  real_addfont_a = (addfont_a_t)gdi_proc(gdi, "AddFontResourceA");

  if (!real_textout_w || !real_extent_w || !real_metrics_w || !real_font_w) return;

  /* DengXian leaves more of the fixed engine cell available for CJK glyphs. */
  MultiByteToWideChar(CP_UTF8, 0, "DengXian", -1, g_face, LF_FACESIZE);
  {
    char env[LF_FACESIZE * 2];
    DWORD n = GetEnvironmentVariableA("KOTOBA_FONT", env, sizeof(env));
    if (n > 0 && n < sizeof(env)) MultiByteToWideChar(CP_UTF8, 0, env, -1, g_face, LF_FACESIZE);
  }
  g_trace = GetEnvironmentVariableA("KOTOBA_TRACE", NULL, 0) > 0;

  k_iat_hook("GDI32.dll", "TextOutA", (void *)my_textout_a);
  k_iat_hook("GDI32.dll", "GetTextExtentPoint32A", (void *)my_extent_a);
  k_iat_hook("GDI32.dll", "GetTextMetricsA", (void *)my_metrics_a);
  k_iat_hook("GDI32.dll", "CreateFontIndirectA", (void *)my_font_a);
  if (real_addfont_w) k_iat_hook("GDI32.dll", "AddFontResourceA", (void *)my_addfont_a);
}
