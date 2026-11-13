#include "majiro.h"
#include <string.h>

typedef HANDLE (WINAPI *create_w_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD,
                                    DWORD, HANDLE);
typedef HANDLE (WINAPI *create_a_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD,
                                    DWORD, HANDLE);
typedef DWORD (WINAPI *attrs_w_t)(LPCWSTR);
typedef DWORD (WINAPI *attrs_a_t)(LPCSTR);
typedef BOOL (WINAPI *settext_w_t)(HWND, LPCWSTR);
typedef int (WINAPI *msgbox_a_t)(HWND, LPCSTR, LPCSTR, UINT);
typedef HWND (WINAPI *cw_ex_w_t)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND,
                                 HMENU, HINSTANCE, LPVOID);
typedef HWND (WINAPI *cw_ex_a_t)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND,
                                 HMENU, HINSTANCE, LPVOID);

static create_w_t real_create_w;
static create_a_t real_create_a;
static attrs_w_t real_attrs_w;
static attrs_a_t real_attrs_a;
static settext_w_t real_settext_w;
static msgbox_a_t real_msgbox_a;
static cw_ex_w_t real_cw_ex_w;
static cw_ex_a_t real_cw_ex_a;

static int interesting(const char *p) {
  const char *keys[] = {".arc", ".mjo", "scenario", "update", "savedata", "data2", ".cfg"};
  int i;
  for (i = 0; i < 7; i++) {
    const char *k = keys[i];
    const char *s;
    for (s = p; *s; s++) {
      const char *a = s;
      const char *b = k;
      while (*a && *b && (*a == *b || (*a >= 'A' && *a <= 'Z' && *a - 'A' + 'a' == *b))) {
        a++;
        b++;
      }
      if (!*b) return 1;
    }
  }
  return 0;
}

/* The engine hands us script names as raw UTF-8 bytes through the ANSI API.
   CP936 mangles them, so probe UTF-8 and CP932 interpretations as well and
   use whichever path really exists. */
static int resolve(const char *ansi, WCHAR *out) {
  UINT cps[3] = {CP_UTF8, 932, CP_ACP};
  int i;
  for (i = 0; i < 3; i++) {
    if (!MultiByteToWideChar(cps[i], i == 0 ? MB_ERR_INVALID_CHARS : 0, ansi, -1, out,
                             MAX_PATH * 2))
      continue;
    if (real_attrs_w(out) != INVALID_FILE_ATTRIBUTES) return 1;
  }
  return 0;
}

static HANDLE WINAPI my_create_w(LPCWSTR path, DWORD access, DWORD share,
                                 LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags,
                                 HANDLE tmpl) {
  char utf8[MAX_PATH * 3];
  if (path) {
    int n = WideCharToMultiByte(CP_UTF8, 0, path, -1, utf8, sizeof(utf8), NULL, NULL);
    if (n > 0 && interesting(utf8)) k_log("openW: %s", utf8);
  }
  return real_create_w(path, access, share, sa, disp, flags, tmpl);
}

static HANDLE WINAPI my_create_a(LPCSTR path, DWORD access, DWORD share,
                                 LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags,
                                 HANDLE tmpl) {
  WCHAR wide[MAX_PATH * 2];
  if (!path) return real_create_a(path, access, share, sa, disp, flags, tmpl);
  if (interesting(path)) k_log("openA: %s", path);
  if (disp == OPEN_EXISTING && resolve(path, wide)) return real_create_w(wide, access, share, sa, disp, flags, tmpl);
  return real_create_a(path, access, share, sa, disp, flags, tmpl);
}

static DWORD WINAPI my_attrs_a(LPCSTR path) {
  WCHAR wide[MAX_PATH * 2];
  if (!path) return real_attrs_a(path);
  if (resolve(path, wide)) {
    DWORD a = real_attrs_w(wide);
    if (interesting(path)) k_log("attrA+: %s", path);
    return a;
  }
  if (interesting(path)) k_log("attrA-: %s", path);
  return real_attrs_a(path);
}

static BOOL WINAPI my_settext_a(HWND hwnd, LPCSTR text) {
  WCHAR buf[1024];
  int w;
  if (!text) return real_settext_w(hwnd, NULL);
  w = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, buf, 1024);
  if (w <= 0) w = MultiByteToWideChar(932, 0, text, -1, buf, 1024);
  if (w <= 0) return 0;
  return real_settext_w(hwnd, buf);
}

/* The title comes from TITLEBAR in majiro.env as CP932 bytes; the stock A
   path would decode it with CP936 and show mojibake. */
static HWND WINAPI my_cw_ex_a(DWORD ex, LPCSTR cls, LPCSTR title, DWORD style, int x, int y,
                              int w, int h, HWND parent, HMENU menu, HINSTANCE inst,
                              LPVOID param) {
  WCHAR cls_w[256];
  WCHAR title_w[512];
  LPCWSTR cls_p = NULL;
  LPCWSTR title_p = NULL;
  if (!real_cw_ex_w) return real_cw_ex_a(ex, cls, title, style, x, y, w, h, parent, menu, inst, param);
  if (cls) {
    if (HIWORD(cls) && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, cls, -1, cls_w, 256) > 0)
      cls_p = cls_w;
    else if (HIWORD(cls) && MultiByteToWideChar(932, 0, cls, -1, cls_w, 256) > 0)
      cls_p = cls_w;
    else if (!HIWORD(cls))
      cls_p = (LPCWSTR)(ULONG_PTR)(ULONG)cls;
  }
  if (title) {
    int tw = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, title, -1, title_w, 512);
    if (tw <= 0) tw = MultiByteToWideChar(932, 0, title, -1, title_w, 512);
    if (tw > 0) {
      title_p = title_w;
      k_log("title: %s", title);
    }
  }
  if (!cls_p && cls) return real_cw_ex_a(ex, cls, title, style, x, y, w, h, parent, menu, inst, param);
  return real_cw_ex_w(ex, cls_p, title_p, style, x, y, w, h, parent, menu, inst, param);
}

static int WINAPI my_msgbox_a(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
  WCHAR wide[1024];
  char utf8[2048];
  int w;
  if (text) {
    w = MultiByteToWideChar(932, 0, text, -1, wide, 1024);
    if (w > 0 &&
        WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, sizeof(utf8), NULL, NULL) > 0)
      k_log("msgbox(sjis): %s", utf8);
    k_log("msgbox(raw): %s", text);
  }
  return real_msgbox_a(hwnd, text, caption, type);
}

void k_fs_init(void) {
  HMODULE k32 = GetModuleHandleA("kernel32.dll");
  HMODULE u32 = GetModuleHandleA("user32.dll");
  if (!k32) return;
  real_create_w = (create_w_t)GetProcAddress(k32, "CreateFileW");
  real_create_a = (create_a_t)GetProcAddress(k32, "CreateFileA");
  real_attrs_w = (attrs_w_t)GetProcAddress(k32, "GetFileAttributesW");
  real_attrs_a = (attrs_a_t)GetProcAddress(k32, "GetFileAttributesA");
  if (u32) real_settext_w = (settext_w_t)GetProcAddress(u32, "SetWindowTextW");
  if (u32) real_msgbox_a = (msgbox_a_t)GetProcAddress(u32, "MessageBoxA");
  if (u32) real_cw_ex_w = (cw_ex_w_t)GetProcAddress(u32, "CreateWindowExW");
  if (u32) real_cw_ex_a = (cw_ex_a_t)GetProcAddress(u32, "CreateWindowExA");
  if (!real_create_w || !real_attrs_w) return;

  k_iat_hook("kernel32.dll", "CreateFileW", (void *)my_create_w);
  if (real_create_a) k_iat_hook("kernel32.dll", "CreateFileA", (void *)my_create_a);
  if (real_attrs_a) k_iat_hook("kernel32.dll", "GetFileAttributesA", (void *)my_attrs_a);
  if (real_settext_w) k_iat_hook("user32.dll", "SetWindowTextA", (void *)my_settext_a);
  if (real_msgbox_a) k_iat_hook("user32.dll", "MessageBoxA", (void *)my_msgbox_a);
  if (real_cw_ex_w && real_cw_ex_a) k_iat_hook("user32.dll", "CreateWindowExA", (void *)my_cw_ex_a);
}
