#include "majiro.h"
#include <string.h>
#include <wchar.h>

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
static int (WINAPI *real_msgbox_w)(HWND, LPCWSTR, LPCWSTR, UINT);
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

static void translate_menu(HMENU m);

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
  {
    HWND hwnd = real_cw_ex_w(ex, cls_p, title_p, style, x, y, w, h, parent, menu, inst, param);
    if (hwnd && !parent && GetMenu(hwnd)) {
      translate_menu(GetMenu(hwnd));
      DrawMenuBar(hwnd);
    }
    return hwnd;
  }
}

static int to_wide_any(const char *s, WCHAR *out, int cap) {
  int w = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, out, cap);
  if (w <= 0) w = MultiByteToWideChar(932, 0, s, -1, out, cap);
  return w;
}

static const struct { const WCHAR *ja, *zh; } k_msg_zh[] = {
  {L"終了してよろしいですか？", L"确定要退出游戏吗？"},
  {L"タイトルに戻ります。よろしいですか？", L"要返回标题画面吗？"},
  {L"クイックセーブします。よろしいですか？", L"要快速存档吗？"},
  {L"クイックロードします。よろしいですか？", L"要快速读档吗？"},
  {L"クイックセーブしました", L"已快速存档"},
  {L"クイックセーブされていません", L"没有快速存档"},
  {L"ロードに失敗しました", L"读档失败"},
};

static const struct { const WCHAR *ja, *zh; } k_menu_zh[] = {
  {L"ファイル/設定", L"文件/设置"}, {L"ファイル", L"文件"}, {L"セーブ", L"存档"},
  {L"名前を付けてセーブ", L"命名存档"}, {L"ロード", L"读档"}, {L"名前で指定してロード", L"按名称读档"},
  {L"画面の保存", L"保存截图"}, {L"ジョイスティック使用", L"使用手柄"}, {L"スピード設定", L"速度设置"},
  {L"サウンド設定", L"声音设置"}, {L"音声個別設定", L"角色语音设置"}, {L"フォント設定", L"字体设置"},
  {L"フォント", L"字体"}, {L"拡張設定", L"扩展设置"}, {L"タイトルへ戻る", L"返回标题"},
  {L"終了", L"退出"}, {L"画面設定", L"画面设置"}, {L"スクリーン", L"画面"},
  {L"フルスクリーン", L"全屏"}, {L"ウインドウ", L"窗口"}, {L"ワイドモード", L"宽屏模式"},
  {L"ムービー設定", L"影片设置"}, {L"DirectShowで再生", L"用 DirectShow 播放"},
  {L"MCIで再生", L"用 MCI 播放"}, {L"ムービー禁止", L"禁用影片"}, {L"ムービーを禁止", L"禁用影片"},
  {L"スクリーン詳細設定", L"画面详细设置"}, {L"オートプレイ", L"自动播放"}, {L"オートモード", L"自动模式"},
  {L"既読スキップ", L"跳过已读"}, {L"強制スキップ", L"强制跳过"}, {L"スキップ", L"跳过"},
  {L"設定", L"设置"}, {L"コンフィグ", L"设置"}, {L"前の選択に戻る", L"返回上一个选项"},
  {L"次の選択に飛ぶ", L"跳到下一个选项"}, {L"ヘルプ", L"帮助"}, {L"バージョン情報", L"版本信息"},
  {L"エラーログを開く", L"打开错误日志"}, {L"ユーザーサポート", L"用户支持"}, {L"Qセーブ", L"快速存档"},
  {L"Qロード", L"快速读档"}, {L"バックログ", L"历史记录"}, {L"自動進行", L"自动播放"},
  {L"読んだ所はスキップ", L"跳过已读"}, {L"常に手前に表示", L"窗口置顶"},
};

/* Translate the text before "(", "\t" or "..." and keep accelerators/shortcuts. */
static void translate_menu(HMENU m) {
  int i, n = m ? GetMenuItemCount(m) : 0;
  for (i = 0; i < n; i++) {
    WCHAR text[256], out[256];
    MENUITEMINFOW mi;
    size_t k, core;
    memset(&mi, 0, sizeof(mi));
    mi.cbSize = sizeof(mi);
    mi.fMask = MIIM_STRING | MIIM_SUBMENU | MIIM_FTYPE;
    mi.dwTypeData = text;
    mi.cch = 256;
    if (!GetMenuItemInfoW(m, i, TRUE, &mi)) continue;
    if (mi.hSubMenu) translate_menu(mi.hSubMenu);
    if (mi.fType & MFT_SEPARATOR || !mi.cch) continue;
    core = wcscspn(text, L"(\t");
    if (core >= 3 && wcsncmp(text + core - 3, L"...", 3) == 0) core -= 3;
    for (k = 0; k < sizeof(k_menu_zh) / sizeof(k_menu_zh[0]); k++) {
      if (wcslen(k_menu_zh[k].ja) != core || wcsncmp(text, k_menu_zh[k].ja, core) != 0) continue;
      _snwprintf(out, 256, L"%s%s", k_menu_zh[k].zh, text + core);
      out[255] = 0;
      mi.fMask = MIIM_STRING;
      mi.dwTypeData = out;
      SetMenuItemInfoW(m, i, TRUE, &mi);
      break;
    }
  }
}

static BOOL(WINAPI *real_setmenu)(HWND, HMENU);
static BOOL WINAPI my_setmenu(HWND hwnd, HMENU m) {
  translate_menu(m);
  return real_setmenu(hwnd, m);
}

static int WINAPI my_msgbox_a(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
  WCHAR wtext[1024], wcap[256];
  const WCHAR *t = NULL, *c = NULL;
  size_t i;
  if (!real_msgbox_w) return real_msgbox_a(hwnd, text, caption, type);
  if (text && to_wide_any(text, wtext, 1024) > 0) {
    t = wtext;
    for (i = 0; i < sizeof(k_msg_zh) / sizeof(k_msg_zh[0]); i++)
      if (wcscmp(wtext, k_msg_zh[i].ja) == 0) { t = k_msg_zh[i].zh; break; }
  }
  if (caption) {
    char cur[512];
    /* Engine passes back its own window title fetched via GetWindowTextA,
       i.e. CP936 bytes of our Unicode title; take the wide title instead. */
    if (hwnd && GetWindowTextA(hwnd, cur, sizeof(cur)) > 0 && strcmp(cur, caption) == 0 &&
        GetWindowTextW(hwnd, wcap, 256) > 0)
      c = wcap;
    else if (to_wide_any(caption, wcap, 256) > 0)
      c = wcap;
  }
  return real_msgbox_w(hwnd, t, c, type);
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
  if (u32) real_msgbox_w = (int (WINAPI *)(HWND, LPCWSTR, LPCWSTR, UINT))GetProcAddress(u32, "MessageBoxW");
  if (u32) real_cw_ex_w = (cw_ex_w_t)GetProcAddress(u32, "CreateWindowExW");
  if (u32) real_cw_ex_a = (cw_ex_a_t)GetProcAddress(u32, "CreateWindowExA");
  if (!real_create_w || !real_attrs_w) return;

  k_iat_hook("kernel32.dll", "CreateFileW", (void *)my_create_w);
  if (real_create_a) k_iat_hook("kernel32.dll", "CreateFileA", (void *)my_create_a);
  if (real_attrs_a) k_iat_hook("kernel32.dll", "GetFileAttributesA", (void *)my_attrs_a);
  if (real_settext_w) k_iat_hook("user32.dll", "SetWindowTextA", (void *)my_settext_a);
  if (real_msgbox_a) k_iat_hook("user32.dll", "MessageBoxA", (void *)my_msgbox_a);
  if (real_cw_ex_w && real_cw_ex_a) k_iat_hook("user32.dll", "CreateWindowExA", (void *)my_cw_ex_a);
  if (u32) real_setmenu = (BOOL(WINAPI *)(HWND, HMENU))GetProcAddress(u32, "SetMenu");
  if (real_setmenu) k_iat_hook("user32.dll", "SetMenu", (void *)my_setmenu);
}
