#include "majiro.h"

/* Log MCI traffic so we can see whether the engine actually asks Windows to
   play BGM and what the media control interface answers. The real functions
   live in winmm_orig.dll; these are exported in place of the usual forwards. */

typedef UINT (WINAPI *sendcmd_a_t)(UINT, UINT, DWORD_PTR, DWORD_PTR);
typedef UINT (WINAPI *sendcmd_w_t)(UINT, UINT, DWORD_PTR, DWORD_PTR);
typedef UINT (WINAPI *sendstr_a_t)(LPCSTR, LPSTR, UINT, HWND);
typedef UINT (WINAPI *sendstr_w_t)(LPCWSTR, LPWSTR, UINT, HWND);

static sendcmd_a_t real_cmd_a;
static sendcmd_w_t real_cmd_w;
static sendstr_a_t real_str_a;
static sendstr_w_t real_str_w;

static void resolve(void) {
  HMODULE m = GetModuleHandleA("winmm_orig.dll");
  if (!m) m = LoadLibraryA("winmm_orig.dll");
  if (!m) return;
  if (!real_cmd_a) real_cmd_a = (sendcmd_a_t)GetProcAddress(m, "mciSendCommandA");
  if (!real_cmd_w) real_cmd_w = (sendcmd_w_t)GetProcAddress(m, "mciSendCommandW");
  if (!real_str_a) real_str_a = (sendstr_a_t)GetProcAddress(m, "mciSendStringA");
  if (!real_str_w) real_str_w = (sendstr_w_t)GetProcAddress(m, "mciSendStringW");
}

/* MCI_OPEN parms: callback, device id, device type, element name, alias. */
typedef struct {
  DWORD_PTR cb;
  UINT id;
  const char *type;
  const char *elem;
  const char *alias;
} open_a_t;
typedef struct {
  DWORD_PTR cb;
  UINT id;
  const wchar_t *type;
  const wchar_t *elem;
  const wchar_t *alias;
} open_w_t;

static void log_open_a(DWORD_PTR p) {
  const open_a_t *o = (const open_a_t *)p;
  if (!o) return;
  k_log("mci OPEN id=%u type=%s elem=%s", o->id,
        o->type ? o->type : "?", o->elem ? o->elem : "?");
}

UINT WINAPI kotoba_mciSendCommandA(UINT id, UINT msg, DWORD_PTR flags, DWORD_PTR param) {
  UINT r;
  resolve();
  if (!real_cmd_a) return 0;
  if (msg == 0x0803) log_open_a(param);
  r = real_cmd_a(id, msg, flags, param);
  if (msg != 0x0814) /* skip MCI_STATUS polling spam */
    k_log("mci cmdA dev=%u msg=%04x -> %u", id, msg, r);
  return r;
}

UINT WINAPI kotoba_mciSendCommandW(UINT id, UINT msg, DWORD_PTR flags, DWORD_PTR param) {
  UINT r;
  resolve();
  if (!real_cmd_w) return 0;
  if (msg == 0x0803 && param) {
    const open_w_t *o = (const open_w_t *)param;
    char elem[MAX_PATH * 3];
    elem[0] = 0;
    if (o->elem) WideCharToMultiByte(CP_UTF8, 0, o->elem, -1, elem, sizeof(elem), NULL, NULL);
    k_log("mci OPENW id=%u elem=%s", o->id, elem);
  }
  r = real_cmd_w(id, msg, flags, param);
  if (msg != 0x0814)
    k_log("mci cmdW dev=%u msg=%04x -> %u", id, msg, r);
  return r;
}

UINT WINAPI kotoba_mciSendStringA(LPCSTR cmd, LPSTR ret, UINT retlen, HWND cb) {
  UINT r;
  resolve();
  if (!real_str_a) return 0;
  k_log("mci strA: %s", cmd ? cmd : "?");
  r = real_str_a(cmd, ret, retlen, cb);
  if (r) k_log("mci strA -> err=%u", r);
  return r;
}

UINT WINAPI kotoba_mciSendStringW(LPCWSTR cmd, LPWSTR ret, UINT retlen, HWND cb) {
  UINT r;
  char u[512];
  resolve();
  if (!real_str_w) return 0;
  u[0] = 0;
  if (cmd) WideCharToMultiByte(CP_UTF8, 0, cmd, -1, u, sizeof(u), NULL, NULL);
  k_log("mci strW: %s", u);
  r = real_str_w(cmd, ret, retlen, cb);
  if (r) k_log("mci strW -> err=%u", r);
  return r;
}