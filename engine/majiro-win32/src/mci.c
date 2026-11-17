#include "majiro.h"
#include <mmsystem.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

typedef MCIERROR (WINAPI *sendcmd_a_t)(MCIDEVICEID, UINT, DWORD_PTR, DWORD_PTR);
typedef MCIERROR (WINAPI *sendcmd_w_t)(MCIDEVICEID, UINT, DWORD_PTR, DWORD_PTR);
typedef MCIERROR (WINAPI *sendstr_a_t)(LPCSTR, LPSTR, UINT, HWND);
typedef MCIERROR (WINAPI *sendstr_w_t)(LPCWSTR, LPWSTR, UINT, HWND);

static sendcmd_a_t real_cmd_a;
static sendcmd_w_t real_cmd_w;
static sendstr_a_t real_str_a;
static sendstr_w_t real_str_w;

static MCIERROR resolve(void) {
  HMODULE self, m;
  WCHAR path[MAX_PATH], *name;
  static const WCHAR library[] = L"winmm_orig.dll";
  DWORD n;
  if (real_cmd_a && real_cmd_w && real_str_a && real_str_w) return 0;
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          (LPCWSTR)(uintptr_t)resolve, &self)) return MCIERR_CANNOT_LOAD_DRIVER;
  n = GetModuleFileNameW(self, path, MAX_PATH);
  if (!n || n >= MAX_PATH || !(name = wcsrchr(path, L'\\')) ||
      (SIZE_T)(name + 1 - path) + sizeof(library) / sizeof(library[0]) > MAX_PATH)
    return MCIERR_CANNOT_LOAD_DRIVER;
  memcpy(name + 1, library, sizeof(library));
  m = GetModuleHandleW(path);
  if (!m) m = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
  if (!m || m == self) return MCIERR_CANNOT_LOAD_DRIVER;
  if (!real_cmd_a) real_cmd_a = (sendcmd_a_t)GetProcAddress(m, "mciSendCommandA");
  if (!real_cmd_w) real_cmd_w = (sendcmd_w_t)GetProcAddress(m, "mciSendCommandW");
  if (!real_str_a) real_str_a = (sendstr_a_t)GetProcAddress(m, "mciSendStringA");
  if (!real_str_w) real_str_w = (sendstr_w_t)GetProcAddress(m, "mciSendStringW");
  return 0;
}

static void trace_text_a(LPCSTR text, char out[512]) {
  size_t i;
  strcpy(out, "(unreadable)");
  for (i = 0; i < 511; i++) {
    uintptr_t p = (uintptr_t)text;
    if (p > UINTPTR_MAX - i || !k_readable((void *)(p + i), 1)) {
      strcpy(out, "(unreadable)");
      return;
    }
    out[i] = *(const char *)(p + i);
    if (!out[i]) return;
  }
  out[511] = 0;
}

static void trace_text_w(LPCWSTR text, char out[512]) {
  WCHAR wide[160];
  size_t i;
  strcpy(out, "(unreadable)");
  for (i = 0; i < 159; i++) {
    uintptr_t p = (uintptr_t)text;
    if (p > UINTPTR_MAX - i * sizeof(WCHAR) ||
        !k_readable((void *)(p + i * sizeof(WCHAR)), sizeof(WCHAR))) return;
    wide[i] = *(const WCHAR *)(p + i * sizeof(WCHAR));
    if (!wide[i]) break;
  }
  wide[i] = 0;
  if (!WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, 512, NULL, NULL))
    strcpy(out, "(unreadable)");
}

static void log_open_a(DWORD_PTR flags, DWORD_PTR param) {
  const MCI_OPEN_PARMSA *o = (const MCI_OPEN_PARMSA *)param;
  char type[512] = "(unset)", elem[512] = "(unset)";
  if (!k_readable(o, sizeof(*o))) return;
  if (flags & MCI_OPEN_TYPE) {
    if (flags & MCI_OPEN_TYPE_ID)
      snprintf(type, sizeof(type), "ID:%lu", (unsigned long)(uintptr_t)o->lpstrDeviceType);
    else trace_text_a(o->lpstrDeviceType, type);
  }
  if (flags & MCI_OPEN_ELEMENT) {
    if (flags & MCI_OPEN_ELEMENT_ID)
      snprintf(elem, sizeof(elem), "ID:%lu", (unsigned long)(uintptr_t)o->lpstrElementName);
    else trace_text_a(o->lpstrElementName, elem);
  }
  k_log("mci OPEN type=%s elem=%s", type, elem);
}

static void log_open_w(DWORD_PTR flags, DWORD_PTR param) {
  const MCI_OPEN_PARMSW *o = (const MCI_OPEN_PARMSW *)param;
  char type[512] = "(unset)", elem[512] = "(unset)";
  if (!k_readable(o, sizeof(*o))) return;
  if (flags & MCI_OPEN_TYPE) {
    if (flags & MCI_OPEN_TYPE_ID)
      snprintf(type, sizeof(type), "ID:%lu", (unsigned long)(uintptr_t)o->lpstrDeviceType);
    else trace_text_w(o->lpstrDeviceType, type);
  }
  if (flags & MCI_OPEN_ELEMENT) {
    if (flags & MCI_OPEN_ELEMENT_ID)
      snprintf(elem, sizeof(elem), "ID:%lu", (unsigned long)(uintptr_t)o->lpstrElementName);
    else trace_text_w(o->lpstrElementName, elem);
  }
  k_log("mci OPENW type=%s elem=%s", type, elem);
}

MCIERROR WINAPI ruri_mciSendCommandA(MCIDEVICEID id, UINT msg, DWORD_PTR flags, DWORD_PTR param) {
  DWORD saved = GetLastError();
  MCIERROR r = resolve();
  int trace = k_trace_enabled();
  if (!real_cmd_a) {
    SetLastError(saved);
    return r ? r : MCIERR_UNSUPPORTED_FUNCTION;
  }
  if (trace && msg == MCI_OPEN) log_open_a(flags, param);
  SetLastError(saved);
  r = real_cmd_a(id, msg, flags, param);
  saved = GetLastError();
  if (trace && msg != MCI_STATUS) k_log("mci cmdA dev=%u msg=%04x -> %lu", id, msg, r);
  SetLastError(saved);
  return r;
}

MCIERROR WINAPI ruri_mciSendCommandW(MCIDEVICEID id, UINT msg, DWORD_PTR flags, DWORD_PTR param) {
  DWORD saved = GetLastError();
  MCIERROR r = resolve();
  int trace = k_trace_enabled();
  if (!real_cmd_w) {
    SetLastError(saved);
    return r ? r : MCIERR_UNSUPPORTED_FUNCTION;
  }
  if (trace && msg == MCI_OPEN) log_open_w(flags, param);
  SetLastError(saved);
  r = real_cmd_w(id, msg, flags, param);
  saved = GetLastError();
  if (trace && msg != MCI_STATUS) k_log("mci cmdW dev=%u msg=%04x -> %lu", id, msg, r);
  SetLastError(saved);
  return r;
}

MCIERROR WINAPI ruri_mciSendStringA(LPCSTR cmd, LPSTR ret, UINT retlen, HWND cb) {
  DWORD saved = GetLastError();
  MCIERROR r = resolve();
  int trace = k_trace_enabled();
  char text[512];
  if (!real_str_a) {
    SetLastError(saved);
    return r ? r : MCIERR_UNSUPPORTED_FUNCTION;
  }
  if (trace) {
    trace_text_a(cmd, text);
    k_log("mci strA: %s", text);
  }
  SetLastError(saved);
  r = real_str_a(cmd, ret, retlen, cb);
  saved = GetLastError();
  if (trace && r) k_log("mci strA -> err=%lu", r);
  SetLastError(saved);
  return r;
}

MCIERROR WINAPI ruri_mciSendStringW(LPCWSTR cmd, LPWSTR ret, UINT retlen, HWND cb) {
  DWORD saved = GetLastError();
  MCIERROR r = resolve();
  int trace = k_trace_enabled();
  char text[512];
  if (!real_str_w) {
    SetLastError(saved);
    return r ? r : MCIERR_UNSUPPORTED_FUNCTION;
  }
  if (trace) {
    trace_text_w(cmd, text);
    k_log("mci strW: %s", text);
  }
  SetLastError(saved);
  r = real_str_w(cmd, ret, retlen, cb);
  saved = GetLastError();
  if (trace && r) k_log("mci strW -> err=%lu", r);
  SetLastError(saved);
  return r;
}
