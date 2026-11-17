#include <windows.h>
#include <mmsystem.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

static int resolve_mode, logs, loads, calls, low_reads, trace_on;
static const void *expected_param;
static DWORD_PTR expected_flags;
static UINT expected_msg;
static char output[4096];
static MCIERROR WINAPI fake_cmd(MCIDEVICEID id, UINT msg, DWORD_PTR flags, DWORD_PTR param) {
  assert(GetLastError() == 12345); assert(id == 7); assert(msg == expected_msg);
  assert(flags == expected_flags); assert((void *)param == expected_param);
  calls++; SetLastError(54321); return 321;
}
static MCIERROR WINAPI fake_str_a(LPCSTR s, LPSTR out, UINT n, HWND cb) {
  assert(GetLastError() == 12345); assert(s == expected_param); assert(n == 8); assert(!cb);
  strcpy(out, "A"); calls++; SetLastError(54321); return 322;
}
static MCIERROR WINAPI fake_str_w(LPCWSTR s, LPWSTR out, UINT n, HWND cb) {
  assert(GetLastError() == 12345); assert(s == expected_param); assert(n == 8); assert(!cb);
  wcscpy(out, L"W"); calls++; SetLastError(54321); return 323;
}
static BOOL WINAPI test_module_ex(DWORD flags, LPCWSTR address, HMODULE *m) {
  assert(flags == (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT));
  assert(address); SetLastError(8001); *m = (HMODULE)1; return resolve_mode != 1;
}
static DWORD WINAPI test_module_name(HMODULE m, LPWSTR out, DWORD n) {
  assert(m == (HMODULE)1); assert(n == MAX_PATH); SetLastError(8002);
  if (resolve_mode == 2) return MAX_PATH;
  if (resolve_mode == 3) { wcscpy(out, L"winmm.dll"); return 9; }
  wcscpy(out, L"C:\\isolated proxy\\winmm.dll"); return (DWORD)wcslen(out);
}
static HMODULE WINAPI test_module(LPCWSTR path) {
  assert(!wcscmp(path, L"C:\\isolated proxy\\winmm_orig.dll"));
  SetLastError(8003); return NULL;
}
static HMODULE WINAPI test_load(LPCWSTR path, HANDLE file, DWORD flags) {
  assert(!wcscmp(path, L"C:\\isolated proxy\\winmm_orig.dll"));
  assert(!file); assert(flags == LOAD_WITH_ALTERED_SEARCH_PATH);
  loads++; SetLastError(8004); return resolve_mode == 4 ? NULL : (HMODULE)2;
}
static FARPROC WINAPI test_proc(HMODULE m, LPCSTR name) {
  assert(m == (HMODULE)2); SetLastError(8005);
  if (resolve_mode == 5) return NULL;
  if (!strcmp(name, "mciSendCommandA") || !strcmp(name, "mciSendCommandW")) return (FARPROC)fake_cmd;
  if (!strcmp(name, "mciSendStringA")) return (FARPROC)fake_str_a;
  assert(!strcmp(name, "mciSendStringW")); return (FARPROC)fake_str_w;
}
int k_trace_enabled(void) { SetLastError(8101); return trace_on; }
int k_readable(const void *p, SIZE_T len) {
  MEMORY_BASIC_INFORMATION mbi;
  SetLastError(8102);
  if ((uintptr_t)p < 0x10000) { low_reads++; return 0; }
  if (!VirtualQuery(p, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
      (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return 0;
  return len <= mbi.RegionSize - ((uintptr_t)p - (uintptr_t)mbi.BaseAddress);
}
void k_log(const char *fmt, ...) {
  va_list ap;
  size_t n = strlen(output);
  va_start(ap, fmt); vsnprintf(output + n, sizeof(output) - n, fmt, ap); va_end(ap);
  logs++; SetLastError(8103);
}
#define GetModuleHandleExW test_module_ex
#define GetModuleFileNameW test_module_name
#define GetModuleHandleW test_module
#define LoadLibraryExW test_load
#define GetProcAddress test_proc
#include "mci.c"

static void clear_real(void) { real_cmd_a = NULL; real_cmd_w = NULL; real_str_a = NULL; real_str_w = NULL; }
static void command_pair(DWORD_PTR flags, MCI_OPEN_PARMSA *a, MCI_OPEN_PARMSW *w) {
  expected_flags = flags; expected_msg = MCI_OPEN;
  expected_param = a; SetLastError(12345);
  assert(kotoba_mciSendCommandA(7, MCI_OPEN, flags, (DWORD_PTR)a) == 321);
  assert(GetLastError() == 54321);
  expected_param = w; SetLastError(12345);
  assert(kotoba_mciSendCommandW(7, MCI_OPEN, flags, (DWORD_PTR)w) == 321);
  assert(GetLastError() == 54321);
}
int main(void) {
  int i, before;
  MCI_OPEN_PARMSA a = {0}; MCI_OPEN_PARMSW w = {0};
  char ret_a[8]; WCHAR ret_w[8];
  for (i = 1; i <= 5; i++) {
    MCIERROR error = i == 5 ? MCIERR_UNSUPPORTED_FUNCTION : MCIERR_CANNOT_LOAD_DRIVER;
    resolve_mode = i; clear_real();
    SetLastError(12345); assert(kotoba_mciSendCommandA(0, 0, 0, 0) == error); assert(GetLastError() == 12345);
    SetLastError(12345); assert(kotoba_mciSendCommandW(0, 0, 0, 0) == error); assert(GetLastError() == 12345);
    strcpy(ret_a, "keep"); wcscpy(ret_w, L"keep");
    SetLastError(12345); assert(kotoba_mciSendStringA(NULL, ret_a, 8, NULL) == error); assert(GetLastError() == 12345);
    SetLastError(12345); assert(kotoba_mciSendStringW(NULL, ret_w, 8, NULL) == error); assert(GetLastError() == 12345);
    assert(!strcmp(ret_a, "keep")); assert(!wcscmp(ret_w, L"keep"));
  }
  assert(!calls); puts("PASS: all four wrappers return MCI errors for module/path/load/export failures");
  resolve_mode = 0; clear_real(); trace_on = 1;
  a.lpstrDeviceType = (LPCSTR)(uintptr_t)MCI_DEVTYPE_CD_AUDIO;
  w.lpstrDeviceType = (LPCWSTR)(uintptr_t)MCI_DEVTYPE_CD_AUDIO;
  a.lpstrElementName = (LPCSTR)17; w.lpstrElementName = (LPCWSTR)17;
  command_pair(MCI_OPEN_TYPE | MCI_OPEN_TYPE_ID | MCI_OPEN_ELEMENT | MCI_OPEN_ELEMENT_ID, &a, &w);
  assert(!low_reads); assert(strstr(output, "ID:516")); assert(strstr(output, "ID:17"));
  output[0] = 0; command_pair(0, &a, &w);
  assert(!low_reads); assert(strstr(output, "type=(unset) elem=(unset)"));
  output[0] = 0; command_pair(MCI_OPEN_TYPE_ID | MCI_OPEN_ELEMENT_ID, &a, &w);
  assert(!low_reads); assert(strstr(output, "type=(unset) elem=(unset)"));
  a.lpstrDeviceType = "waveaudio"; w.lpstrDeviceType = L"waveaudio";
  a.lpstrElementName = "bgm.wav"; w.lpstrElementName = L"bgm.wav";
  output[0] = 0; command_pair(MCI_OPEN_TYPE | MCI_OPEN_ELEMENT, &a, &w);
  assert(strstr(output, "type=waveaudio elem=bgm.wav"));
  a.lpstrElementName = (LPCSTR)17; w.lpstrElementName = (LPCWSTR)17;
  command_pair(MCI_OPEN_ELEMENT, &a, &w); assert(low_reads == 2);
  before = logs; trace_on = 0; command_pair(MCI_OPEN_ELEMENT, &a, &w);
  assert(logs == before && low_reads == 2);
  trace_on = 1;
  expected_msg = MCI_STATUS; expected_flags = 0; expected_param = NULL;
  before = logs; SetLastError(12345);
  assert(kotoba_mciSendCommandA(7, MCI_STATUS, 0, 0) == 321); assert(GetLastError() == 54321); assert(logs == before);
  expected_param = "play test"; SetLastError(12345);
  assert(kotoba_mciSendStringA(expected_param, ret_a, 8, NULL) == 322); assert(GetLastError() == 54321); assert(!strcmp(ret_a, "A"));
  expected_param = L"play test"; SetLastError(12345);
  assert(kotoba_mciSendStringW(expected_param, ret_w, 8, NULL) == 323); assert(GetLastError() == 54321); assert(!wcscmp(ret_w, L"W"));
  assert(loads); puts("PASS: controlled same-directory path, A/W ID/unset/string flags, trace gating, forwarded arguments/results/LastError");
  return 0;
}
