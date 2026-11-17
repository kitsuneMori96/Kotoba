#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <stdarg.h>

static UINT accept_cp, probed[8];
static int probe_count, trace_on, logs, create_a_calls, create_w_calls, attrs_a_calls, attrs_w_calls;
static int backend_sets_error, backend_fails;
static DWORD final_disp;
static void final_call(void) {
  assert(GetLastError() == 12345);
  if (backend_sets_error) SetLastError(54321);
}
static HANDLE WINAPI create_w(LPCWSTR p, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa, DWORD d, DWORD f, HANDLE t) {
  (void)p; assert(a == GENERIC_READ); assert(s == FILE_SHARE_READ); assert(!sa); assert(d == final_disp); assert(!f); assert(!t);
  final_call(); create_w_calls++; return backend_fails ? INVALID_HANDLE_VALUE : (HANDLE)42;
}
static HANDLE WINAPI create_a(LPCSTR p, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa, DWORD d, DWORD f, HANDLE t) {
  (void)p; assert(a == GENERIC_READ); assert(s == FILE_SHARE_READ); assert(!sa); assert(d == final_disp); assert(!f); assert(!t);
  final_call(); create_a_calls++; return backend_fails ? INVALID_HANDLE_VALUE : (HANDLE)42;
}
static DWORD WINAPI attrs_w(LPCWSTR p) {
  if (GetLastError() == 12345) { final_call(); attrs_w_calls++; return backend_fails ? INVALID_FILE_ATTRIBUTES : FILE_ATTRIBUTE_ARCHIVE; }
  SetLastError(9200);
  return p[0] == accept_cp ? FILE_ATTRIBUTE_ARCHIVE : INVALID_FILE_ATTRIBUTES;
}
static DWORD WINAPI attrs_a(LPCSTR p) {
  (void)p; final_call(); attrs_a_calls++; return backend_fails ? INVALID_FILE_ATTRIBUTES : FILE_ATTRIBUTE_ARCHIVE;
}
static int WINAPI test_mb(UINT cp, DWORD flags, LPCCH p, int n, LPWSTR out, int cap) {
  assert(p && n == -1 && cap > 1);
  assert(flags == (cp == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0));
  assert(probe_count < 8); probed[probe_count++] = cp;
  SetLastError(9100); out[0] = (WCHAR)cp; out[1] = 0; return 2;
}
int k_trace_enabled(void) { SetLastError(9300); return trace_on; }
void k_log(const char *fmt, ...) { (void)fmt; logs++; SetLastError(9400); }
int k_iat_hook(const char *dll, const char *fn, void *repl) { (void)dll; (void)fn; (void)repl; return 1; }
#define MultiByteToWideChar test_mb
#include "fslog.c"

static void reset(void) {
  probe_count = 0; create_a_calls = create_w_calls = attrs_a_calls = attrs_w_calls = 0;
  final_disp = OPEN_EXISTING; SetLastError(12345);
}
static void result_error(void) { assert(GetLastError() == (backend_sets_error ? 54321 : 12345)); }
static void check_probes(int count) {
  assert(probe_count == count);
  if (count > 0) assert(probed[0] == CP_UTF8);
  if (count > 1) assert(probed[1] == 932);
  if (count > 2) assert(probed[2] == CP_ACP);
}
int main(void) {
  int tr, err, fail, choice;
  UINT cps[] = { CP_UTF8, 932, CP_ACP, 9999 };
  real_create_w = create_w; real_create_a = create_a; real_attrs_w = attrs_w; real_attrs_a = attrs_a;
  for (tr = 0; tr <= 1; tr++) for (err = 0; err <= 1; err++) for (fail = 0; fail <= 1; fail++) {
    trace_on = tr; backend_sets_error = err; backend_fails = fail;
    for (choice = 0; choice < 4; choice++) {
      HANDLE h; DWORD attr; int before = logs;
      accept_cp = cps[choice]; reset();
      h = my_create_a("data.arc", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
      result_error(); assert(h == (fail ? INVALID_HANDLE_VALUE : (HANDLE)42));
      assert(create_w_calls == (choice < 3)); assert(create_a_calls == (choice == 3));
      check_probes(choice < 3 ? choice + 1 : 3); if (!tr) assert(logs == before);
      reset(); before = logs;
      attr = my_attrs_a("data.arc"); result_error();
      assert(attr == (fail ? INVALID_FILE_ATTRIBUTES : FILE_ATTRIBUTE_ARCHIVE));
      assert(attrs_w_calls == (choice < 3)); assert(attrs_a_calls == (choice == 3));
      check_probes(choice < 3 ? choice + 1 : 3); if (!tr) assert(logs == before);
    }
    reset();
    assert(my_create_w(L"data.arc", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL) ==
           (fail ? INVALID_HANDLE_VALUE : (HANDLE)42));
    result_error(); assert(create_w_calls == 1);
    reset(); final_disp = CREATE_ALWAYS;
    my_create_a("data.arc", GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    result_error(); assert(create_a_calls == 1); check_probes(0);
    reset(); my_create_a(NULL, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    result_error(); assert(create_a_calls == 1); check_probes(0);
    reset(); my_attrs_a(NULL); result_error(); assert(attrs_a_calls == 1); check_probes(0);
  }
  assert(logs);
  puts("PASS: A/W file calls preserve entry/backend LastError for success/failure, trace on/off, null/non-OPEN_EXISTING and unchanged UTF-8/932/ACP probe order");
  return 0;
}
