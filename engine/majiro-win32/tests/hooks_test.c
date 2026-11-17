#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static BYTE *fake_base;
static int protect_calls, fail_protect, fail_protect_from, flush_calls, fail_flush;
static int gdi_calls, fs_calls, msgbox_calls, temp_mode, file_mode, writes;
static char last_log[1024];
static BOOL WINAPI test_protect(LPVOID p, SIZE_T n, DWORD flags, PDWORD old) {
  ++protect_calls;
  if (protect_calls == fail_protect || (fail_protect_from && protect_calls >= fail_protect_from)) {
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
  }
  return VirtualProtect(p, n, flags, old);
}
static BOOL WINAPI test_flush(HANDLE p, LPCVOID b, SIZE_T n) {
  ++flush_calls;
  if (flush_calls == fail_flush) { SetLastError(ERROR_INVALID_FUNCTION); return FALSE; }
  return FlushInstructionCache(p, b, n);
}
static HMODULE WINAPI test_module(LPCSTR name) { assert(!name); return (HMODULE)fake_base; }
static DWORD WINAPI test_temp(DWORD n, LPSTR p) {
  SetLastError(9001);
  if (temp_mode) return 0;
  assert(n > 16); strcpy(p, "C:\\synthetic\\"); return (DWORD)strlen(p);
}
static HANDLE WINAPI test_create(LPCSTR p, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa,
                                 DWORD d, DWORD f, HANDLE t) {
  (void)p; (void)a; (void)s; (void)sa; (void)d; (void)f; (void)t;
  SetLastError(9002); return file_mode ? INVALID_HANDLE_VALUE : (HANDLE)42;
}
static DWORD WINAPI test_seek(HANDLE h, LONG d, PLONG hi, DWORD m) {
  (void)h; (void)d; (void)hi; (void)m; SetLastError(9003); return 0;
}
static BOOL WINAPI test_write(HANDLE h, LPCVOID b, DWORD n, LPDWORD out, LPOVERLAPPED ov) {
  (void)h; (void)ov; assert(n < sizeof(last_log));
  memcpy(last_log, b, n); last_log[n] = 0; *out = n; writes++; SetLastError(9004); return TRUE;
}
static BOOL WINAPI test_close(HANDLE h) { (void)h; SetLastError(9005); return TRUE; }
#define VirtualProtect test_protect
#define FlushInstructionCache test_flush
#define GetModuleHandleA test_module
#define GetTempPathA test_temp
#define CreateFileA test_create
#define SetFilePointer test_seek
#define WriteFile test_write
#define CloseHandle test_close
#include "hooks.c"
#undef VirtualProtect
#undef FlushInstructionCache
#undef GetModuleHandleA
#undef GetTempPathA
#undef CreateFileA
#undef SetFilePointer
#undef WriteFile
#undef CloseHandle
#include "utf8.c"
void k_gdi_init(void) { gdi_calls++; }
void k_msgbox_init(void) { msgbox_calls++; }
void k_fs_init(void) { fs_calls++; }

static const BYTE fc_prologue[7] = {0x80, 0x7B, 0x29, 0x00, 0x8D, 0x4B, 0x29};
static const BYTE np_call[5] = {0xE8, 0x0C, 0xA9, 0x00, 0x00};
static const struct { DWORD addr; const BYTE *sig; size_t len; } sigs[] = {
#define S(a,s) {a,s,sizeof(s)}
  S(0x478E40,S_HASH), S(0x47C5D0,S_NEXT), S(0x47C610,S_COUNT), S(0x47C6C0,S_SKIP),
  S(0x47EE00,S_LEAD), S(0x47C650,S_LOWER), S(0x47C440,S_STRCHR), S(0x47C710,S_STRREV),
  S(0x4444C4,S_K1), S(0x44463B,S_K2), S(0x444870,S_K2), S(0x444D57,S_K3),
  S(0x442AEF,S_K4), S(0x4444F3,S_M1), S(0x442B2E,S_M2),
  S(0x443EC2,fc_prologue), S(0x44421F,np_call)
#undef S
};
static void setup(void) {
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS32 *nt;
  IMAGE_SECTION_HEADER *section;
  size_t i;
  DWORD old;
  if (!fake_base) fake_base = VirtualAlloc(NULL, 0x90000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  assert(fake_base);
  assert(VirtualProtect(fake_base, 0x90000, PAGE_EXECUTE_READWRITE, &old));
  memset(fake_base, 0, 0x90000);
  dos = (IMAGE_DOS_HEADER *)fake_base; dos->e_magic = IMAGE_DOS_SIGNATURE; dos->e_lfanew = 0x80;
  nt = (IMAGE_NT_HEADERS32 *)(fake_base + 0x80);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
  nt->FileHeader.NumberOfSections = 1;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  nt->OptionalHeader.SizeOfImage = 0x90000;
  nt->OptionalHeader.SizeOfHeaders = 0x1000;
  nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  section = IMAGE_FIRST_SECTION(nt);
  section->VirtualAddress = 0x1000; section->Misc.VirtualSize = 0x8f000;
  section->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
  for (i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++)
    memcpy(fake_base + sigs[i].addr - IMAGE_BASE, sigs[i].sig, sigs[i].len);
  g_base = fake_base;
  g_backup_count = 0; g_hooks_ready = 0; g_iat_failed = 0;
  protect_calls = flush_calls = fail_protect = fail_protect_from = fail_flush = 0;
  assert(validate_image()); assert(validate_imports()); assert(hash_core_ok());
}
static void originals(void) {
  size_t i;
  for (i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++)
    assert(memcmp(fake_base + sigs[i].addr - IMAGE_BASE, sigs[i].sig, sigs[i].len) == 0);
}
static IMAGE_IMPORT_DESCRIPTOR *imports(void) {
  IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(fake_base + 0x1000);
  memset(imp, 0, 2 * sizeof(*imp));
  imp->Name = 0x1100; imp->OriginalFirstThunk = 0x1200; imp->FirstThunk = 0x1300;
  strcpy((char *)fake_base + 0x1100, "kernel32.dll");
  *(DWORD *)(fake_base + 0x1200) = 0x1400;
  *(DWORD *)(fake_base + 0x1204) = 0;
  *(DWORD *)(fake_base + 0x1300) = 0x76543210;
  *(DWORD *)(fake_base + 0x1304) = 0;
  *(WORD *)(fake_base + 0x1400) = 0;
  strcpy((char *)fake_base + 0x1402, "CreateFileA");
  g_imports.VirtualAddress = 0x1000; g_imports.Size = 2 * sizeof(*imp);
  return imp;
}
static void boundaries(void) {
  IMAGE_DOS_HEADER *dos;
  IMAGE_IMPORT_DESCRIPTOR *imp;
  DWORD old;
  BYTE b = 0;
  setup();
  assert(!k_readable(NULL, 1)); assert(!k_readable((void *)0xfffffffe, 8));
  assert(!image_range(0xffffffff, 4)); assert(!image_range(g_size - 1, 2));
  assert(!sig_ok(IMAGE_BASE - 1, &b, 1)); assert(!sig_ok(IMAGE_BASE + g_size, &b, 1));
  dos = (IMAGE_DOS_HEADER *)fake_base;
  dos->e_lfanew = 0x7fffffff; assert(!validate_image());
  setup(); dos->e_magic = 0; assert(!validate_image());
  setup(); g_nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64; assert(!validate_image());
  setup(); g_nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC; assert(!validate_image());
  setup(); g_nt->OptionalHeader.SizeOfHeaders = 0x100; assert(!validate_image());
  setup(); g_nt->OptionalHeader.SizeOfImage = 0x1000; assert(!validate_image());
  setup(); g_nt->FileHeader.SizeOfOptionalHeader = 1; assert(!validate_image());
  setup(); g_nt->FileHeader.NumberOfSections = 97; assert(!validate_image());
  setup(); g_sections[0].Misc.VirtualSize = 0xffffffff; assert(!validate_image());
  setup(); g_sections[0].Characteristics = IMAGE_SCN_MEM_READ; assert(!hash_core_ok());
  setup(); assert(VirtualProtect(fake_base + 0x79000, 0x1000, PAGE_NOACCESS, &old)); assert(!hash_core_ok());
  assert(VirtualProtect(fake_base + 0x79000, 0x1000, old, &old));
  assert(VirtualProtect(fake_base + 0x7c000, 0x1000, PAGE_READONLY | PAGE_GUARD, &old));
  assert(!sig_ok(0x47C5D0, S_NEXT, sizeof(S_NEXT)));
  setup(); imp = imports(); assert(validate_imports());
  g_imports.Size = sizeof(*imp); assert(!validate_imports());
  imports(); g_imports.VirtualAddress = g_size - 1; assert(!validate_imports());
  imports(); imp->Name = g_size - 1; fake_base[g_size - 1] = 'x'; assert(!validate_imports());
  fake_base[g_size - 1] = 0; assert(validate_imports());
  imports(); *(DWORD *)(fake_base + 0x1200) = g_size - 1; assert(!validate_imports());
  imports(); *(DWORD *)(fake_base + 0x1200) = IMAGE_ORDINAL_FLAG32 | 3; assert(validate_imports());
  imports(); *(DWORD *)(fake_base + 0x1300) = 0; assert(!validate_imports());
  imports(); imp->FirstThunk = g_size - 4; *(DWORD *)(fake_base + g_size - 4) = 1; assert(!validate_imports());
  imports(); imp->OriginalFirstThunk = 0;
  assert(validate_imports()); assert(iat_hook_export("kernel32.dll", "CreateFileA", (void *)1));
  assert(*(DWORD *)(fake_base + 0x1300) == 0x76543210);
  imports(); assert(iat_hook_export("kernel32.dll", "CreateFileA", (void *)0x1234));
  assert(*(DWORD *)(fake_base + 0x1300) == 0x1234);
  imports(); protect_calls = 0; fail_protect = 2;
  assert(!iat_hook_export("kernel32.dll", "CreateFileA", (void *)0x1234));
  assert(*(DWORD *)(fake_base + 0x1300) == 0x76543210);
  setup(); imports(); protect_calls = 0; fail_protect = 1;
  assert(!iat_hook_export("kernel32.dll", "CreateFileA", (void *)0x1234));
  assert(*(DWORD *)(fake_base + 0x1300) == 0x76543210);
  puts("PASS: PE32/I386, inaccessible/signature/hash ranges, import/string/thunk bounds, OFT=0, IAT failures");
}
static void writes_and_rollback(void) {
  int i;
  DWORD old;
  MEMORY_BASIC_INFORMATION mbi;
  for (i = 1; i <= 30; i++) {
    setup(); assert(VirtualProtect(fake_base, 0x90000, PAGE_EXECUTE_READ, &old));
    fail_protect = i;
    assert(!patch_text_layer()); assert(!g_backup_count); originals();
    assert(VirtualQuery(fake_base + 0x78e40, &mbi, sizeof(mbi)));
    assert(mbi.Protect == PAGE_EXECUTE_READ);
  }
  for (i = 1; i <= 15; i++) {
    setup(); fail_flush = i;
    assert(!patch_text_layer()); assert(!g_backup_count); originals();
  }
  setup(); assert(patch_text_layer()); assert(g_backup_count == 15);
  assert(rollback_code()); originals();
  setup(); fail_flush = 2; fail_protect_from = 5;
  assert(!patch_text_layer()); assert(!g_backup_count); assert(protect_calls <= 6);
  assert(strstr(last_log, "incomplete"));
  puts("PASS: 30 protection and 15 cache-flush failure points, bounded complete/incomplete rollback");
}
static void logs(void) {
  int i;
  for (i = 0; i < 3; i++) {
    temp_mode = i == 1; file_mode = i == 2;
    SetLastError(12345); k_log("synthetic %d", i); assert(GetLastError() == 12345);
  }
  temp_mode = file_mode = 0;
  SetEnvironmentVariableA("RURI_TRACE", NULL); SetLastError(12345);
  assert(!k_trace_enabled()); assert(GetLastError() == 12345);
  SetEnvironmentVariableA("RURI_TRACE", "1"); SetLastError(12345);
  assert(k_trace_enabled()); assert(GetLastError() == 12345);
  SetEnvironmentVariableA("RURI_TRACE", NULL);
  puts("PASS: log success/failure and trace checks preserve LastError");
}
int main(int argc, char **argv) {
  assert(argc == 2);
  if (!strcmp(argv[1], "helpers")) { boundaries(); writes_and_rollback(); logs(); }
  else {
    setup();
    if (!strcmp(argv[1], "mismatch")) fake_base[0x7c5d0] ^= 1;
    else if (!strcmp(argv[1], "badpe")) ((IMAGE_DOS_HEADER *)fake_base)->e_magic = 0;
    else if (!strcmp(argv[1], "badimport")) {
      g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x8ffff;
      g_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 40;
    } else if (!strcmp(argv[1], "writefail")) fail_protect = 9;
    else assert(!strcmp(argv[1], "valid"));
    SetLastError(12345); ruri_init(); assert(GetLastError() == 12345);
    if (!strcmp(argv[1], "valid")) { assert(gdi_calls == 1 && msgbox_calls == 1 && fs_calls == 1 && g_hooks_ready); }
    else { assert(!gdi_calls && !msgbox_calls && !fs_calls && !g_hooks_ready); }
    ruri_init(); assert(gdi_calls <= 1 && msgbox_calls <= 1 && fs_calls <= 1);
    if (!strcmp(argv[1], "writefail")) originals();
    printf("PASS: init gate %s\n", argv[1]);
  }
  VirtualFree(fake_base, 0, MEM_RELEASE);
  return 0;
}
