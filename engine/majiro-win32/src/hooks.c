#include "majiro.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define IMAGE_BASE 0x400000u

static BYTE *g_base;
static int g_patched;

void k_log(const char *fmt, ...) {
  char path[MAX_PATH];
  char line[1024];
  DWORD n;
  HANDLE h;
  va_list ap;

  n = GetTempPathA(MAX_PATH, path);
  if (n == 0 || n + 20 >= MAX_PATH) return;
  lstrcatA(path, "kotoba_hook.log");
  h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                  OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return;
  SetFilePointer(h, 0, NULL, FILE_END);
  va_start(ap, fmt);
  n = (DWORD)vsnprintf(line, sizeof(line) - 3, fmt, ap);
  va_end(ap);
  if (n > sizeof(line) - 3) n = sizeof(line) - 3;
  line[n++] = '\r';
  line[n++] = '\n';
  WriteFile(h, line, n, &n, NULL);
  CloseHandle(h);
}

static int sig_ok(DWORD addr, const BYTE *sig, int n) {
  return memcmp(g_base + (addr - IMAGE_BASE), sig, n) == 0;
}

static int write_bytes(DWORD addr, const BYTE *data, int n) {
  BYTE *p = g_base + (addr - IMAGE_BASE);
  DWORD old;
  if (!VirtualProtect(p, n, PAGE_EXECUTE_READWRITE, &old)) return 0;
  memcpy(p, data, n);
  FlushInstructionCache(GetCurrentProcess(), p, n);
  VirtualProtect(p, n, old, &old);
  return 1;
}

static void install_detour(DWORD addr, void *fn) {
  BYTE buf[5];
  buf[0] = 0xE9;
  *(int32_t *)(buf + 1) = (int32_t)((BYTE *)fn - (g_base + (addr - IMAGE_BASE) + 5));
  write_bytes(addr, buf, 5);
}

/* Four draw/measure loops build a 16-bit key inline from the two raw bytes. */
static void patch_key_edx(DWORD addr, const BYTE *sig) {
  BYTE buf[12];
  memset(buf, 0x90, sizeof(buf));
  buf[0] = 0x8B;
  buf[1] = 0x15;
  *(uint32_t *)(buf + 2) = (uint32_t)&g_last_key;
  write_bytes(addr, buf, sizeof(buf));
  (void)sig;
}

/* Layout keeps the per-character text in a local; measure from the shadow copy. */
static void patch_key_ecx6(DWORD addr) {
  BYTE buf[17];
  memset(buf, 0x90, sizeof(buf));
  buf[0] = 0x8B;
  buf[1] = 0x0D;
  *(uint32_t *)(buf + 2) = (uint32_t)&g_last_key;
  write_bytes(addr, buf, sizeof(buf));
}

/* Rewrite the inline strlen + GetTextExtentPoint32A of one character so it
   measures the UTF-8 bytes captured by k_next instead of a 2-byte key. */
static void patch_measure(DWORD addr, int len, int arg_off) {
  BYTE buf[64];
  int i = 0;
  memset(buf, 0x90, sizeof(buf));
  if (arg_off == 0x08) {
    buf[i++] = 0x8D; buf[i++] = 0x4D; buf[i++] = 0xF0;  /* lea ecx,[ebp-0x10] */
    buf[i++] = 0x51;                                   /* push ecx */
  } else {
    buf[i++] = 0x8D; buf[i++] = 0x45; buf[i++] = (BYTE)(-(int)arg_off);
    buf[i++] = 0x50;                                   /* push eax */
  }
  buf[i++] = 0xFF; buf[i++] = 0x35;                    /* push dword [g_char_len] */
  *(uint32_t *)(buf + i) = (uint32_t)&g_char_len;
  i += 4;
  buf[i++] = 0x68;                                     /* push g_char_buf */
  *(uint32_t *)(buf + i) = (uint32_t)g_char_buf;
  i += 4;
  write_bytes(addr, buf, len);
}

static void iat_hook_export(const char *dll, const char *fn, void *repl) {
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)g_base;
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(g_base + dos->e_lfanew);
  DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  IMAGE_IMPORT_DESCRIPTOR *imp;

  if (!rva) return;
  for (imp = (IMAGE_IMPORT_DESCRIPTOR *)(g_base + rva); imp->Name; imp++) {
    const char *name = (const char *)(g_base + imp->Name);
    IMAGE_THUNK_DATA *thunk;
    IMAGE_THUNK_DATA *orig;
    if (lstrcmpiA(name, dll) != 0) continue;
    thunk = (IMAGE_THUNK_DATA *)(g_base + imp->FirstThunk);
    orig = (IMAGE_THUNK_DATA *)(g_base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                                                 : imp->FirstThunk));
    for (; orig->u1.Function; orig++, thunk++) {
      IMAGE_IMPORT_BY_NAME *ib;
      DWORD old;
      if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
      ib = (IMAGE_IMPORT_BY_NAME *)(g_base + orig->u1.AddressOfData);
      if (lstrcmpA((const char *)ib->Name, fn) != 0) continue;
      if (!VirtualProtect(&thunk->u1.Function, sizeof(DWORD), PAGE_READWRITE, &old)) continue;
      thunk->u1.Function = (DWORD)repl;
      VirtualProtect(&thunk->u1.Function, sizeof(DWORD), old, &old);
    }
  }
}

void k_iat_hook(const char *dll, const char *fn, void *repl) {
  if (g_base) iat_hook_export(dll, fn, repl);
}

static const BYTE S_NEXT[] = {0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x8A, 0x06, 0x84, 0xC0};
static const BYTE S_COUNT[] = {0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x57, 0x33, 0xFF, 0x8A, 0x06};
static const BYTE S_SKIP[] = {0x55, 0x8B, 0xEC, 0x53, 0x8B, 0x5D, 0x0C, 0x85, 0xDB, 0x7E, 0x34};
static const BYTE S_LEAD[] = {0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x0F, 0xB6, 0xC0, 0x0F, 0xBE, 0x80};
static const BYTE S_LOWER[] = {0x55, 0x8B, 0xEC, 0x56, 0x57, 0x8B, 0x7D, 0x08, 0x8B, 0xF7};
static const BYTE S_STRCHR[] = {0x55, 0x8B, 0xEC, 0x53, 0x8B, 0x5D, 0x0C, 0x81, 0xFB, 0x00, 0x01, 0x00, 0x00};
static const BYTE S_STRREV[] = {0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x04, 0x08, 0x00, 0x00};

static const BYTE S_K1[] = {0x0F, 0xB6, 0x56, 0x01, 0x0F, 0xB6, 0x0E, 0xC1, 0xE2, 0x08, 0x03, 0xD1};
static const BYTE S_K2[] = {0x0F, 0xB6, 0x50, 0x01, 0x0F, 0xB6, 0x08, 0xC1, 0xE2, 0x08, 0x03, 0xD1};
static const BYTE S_K3[] = {0x0F, 0xB6, 0x53, 0x01, 0x0F, 0xB6, 0x0B, 0xC1, 0xE2, 0x08, 0x03, 0xD1};
static const BYTE S_K4[] = {0x0F, 0xB6, 0x02, 0x83, 0xFE, 0x02, 0x7C, 0x0E, 0x0F, 0xB6, 0x4A, 0x01,
                            0xC1, 0xE1, 0x08, 0x03, 0xC8};
static const BYTE S_M1[] = {0x8D, 0x45, 0x08, 0x8D, 0x50, 0x01, 0x8D, 0xA4, 0x24, 0x00, 0x00, 0x00,
                            0x00, 0x8A, 0x08, 0x40, 0x84, 0xC9, 0x75, 0xF9, 0x8D, 0x4D, 0xF0, 0x2B,
                            0xC2, 0x51, 0x50, 0x8D, 0x45, 0x08, 0x50};
static const BYTE S_M2[] = {0x8D, 0x4D, 0xF8, 0x8D, 0x51, 0x01, 0x8A, 0x01, 0x41, 0x84, 0xC0, 0x75,
                            0xF9, 0x8D, 0x45, 0xD4, 0x2B, 0xCA, 0x50, 0x51, 0x8D, 0x45, 0xF8, 0x50};

static const BYTE S_HASH[] = {0x55, 0x8B, 0xEC, 0x8B, 0x55, 0x08, 0x8B, 0xC2, 0x56, 0x8D, 0x70, 0x01};

typedef unsigned long long(__cdecl *hash_core_t)(unsigned long long, const char *, unsigned);

/* Arc entries are keyed by the hash of the CP932 name, but UTF-8 scripts pass
   UTF-8 bytes; hash the CP932 form whenever the name converts losslessly. */
static unsigned long long __cdecl k_name_hash(const char *s) {
  hash_core_t core = (hash_core_t)(g_base + (0x479150 - IMAGE_BASE));
  const char *p = s;
  char buf[512];
  WCHAR w[256];
  BOOL bad = FALSE;
  const unsigned char *q;
  for (q = (const unsigned char *)s; *q && *q < 0x80; q++) {}
  if (*q && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, 256) > 0 &&
      WideCharToMultiByte(932, WC_NO_BEST_FIT_CHARS, w, -1, buf, sizeof(buf), NULL, &bad) > 0 && !bad)
    p = buf;
  return ~core(~0ULL, p, (unsigned)strlen(p));
}

static void patch_text_layer(void) {
  install_detour(0x478E40, (void *)k_name_hash);
  install_detour(0x47C5D0, (void *)k_next);
  install_detour(0x47C610, (void *)k_count);
  install_detour(0x47C6C0, (void *)k_skip);
  install_detour(0x47EE00, (void *)k_is_lead);
  install_detour(0x47C650, (void *)k_lower);
  install_detour(0x47C440, (void *)k_strchr);
  install_detour(0x47C710, (void *)k_strrev);

  patch_key_edx(0x4444C4, S_K1);
  patch_key_edx(0x44463B, S_K2);
  patch_key_edx(0x444870, S_K2);
  patch_key_edx(0x444D57, S_K3);
  patch_key_ecx6(0x442AEF);
  patch_measure(0x4444F3, 31, 0x08);
  patch_measure(0x442B2E, 24, 0x2C);
}

static LONG WINAPI crash_filter(EXCEPTION_POINTERS *ep) {
  DWORD code = ep->ExceptionRecord->ExceptionCode;
  PVOID addr = ep->ExceptionRecord->ExceptionAddress;
  static int logged;
  if (!logged) {
    logged = 1;
    k_log("crash: code=%08lx addr=%p exe_off=%08lx",
          (unsigned long)code, addr,
          (unsigned long)((BYTE *)addr - g_base));
    if (ep->ExceptionRecord->NumberParameters >= 2)
      k_log("crash: param0=%08lx param1=%08lx",
            (unsigned long)ep->ExceptionRecord->ExceptionInformation[0],
            (unsigned long)ep->ExceptionRecord->ExceptionInformation[1]);
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

void kotoba_init(void) {
  HMODULE self = NULL;

  g_base = (BYTE *)GetModuleHandleA(NULL);
  if (!g_base) return;

  k_log("kotoba: base=%p", g_base);
  SetUnhandledExceptionFilter(crash_filter);
  AddVectoredExceptionHandler(1, crash_filter);

  if (!(sig_ok(0x47C5D0, S_NEXT, sizeof(S_NEXT)) && sig_ok(0x47C610, S_COUNT, sizeof(S_COUNT)) &&
        sig_ok(0x47C6C0, S_SKIP, sizeof(S_SKIP)) && sig_ok(0x47EE00, S_LEAD, sizeof(S_LEAD)) &&
        sig_ok(0x47C650, S_LOWER, sizeof(S_LOWER)) && sig_ok(0x47C440, S_STRCHR, sizeof(S_STRCHR)) && sig_ok(0x47C710, S_STRREV, sizeof(S_STRREV)) && sig_ok(0x478E40, S_HASH, sizeof(S_HASH)) && sig_ok(0x4444C4, S_K1, sizeof(S_K1)) &&
        sig_ok(0x44463B, S_K2, sizeof(S_K2)) && sig_ok(0x444870, S_K2, sizeof(S_K2)) &&
        sig_ok(0x444D57, S_K3, sizeof(S_K3)) && sig_ok(0x442AEF, S_K4, sizeof(S_K4)) &&
        sig_ok(0x4444F3, S_M1, sizeof(S_M1)) && sig_ok(0x442B2E, S_M2, sizeof(S_M2)))) {
    k_log("kotoba: executable signature mismatch, text patches skipped");
  } else {
    patch_text_layer();
    g_patched = 1;
    k_log("kotoba: text layer patched");
  }

  k_gdi_init();
  k_fs_init();
  k_log("kotoba: gdi hooks installed (text layer %s)", g_patched ? "on" : "off");
  (void)self;
}
