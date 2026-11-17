#include "majiro.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define IMAGE_BASE 0x400000u

static BYTE *g_base;
static DWORD g_size;
static IMAGE_NT_HEADERS32 *g_nt;
static IMAGE_SECTION_HEADER *g_sections;
static IMAGE_DATA_DIRECTORY g_imports;
static int g_hooks_ready;
static int g_iat_failed;

int k_trace_enabled(void) {
  DWORD saved = GetLastError();
  int enabled = GetEnvironmentVariableA("KOTOBA_TRACE", NULL, 0) > 0;
  SetLastError(saved);
  return enabled;
}

int k_readable(const void *ptr, SIZE_T len) {
  uintptr_t p = (uintptr_t)ptr;
  if (!p || !len || len > UINTPTR_MAX - p) return 0;
  while (len) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T step;
    if (!VirtualQuery((const void *)p, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
        (mbi.Protect & PAGE_GUARD) ||
        !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
      return 0;
    step = mbi.RegionSize - (p - (uintptr_t)mbi.BaseAddress);
    if (!step) return 0;
    if (step > len) step = len;
    p += step;
    len -= step;
  }
  return 1;
}

static int image_range(DWORD rva, SIZE_T len) {
  uintptr_t p;
  if (rva >= g_size || len > g_size - rva || !k_readable(g_base + rva, len)) return 0;
  p = (uintptr_t)(g_base + rva);
  while (len) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T step;
    if (!VirtualQuery((void *)p, &mbi, sizeof(mbi)) || mbi.AllocationBase != g_base) return 0;
    step = mbi.RegionSize - (p - (uintptr_t)mbi.BaseAddress);
    if (!step) return 0;
    if (step > len) step = len;
    p += step;
    len -= step;
  }
  return 1;
}

static int executable_range(DWORD rva, SIZE_T len) {
  unsigned i;
  uintptr_t p;
  SIZE_T left = len;
  if (!image_range(rva, len)) return 0;
  for (i = 0; i < g_nt->FileHeader.NumberOfSections; i++) {
    const IMAGE_SECTION_HEADER *s = &g_sections[i];
    DWORD size = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
    if ((s->Characteristics & IMAGE_SCN_MEM_EXECUTE) && rva >= s->VirtualAddress &&
        rva - s->VirtualAddress < size && len <= size - (rva - s->VirtualAddress)) break;
  }
  if (i == g_nt->FileHeader.NumberOfSections) return 0;
  p = (uintptr_t)(g_base + rva);
  while (left) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T step;
    if (!VirtualQuery((void *)p, &mbi, sizeof(mbi)) ||
        !(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
      return 0;
    step = mbi.RegionSize - (p - (uintptr_t)mbi.BaseAddress);
    if (!step) return 0;
    if (step > left) step = left;
    p += step;
    left -= step;
  }
  return 1;
}

static int validate_image(void) {
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)g_base;
  IMAGE_NT_HEADERS32 *nt;
  SIZE_T section_rva, headers;
  unsigned i;
  g_size = 0;
  g_nt = NULL;
  memset(&g_imports, 0, sizeof(g_imports));
  if (!k_readable(dos, sizeof(*dos)) || dos->e_magic != IMAGE_DOS_SIGNATURE ||
      dos->e_lfanew < (LONG)sizeof(*dos) ||
      (SIZE_T)dos->e_lfanew > UINTPTR_MAX - (uintptr_t)g_base - sizeof(*nt)) return 0;
  nt = (IMAGE_NT_HEADERS32 *)(g_base + dos->e_lfanew);
  if (!k_readable(nt, sizeof(*nt)) || nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
      nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32) ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
      nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT ||
      nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
      !nt->FileHeader.NumberOfSections || nt->FileHeader.NumberOfSections > 96) return 0;
  g_size = nt->OptionalHeader.SizeOfImage;
  headers = nt->OptionalHeader.SizeOfHeaders;
  section_rva = (SIZE_T)dos->e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
                nt->FileHeader.SizeOfOptionalHeader;
  if (!g_size || g_size > UINTPTR_MAX - (uintptr_t)g_base || headers > g_size ||
      section_rva > headers || nt->FileHeader.NumberOfSections >
      (headers - section_rva) / sizeof(IMAGE_SECTION_HEADER) ||
      !image_range(0, headers)) return 0;
  g_nt = nt;
  g_sections = (IMAGE_SECTION_HEADER *)(g_base + section_rva);
  for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    const IMAGE_SECTION_HEADER *s = &g_sections[i];
    DWORD size = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
    if (s->VirtualAddress > g_size || size > g_size - s->VirtualAddress) return 0;
  }
  g_imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  return 1;
}

static const char *image_string(DWORD rva) {
  DWORD start = rva;
  while (rva < g_size) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T step;
    if (!image_range(rva, 1) || !VirtualQuery(g_base + rva, &mbi, sizeof(mbi))) return NULL;
    step = mbi.RegionSize - ((uintptr_t)(g_base + rva) - (uintptr_t)mbi.BaseAddress);
    if (step > g_size - rva) step = g_size - rva;
    if (!step) return NULL;
    if (memchr(g_base + rva, 0, step)) return (const char *)(g_base + start);
    rva += (DWORD)step;
  }
  return NULL;
}

static int validate_thunks(const IMAGE_IMPORT_DESCRIPTOR *imp) {
  DWORD iat = imp->FirstThunk, names = imp->OriginalFirstThunk;
  if (!iat) return 0;
  for (;;) {
    DWORD target, name;
    if (!image_range(iat, sizeof(DWORD))) return 0;
    memcpy(&target, g_base + iat, sizeof(target));
    if (names) {
      if (!image_range(names, sizeof(DWORD))) return 0;
      memcpy(&name, g_base + names, sizeof(name));
      if (!name || !target) return !name && !target;
      if (!(name & IMAGE_ORDINAL_FLAG32) &&
          (!image_range(name, sizeof(WORD) + 1) || !image_string(name + sizeof(WORD)))) return 0;
      names += sizeof(DWORD);
    } else if (!target) {
      return 1;
    }
    iat += sizeof(DWORD);
  }
}

static int validate_imports(void) {
  SIZE_T off;
  if (!g_imports.VirtualAddress && !g_imports.Size) return 1;
  if (!g_imports.VirtualAddress || g_imports.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
      !image_range(g_imports.VirtualAddress, g_imports.Size)) return 0;
  for (off = 0; off <= g_imports.Size - sizeof(IMAGE_IMPORT_DESCRIPTOR);
       off += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
    const IMAGE_IMPORT_DESCRIPTOR *imp =
        (const IMAGE_IMPORT_DESCRIPTOR *)(g_base + g_imports.VirtualAddress + off);
    if (!imp->Name && !imp->FirstThunk && !imp->OriginalFirstThunk &&
        !imp->TimeDateStamp && !imp->ForwarderChain) return 1;
    if (!imp->Name || !image_string(imp->Name) || !validate_thunks(imp)) return 0;
  }
  return 0;
}

static int hash_core_ok(void) {
  unsigned i;
  DWORD rva = 0x479150 - IMAGE_BASE;
  for (i = 0; i < g_nt->FileHeader.NumberOfSections; i++) {
    const IMAGE_SECTION_HEADER *s = &g_sections[i];
    DWORD size = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
    if (rva >= s->VirtualAddress && rva - s->VirtualAddress < size)
      return executable_range(rva, size - (rva - s->VirtualAddress));
  }
  return 0;
}

void k_log(const char *fmt, ...) {
  char path[MAX_PATH];
  char line[1024];
  DWORD n, saved = GetLastError();
  HANDLE h;
  va_list ap;
  int count;

  n = GetTempPathA(MAX_PATH, path);
  if (n == 0 || n >= MAX_PATH - 20) goto done;
  lstrcatA(path, "kotoba_hook.log");
  h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                  OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) goto done;
  SetFilePointer(h, 0, NULL, FILE_END);
  va_start(ap, fmt);
  count = vsnprintf(line, sizeof(line) - 2, fmt, ap);
  va_end(ap);
  n = count < 0 ? 0 : (DWORD)count;
  if (n > sizeof(line) - 3) n = sizeof(line) - 3;
  line[n++] = '\r';
  line[n++] = '\n';
  WriteFile(h, line, n, &n, NULL);
  CloseHandle(h);
done:
  SetLastError(saved);
}

static int patch_range(DWORD addr, SIZE_T n) {
  MEMORY_BASIC_INFORMATION mbi;
  BYTE *p;
  if (addr < IMAGE_BASE || !executable_range(addr - IMAGE_BASE, n)) return 0;
  p = g_base + (addr - IMAGE_BASE);
  return VirtualQuery(p, &mbi, sizeof(mbi)) &&
         n <= mbi.RegionSize - ((uintptr_t)p - (uintptr_t)mbi.BaseAddress);
}

static int sig_ok(DWORD addr, const BYTE *sig, int n) {
  return n > 0 && patch_range(addr, (SIZE_T)n) &&
         memcmp(g_base + (addr - IMAGE_BASE), sig, n) == 0;
}

typedef struct {
  DWORD addr, protect;
  int len;
  BYTE bytes[64];
} code_backup;
static code_backup g_backup[24];
static unsigned g_backup_count;

static int write_bytes(DWORD addr, const BYTE *data, int n) {
  BYTE *p;
  DWORD old, ignored;
  BOOL flushed, restored;
  code_backup *b;
  if (n <= 0 || n > 64 || g_backup_count >= sizeof(g_backup) / sizeof(g_backup[0]) ||
      !patch_range(addr, (SIZE_T)n)) return 0;
  p = g_base + (addr - IMAGE_BASE);
  b = &g_backup[g_backup_count];
  b->addr = addr;
  b->len = n;
  memcpy(b->bytes, p, n);
  if (!VirtualProtect(p, n, PAGE_EXECUTE_READWRITE, &old)) return 0;
  b->protect = old;
  g_backup_count++;
  memcpy(p, data, n);
  flushed = FlushInstructionCache(GetCurrentProcess(), p, n);
  restored = VirtualProtect(p, n, old, &ignored);
  return flushed && restored;
}

static int rollback_code(void) {
  int ok = 1;
  while (g_backup_count) {
    code_backup *b = &g_backup[--g_backup_count];
    BYTE *p = g_base + (b->addr - IMAGE_BASE);
    DWORD ignored;
    if (!image_range(b->addr - IMAGE_BASE, b->len) ||
        !VirtualProtect(p, b->len, PAGE_EXECUTE_READWRITE, &ignored)) {
      ok = 0;
      continue;
    }
    memcpy(p, b->bytes, b->len);
    if (!FlushInstructionCache(GetCurrentProcess(), p, b->len)) ok = 0;
    if (!VirtualProtect(p, b->len, b->protect, &ignored)) ok = 0;
  }
  return ok;
}

static int install_detour(DWORD addr, void *fn) {
  BYTE buf[5];
  uint32_t rel = (uint32_t)(uintptr_t)fn -
                 ((uint32_t)(uintptr_t)g_base + addr - IMAGE_BASE + 5);
  buf[0] = 0xE9;
  memcpy(buf + 1, &rel, sizeof(rel));
  return write_bytes(addr, buf, 5);
}

/* Four draw/measure loops build a 16-bit key inline from the two raw bytes. */
static int patch_key_edx(DWORD addr) {
  BYTE buf[12];
  memset(buf, 0x90, sizeof(buf));
  buf[0] = 0x8B;
  buf[1] = 0x15;
  *(uint32_t *)(buf + 2) = (uint32_t)&g_last_key;
  return write_bytes(addr, buf, sizeof(buf));
}

/* Layout keeps the per-character text in a local; measure from the shadow copy. */
static int patch_key_ecx6(DWORD addr) {
  BYTE buf[17];
  memset(buf, 0x90, sizeof(buf));
  buf[0] = 0x8B;
  buf[1] = 0x0D;
  *(uint32_t *)(buf + 2) = (uint32_t)&g_last_key;
  return write_bytes(addr, buf, sizeof(buf));
}

/* Rewrite the inline strlen + GetTextExtentPoint32A of one character so it
   measures the UTF-8 bytes captured by k_next instead of a 2-byte key. */
static int patch_measure(DWORD addr, int len, int arg_off) {
  BYTE buf[64];
  int i = 0;
  if (len < 15 || len > (int)sizeof(buf)) return 0;
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
  return write_bytes(addr, buf, len);
}

static int iat_hook_export(const char *dll, const char *fn, void *repl) {
  SIZE_T off;
  if (!validate_imports()) return 0;
  if (!g_imports.VirtualAddress) return 1;
  for (off = 0; off <= g_imports.Size - sizeof(IMAGE_IMPORT_DESCRIPTOR);
       off += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
    const IMAGE_IMPORT_DESCRIPTOR *imp =
        (const IMAGE_IMPORT_DESCRIPTOR *)(g_base + g_imports.VirtualAddress + off);
    DWORD iat, names;
    if (!imp->Name) break;
    if (lstrcmpiA(image_string(imp->Name), dll) != 0) continue;
    if (!imp->OriginalFirstThunk) {
      if (k_trace_enabled()) k_log("iat: %s has no name thunks, skipped", dll);
      continue;
    }
    iat = imp->FirstThunk;
    names = imp->OriginalFirstThunk;
    for (;;) {
      DWORD name, before, old, ignored;
      DWORD *slot;
      MEMORY_BASIC_INFORMATION mbi;
      if (!image_range(names, sizeof(DWORD)) || !image_range(iat, sizeof(DWORD))) return 0;
      slot = (DWORD *)(g_base + iat);
      memcpy(&name, g_base + names, sizeof(name));
      if (!name) break;
      if (!(name & IMAGE_ORDINAL_FLAG32)) {
        const char *import_name;
        if (!image_range(name, sizeof(WORD) + 1) ||
            !(import_name = image_string(name + sizeof(WORD)))) return 0;
        if (lstrcmpA(import_name, fn) == 0) {
          if (!VirtualQuery(slot, &mbi, sizeof(mbi)) ||
              sizeof(DWORD) > mbi.RegionSize - ((uintptr_t)slot - (uintptr_t)mbi.BaseAddress))
            return 0;
          memcpy(&before, slot, sizeof(before));
          if (!VirtualProtect(slot, sizeof(DWORD), PAGE_READWRITE, &old)) return 0;
          *slot = (DWORD)(uintptr_t)repl;
          if (!VirtualProtect(slot, sizeof(DWORD), old, &ignored)) {
            int rolled_back = VirtualProtect(slot, sizeof(DWORD), PAGE_READWRITE, &ignored);
            if (rolled_back) *slot = before;
            if (!VirtualProtect(slot, sizeof(DWORD), old, &ignored)) rolled_back = 0;
            k_log("iat: rollback %s for %s!%s", rolled_back ? "complete" : "incomplete", dll, fn);
            return 0;
          }
        }
      }
      names += sizeof(DWORD);
      iat += sizeof(DWORD);
    }
  }
  return 1;
}

int k_iat_hook(const char *dll, const char *fn, void *repl) {
  int ok = g_hooks_ready && iat_hook_export(dll, fn, repl);
  if (!ok) {
    g_iat_failed = 1;
    k_log("iat: hook failed for %s!%s", dll, fn);
  }
  return ok;
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

/* Diagnostic only: who hands which size to the font factory at 0x447510. */
static void (*k_factory_resume)(void) __attribute__((used));

static void __attribute__((used)) __cdecl k_factory_log(uintptr_t caller, const unsigned char *s, int factor, uintptr_t frame) {
  const DWORD *f;
  if (!k_readable(s, 0x30)) return;
  f = (const DWORD *)s;
  k_log("factory: caller=+0x%08lx struct=%p f20=%08lx f24=%08lx h=%ld w=%ld factor=%d",
        (unsigned long)((const BYTE *)caller - g_base), (const void *)s,
        (unsigned long)f[0x20 / 4], (unsigned long)f[0x24 / 4],
        (long)f[0x28 / 4], (long)f[0x2c / 4], factor);
  if ((long)f[0x28 / 4] == 5 && k_trace_enabled()) {
    int i;
    for (i = 0; i < 14 && frame > 0x10000 && k_readable((const void *)frame, 8); i++) {
      uintptr_t next = ((const uintptr_t *)frame)[0];
      uintptr_t ret = ((const uintptr_t *)frame)[1];
      k_log("bt5[%d]=+0x%08lx", i, (unsigned long)((const BYTE *)ret - g_base));
      if (next <= frame) break;
      frame = next;
    }
  }
}

__attribute__((naked)) static void k_factory_diag(void) {
  __asm__ __volatile__(
      "push %ebp\n\t"
      "mov %esp,%ebp\n\t"
      "sub $0x40,%esp\n\t"
      "pushal\n\t"
      "push %ebp\n\t"
      "push 12(%ebp)\n\t"
      "push 8(%ebp)\n\t"
      "push 4(%ebp)\n\t"
      "call _k_factory_log\n\t"
      "add $16,%esp\n\t"
      "popal\n\t"
      "jmp *_k_factory_resume\n\t");
}

static int install_factory_diag(void) {
  static const BYTE prologue[6] = {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40};
  const BYTE *p = g_base + (0x447510 - IMAGE_BASE);
  BYTE buf[6];
  uint32_t rel;
  int in_range = patch_range(0x447510, 6);
  int cmp = memcmp(p, prologue, sizeof(prologue));
  if (!in_range || cmp != 0) {
    k_log("diag: factory range=%d cmp=%d bytes=%02x%02x%02x%02x%02x%02x want=%02x%02x%02x%02x%02x%02x",
          in_range, cmp, p[0], p[1], p[2], p[3], p[4], p[5],
          prologue[0], prologue[1], prologue[2], prologue[3], prologue[4], prologue[5]);
    return 0;
  }
  rel = (uint32_t)(uintptr_t)k_factory_diag -
        ((uint32_t)(uintptr_t)g_base + 0x447510 - IMAGE_BASE + 5);
  buf[0] = 0xE9;
  memcpy(buf + 1, &rel, sizeof(rel));
  buf[5] = 0x90;
  k_factory_resume = (void (*)(void))(g_base + (0x447516 - IMAGE_BASE));
  return write_bytes(0x447510, buf, sizeof(buf));
}

/* Control 'f' arrives as "f0x%08x0x%08x0x%08x0x%08x[@]%s" where the first two
   hex fields become font height/width.  A few scenario commands only push two
   of the four arguments, so the VM frame leftovers (e.g. 5/6) land in the h/w
   slots and shrink 96px text to 20px.  The engine treats -1 as "keep the
   current style", so rewrite degenerate sizes to that sentinel. */
static void (*k_fc_resume)(void) __attribute__((used));

static int k_fc_hex(const unsigned char *p, long *out) {
  long v = 0;
  int i;
  for (i = 0; i < 8; i++) {
    unsigned char c = p[i];
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else return 0;
    v = (v << 4) | d;
  }
  *out = v;
  return 1;
}

static void __attribute__((used)) __cdecl k_fc_fix(unsigned char *b) {
  long h = -1, w = -1;
  int fixed = 0;
  if (!b || b[0] != 'f' || b[1] != '0' || b[2] != 'x' || !k_readable(b, 22)) return;
  if (!k_fc_hex(b + 3, &h) || !k_fc_hex(b + 13, &w)) return;
  if (h >= 0 && h < 8) {
    memcpy(b + 3, "ffffffff", 8);
    fixed = 1;
  }
  if (w >= 0 && w < 8) {
    memcpy(b + 13, "ffffffff", 8);
    fixed = 1;
  }
  if (fixed)
    k_log("fctrl: h=%ld w=%ld -> keep current style", h, w);
}

__attribute__((naked)) static void k_fc_diag(void) {
  __asm__ __volatile__(
      "cmpb $0,0x29(%ebx)\n\t"
      "lea 0x29(%ebx),%ecx\n\t"
      "pushfl\n\t"
      "pushal\n\t"
      "push %ebx\n\t"
      "call _k_fc_fix\n\t"
      "add $4,%esp\n\t"
      "popal\n\t"
      "popfl\n\t"
      "jmp *_k_fc_resume\n\t");
}

static int install_fc_fix(void) {
  static const BYTE prologue[7] = {0x80, 0x7B, 0x29, 0x00, 0x8D, 0x4B, 0x29};
  const BYTE *p = g_base + (0x443EC2 - IMAGE_BASE);
  BYTE buf[7];
  uint32_t rel;
  if (!patch_range(0x443EC2, 7) || memcmp(p, prologue, sizeof(prologue)) != 0) {
    k_log("kotoba: fctrl fix range/cmp failed bytes=%02x%02x%02x%02x%02x%02x%02x",
          p[0], p[1], p[2], p[3], p[4], p[5], p[6]);
    return 0;
  }
  rel = (uint32_t)(uintptr_t)k_fc_diag -
        ((uint32_t)(uintptr_t)g_base + 0x443EC2 - IMAGE_BASE + 5);
  buf[0] = 0xE9;
  memcpy(buf + 1, &rel, sizeof(rel));
  buf[5] = 0x90;
  buf[6] = 0x90;
  k_fc_resume = (void (*)(void))(g_base + (0x443EC9 - IMAGE_BASE));
  return write_bytes(0x443EC2, buf, sizeof(buf));
}

/* The scenarios keep the speaker prefix inside the dialogue text
   ("主人公：「…").  Layout at 0x445140 passes everything before 「 to
   0x4441C0, which draws the nameplate from a stack copy.  Rename the prefix
   there so no scenario byte changes and save offsets stay untouched. */
static void *k_np_resume __attribute__((used));

static int k_str_len(const char *s, int max) {
  int i;
  for (i = 0; i < max; i++) {
    if (!k_readable(s + i, 1)) return -1;
    if (!s[i]) return i;
  }
  return -1;
}

/* The VM keeps its instruction pointer behind two global indirections.  The
   opcode handler 0x43c1f0 consumes opcode+operand before executing, so a fault
   inside it reports an IP already past the failing instruction; print a window
   around it so the bytecode can be matched against the script offline. */
static void k_vm_dump(const char *tag) {
  char *slot = (char *)g_base + (0x5d1a58 - IMAGE_BASE);
  uint32_t ip = 0;
  unsigned char b[48];
  const unsigned char *p;
  int i;
  if (k_readable(slot, 4)) {
    uint32_t state = *(uint32_t *)slot;
    if (state && k_readable((void *)(uintptr_t)state, 4)) ip = *(uint32_t *)(uintptr_t)state;
  }
  p = (const unsigned char *)(uintptr_t)ip;
  if (!ip || !k_readable(p - 16, sizeof(b))) {
    k_log("%s: vm ip=%08lx (window unreadable)", tag, (unsigned long)ip);
    return;
  }
  p -= 16;
  memcpy(b, p, sizeof(b));
  for (i = 0; i < 48; i += 16)
    k_log("%s: vm ip=%08lx [%+d] %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x "
          "%02x%02x%02x%02x",
          tag, (unsigned long)ip, i - 16, b[i], b[i + 1], b[i + 2], b[i + 3], b[i + 4],
          b[i + 5], b[i + 6], b[i + 7], b[i + 8], b[i + 9], b[i + 10], b[i + 11], b[i + 12],
          b[i + 13], b[i + 14], b[i + 15]);
}

static void __attribute__((used)) __cdecl k_np_fix(const char *s) {
  static const char jp[] = "\xE4\xB8\xBB\xE5\x85\xAC\xE5\x85\xAC"; /* 主人公 */
  static const char cn[] = "\xE5\x81\xA5\xE5\xBF\x97";             /* 健志 */
  static const char colon[] = "\xEF\xBC\x9A";                      /* ： */
  char *p = (char *)s;
  int n = p ? k_str_len(p, 0x800) : -1;
  if (k_trace_enabled()) {
    k_log("np: n=%d '%s'", n, n > 0 ? p : "");
    k_vm_dump("np");
  } else if (n >= 0 && n <= 24) {
    char hex[3 * 24 + 1];
    int i;
    for (i = 0; i < n; i++) {
      hex[i * 3 + 0] = "0123456789abcdef"[((unsigned char)p[i]) >> 4];
      hex[i * 3 + 1] = "0123456789abcdef"[((unsigned char)p[i]) & 15];
      hex[i * 3 + 2] = ' ';
    }
    hex[i * 3] = 0;
    k_log("np hex: n=%d %s", n, hex);
  }
  if (n < 9 || memcmp(p, jp, 9) != 0) return;
  memmove(p + 6, p + 9, (size_t)(n - 9 + 1));
  memcpy(p, cn, 6);
  if (memcmp(p + 6, colon, 3) == 0) p[6] = 0;
  else if (p[6] == ':') p[6] = 0;
  k_log("nameplate: 主人公 -> 健志");
}

/* The E9 patch replaces a call, so on entry [esp] is the pushed text pointer
   and no return address exists.  After renaming in place, re-create the call
   frame (return address on top of the argument) and enter the original callee
   at 0x44EB30, which queues the text run; skipping it corrupts VM state. */
static void *k_np_target __attribute__((used));

__attribute__((naked)) static void k_np_hook(void) {
  __asm__ __volatile__(
      "pushal\n\t"
      "push 0x20(%esp)\n\t"
      "call _k_np_fix\n\t"
      "add $4,%esp\n\t"
      "popal\n\t"
      "pushl _k_np_resume\n\t"
      "pushl _k_np_target\n\t"
      "ret\n\t");
}

static int install_nameplate_fix(void) {
  static const BYTE call[5] = {0xE8, 0x0C, 0xA9, 0x00, 0x00};
  const BYTE *p = g_base + (0x44421F - IMAGE_BASE);
  BYTE buf[5];
  uint32_t rel;
  if (!patch_range(0x44421F, 5) || memcmp(p, call, sizeof(call)) != 0) {
    k_log("kotoba: nameplate call signature mismatch");
    return 0;
  }
  rel = (uint32_t)(uintptr_t)k_np_hook -
        ((uint32_t)(uintptr_t)g_base + 0x44421F - IMAGE_BASE + 5);
  buf[0] = 0xE9;
  memcpy(buf + 1, &rel, sizeof(rel));
  k_np_resume = (void *)(g_base + (0x444224 - IMAGE_BASE));
  k_np_target = (void *)(g_base + (0x44EB30 - IMAGE_BASE));
  return write_bytes(0x44421F, buf, sizeof(buf));
}

static int patch_text_layer(void) {
  g_backup_count = 0;
  if (install_detour(0x478E40, (void *)k_name_hash) &&
      install_detour(0x47C5D0, (void *)k_next) &&
      install_detour(0x47C610, (void *)k_count) &&
      install_detour(0x47C6C0, (void *)k_skip) &&
      install_detour(0x47EE00, (void *)k_is_lead) &&
      install_detour(0x47C650, (void *)k_lower) &&
      install_detour(0x47C440, (void *)k_strchr) &&
      install_detour(0x47C710, (void *)k_strrev) &&
      patch_key_edx(0x4444C4) && patch_key_edx(0x44463B) &&
      patch_key_edx(0x444870) && patch_key_edx(0x444D57) &&
      patch_key_ecx6(0x442AEF) &&
      patch_measure(0x4444F3, 31, 0x08) && patch_measure(0x442B2E, 24, 0x2C)) return 1;
  k_log("kotoba: text patch failed; code rollback %s", rollback_code() ? "complete" : "incomplete");
  return 0;
}

static LONG WINAPI crash_filter(EXCEPTION_POINTERS *ep) {
  DWORD code = ep->ExceptionRecord->ExceptionCode;
  PVOID addr = ep->ExceptionRecord->ExceptionAddress;
  static int seen;
  if (seen < 16) {
    seen++;
    k_log("crash[%d]: code=%08lx addr=%p exe_off=%08lx", seen, (unsigned long)code, addr,
          (unsigned long)((BYTE *)addr - g_base));
    if (ep->ExceptionRecord->NumberParameters >= 2)
      k_log("crash[%d]: param0=%08lx param1=%08lx", seen,
            (unsigned long)ep->ExceptionRecord->ExceptionInformation[0],
            (unsigned long)ep->ExceptionRecord->ExceptionInformation[1]);
    if (ep->ContextRecord) {
      DWORD *frame = (DWORD *)(uintptr_t)ep->ContextRecord->Ebp;
      int i;
      k_log("crash[%d]: eip=+0x%08lx ebp=%p", seen,
            (unsigned long)((BYTE *)(uintptr_t)ep->ContextRecord->Eip - g_base),
            (void *)frame);
      k_log("crash[%d]: regs eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx esi=%08lx edi=%08lx "
            "esp=%08lx", seen, (unsigned long)ep->ContextRecord->Eax,
            (unsigned long)ep->ContextRecord->Ebx, (unsigned long)ep->ContextRecord->Ecx,
            (unsigned long)ep->ContextRecord->Edx, (unsigned long)ep->ContextRecord->Esi,
            (unsigned long)ep->ContextRecord->Edi, (unsigned long)ep->ContextRecord->Esp);
      if (k_readable((void *)(uintptr_t)ep->ContextRecord->Esi, 0x14))
        k_log("crash[%d]: var %08lx: %08lx %08lx %08lx %08lx %08lx", seen,
              (unsigned long)ep->ContextRecord->Esi,
              (unsigned long)((DWORD *)(uintptr_t)ep->ContextRecord->Esi)[0],
              (unsigned long)((DWORD *)(uintptr_t)ep->ContextRecord->Esi)[1],
              (unsigned long)((DWORD *)(uintptr_t)ep->ContextRecord->Esi)[2],
              (unsigned long)((DWORD *)(uintptr_t)ep->ContextRecord->Esi)[3],
              (unsigned long)((DWORD *)(uintptr_t)ep->ContextRecord->Esi)[4]);
      if (k_readable((void *)((uintptr_t)ep->ContextRecord->Ebp - 0x14), 0x18))
        k_log("crash[%d]: locals %08lx %08lx %08lx %08lx %08lx %08lx", seen,
              (unsigned long)((DWORD *)((uintptr_t)ep->ContextRecord->Ebp - 0x14))[0],
              (unsigned long)((DWORD *)((uintptr_t)ep->ContextRecord->Ebp - 0x14))[1],
              (unsigned long)((DWORD *)((uintptr_t)ep->ContextRecord->Ebp - 0x14))[2],
              (unsigned long)((DWORD *)((uintptr_t)ep->ContextRecord->Ebp - 0x14))[3],
              (unsigned long)((DWORD *)((uintptr_t)ep->ContextRecord->Ebp - 0x14))[4],
              (unsigned long)((DWORD *)((uintptr_t)ep->ContextRecord->Ebp - 0x14))[5]);
      for (i = 0; i < 10 && frame && (uintptr_t)frame > 0x10000 &&
                  k_readable(frame, 8); i++) {
        DWORD ret = frame[1], next = frame[0];
        k_log("crash[%d]: bt[%d]=+0x%08lx", seen, i,
              (unsigned long)((BYTE *)(uintptr_t)ret - g_base));
        if (next <= (DWORD)(uintptr_t)frame) break;
        frame = (DWORD *)(uintptr_t)next;
      }
      k_vm_dump("crash");
    }
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

void kotoba_init(void) {
  static int attempted;
  DWORD saved = GetLastError();
  if (attempted) return;
  attempted = 1;
  g_base = (BYTE *)GetModuleHandleA(NULL);
  if (!g_base || !validate_image() || !validate_imports() || !hash_core_ok()) {
    k_log("kotoba: invalid or unsupported image, game hooks skipped");
    goto done;
  }

  k_log("kotoba: base=%p", g_base);
  if (!(sig_ok(0x47C5D0, S_NEXT, sizeof(S_NEXT)) && sig_ok(0x47C610, S_COUNT, sizeof(S_COUNT)) &&
        sig_ok(0x47C6C0, S_SKIP, sizeof(S_SKIP)) && sig_ok(0x47EE00, S_LEAD, sizeof(S_LEAD)) &&
        sig_ok(0x47C650, S_LOWER, sizeof(S_LOWER)) && sig_ok(0x47C440, S_STRCHR, sizeof(S_STRCHR)) && sig_ok(0x47C710, S_STRREV, sizeof(S_STRREV)) && sig_ok(0x478E40, S_HASH, sizeof(S_HASH)) && sig_ok(0x4444C4, S_K1, sizeof(S_K1)) &&
        sig_ok(0x44463B, S_K2, sizeof(S_K2)) && sig_ok(0x444870, S_K2, sizeof(S_K2)) &&
        sig_ok(0x444D57, S_K3, sizeof(S_K3)) && sig_ok(0x442AEF, S_K4, sizeof(S_K4)) &&
        sig_ok(0x4444F3, S_M1, sizeof(S_M1)) && sig_ok(0x442B2E, S_M2, sizeof(S_M2)))) {
    k_log("kotoba: executable signature mismatch, game hooks skipped");
    goto done;
  }
  if (!patch_text_layer()) goto done;
  k_log("kotoba: text layer patched");
  if (!install_fc_fix()) goto done;
  k_log("kotoba: font-control fix installed");
  {
    char np[8];
    DWORD n = GetEnvironmentVariableA("KOTOBA_NP", np, sizeof(np));
    if (n > 0 && n < sizeof(np) && np[0] == '0') {
      k_log("kotoba: nameplate fix disabled by KOTOBA_NP");
    } else {
      if (!install_nameplate_fix()) goto done;
      k_log("kotoba: nameplate fix installed");
    }
  }
  if (k_trace_enabled()) {
    k_log("diag: factory probe %s", install_factory_diag() ? "on" : "failed");
  }
  SetUnhandledExceptionFilter(crash_filter);
  AddVectoredExceptionHandler(1, crash_filter);
  g_hooks_ready = 1;
  k_gdi_init();
  k_msgbox_init();
  k_fs_init();
  k_log("kotoba: hook setup %s (text layer on)", g_iat_failed ? "incomplete" : "complete");
done:
  SetLastError(saved);
}
