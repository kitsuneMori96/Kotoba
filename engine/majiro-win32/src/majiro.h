#ifndef KOTOBA_MAJIRO_H
#define KOTOBA_MAJIRO_H

#include <windows.h>
#include <stdint.h>

/* UTF-8 aware character iteration shared with the engine patches. */
extern uint32_t g_last_key;
extern uint32_t g_char_len;
extern char g_char_buf[8];

int k_decode(const unsigned char *p, uint32_t *cp);

const char *__cdecl k_next(const char *p);
int __cdecl k_count(const char *p);
const char *__cdecl k_skip(const char *p, int n);
int __cdecl k_is_lead(int b);
char *__cdecl k_lower(char *p);
const char *__cdecl k_strchr(const char *s, unsigned int ch);

void k_log(const char *fmt, ...);
void k_iat_hook(const char *dll, const char *fn, void *repl);
void k_gdi_init(void);
void k_fs_init(void);
void kotoba_init(void);

#endif
