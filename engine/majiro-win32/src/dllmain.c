#include "majiro.h"

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(inst);
    kotoba_init();
  }
  return TRUE;
}
