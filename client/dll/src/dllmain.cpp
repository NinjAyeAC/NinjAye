#include "bridge_runtime.h"

#include <windows.h>

BOOL APIENTRY DllMain(
    HMODULE module,
    DWORD reason,
    LPVOID reserved)
{
    (void)module;
    (void)reserved;

    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(module);
        ninjaye::bridge_runtime_attach();
        break;
    case DLL_PROCESS_DETACH:
        ninjaye::bridge_runtime_detach();
        break;
    default:
        break;
    }
    return TRUE;
}
