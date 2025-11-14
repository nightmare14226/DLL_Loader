#include <windows.h>

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved)
{
    switch (ul_reason)
    {
    case DLL_PROCESS_ATTACH:
        // This will show a message box when DLL is loaded
        MessageBoxA(NULL, 
            "DLL DllMain EXECUTED!\n\nThis proves the DLL code is running.",
            "Verification Success", 
            MB_OK | MB_ICONINFORMATION);
        break;
    }
    return TRUE;
}