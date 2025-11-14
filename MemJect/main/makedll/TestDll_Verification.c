#include <windows.h>
#include <stdio.h>

// Enhanced test DLL with multiple verification methods

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved)
{
    switch (ul_reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        // ============================================
        // VERIFICATION METHOD 1: MessageBox
        // ============================================
        // This will show a visible message box when DLL loads
        MessageBoxA(NULL, 
            "✓ DLL DllMain EXECUTED!\n\n"
            "This proves the DLL code is running in the target process.\n\n"
            "Module Base: 0x%p\n"
            "Process ID: %d\n"
            "Thread ID: %d",
            "DLL Execution Verified", 
            MB_OK | MB_ICONINFORMATION);
        
        // ============================================
        // VERIFICATION METHOD 2: File Writing
        // ============================================
        // Write execution log to file
        FILE* f = fopen("C:\\temp\\dll_execution_log.txt", "a");
        if (f) {
            SYSTEMTIME st;
            GetSystemTime(&st);
            fprintf(f, "========================================\n");
            fprintf(f, "DLL Loaded Successfully!\n");
            fprintf(f, "Timestamp: %04d-%02d-%02d %02d:%02d:%02d\n", 
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            fprintf(f, "Module Base: 0x%p\n", hModule);
            fprintf(f, "Process ID: %d\n", GetCurrentProcessId());
            fprintf(f, "Thread ID: %d\n", GetCurrentThreadId());
            fprintf(f, "========================================\n\n");
            fclose(f);
        }
        
        // ============================================
        // VERIFICATION METHOD 3: Registry Entry
        // ============================================
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, 
            "Software\\DLLVerification", 
            0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            DWORD tickCount = GetTickCount();
            RegSetValueExA(hKey, "LastExecutionTime", 0, REG_DWORD, 
                (BYTE*)&tickCount, sizeof(DWORD));
            
            char moduleStr[64];
            sprintf_s(moduleStr, sizeof(moduleStr), "0x%p", hModule);
            RegSetValueExA(hKey, "ModuleBase", 0, REG_SZ, 
                (BYTE*)moduleStr, (DWORD)strlen(moduleStr) + 1);
            
            RegCloseKey(hKey);
        }
        
        // ============================================
        // VERIFICATION METHOD 4: Create Named Event
        // ============================================
        // Create a named event that can be checked from outside
        HANDLE hEvent = CreateEventA(NULL, TRUE, TRUE, "DLLVerificationEvent");
        if (hEvent) {
            // Event created - can be checked with: WaitForSingleObject(OpenEvent(...), 0)
            CloseHandle(hEvent);
        }
        
        break;
    }
    
    case DLL_PROCESS_DETACH:
        // Cleanup if needed
        break;
    }
    
    return TRUE;
}

