# DLL Execution Verification Guide

This guide shows you **multiple ways** to verify that your DLL's `DllMain` is actually executing when injected.

## Method 1: MessageBox (Easiest - Visual Confirmation)

### Step 1: Modify your TestDll.c

```c
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
```

### Step 2: Compile the DLL
```bash
gcc -shared -o TestDll.dll TestDll.c -Wl,--subsystem,windows
```

### Step 3: Prepare the DLL for injection
You need to XOR encrypt it and save as `data.bin`. Create a simple tool or use this Python script:

```python
# encrypt_dll.py
with open('TestDll.dll', 'rb') as f:
    data = f.read()

# XOR each byte with 0xFF
encrypted = bytes(b ^ 0xFF for b in data)

# Write to data.bin
with open('data.bin', 'wb') as f:
    f.write(encrypted)

print(f"Encrypted {len(encrypted)} bytes to data.bin")
```

Run: `python encrypt_dll.py`

### Step 4: Inject and verify
1. Run your target process (chrome.exe)
2. Run `MemJect.exe`
3. **Expected Result**: A message box should appear saying "DLL DllMain EXECUTED!"

---

## Method 2: File Writing (Persistent Evidence)

### Step 1: Create a DLL that writes to a file

```c
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved)
{
    switch (ul_reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Write to a file to prove execution
        FILE* f = fopen("C:\\temp\\dll_executed.txt", "w");
        if (f) {
            fprintf(f, "DLL DllMain EXECUTED!\n");
            fprintf(f, "Module Base: 0x%p\n", hModule);
            fprintf(f, "Process ID: %d\n", GetCurrentProcessId());
            fprintf(f, "Thread ID: %d\n", GetCurrentThreadId());
            fclose(f);
        }
        break;
    }
    }
    return TRUE;
}
```

### Step 2-4: Same as Method 1

### Step 5: Check the file
After injection, check: `C:\temp\dll_executed.txt`

**Expected Result**: File exists with execution details

---

## Method 3: Process Monitor (Sysinternals)

### Step 1: Download Process Monitor
Download from: https://docs.microsoft.com/en-us/sysinternals/downloads/procmon

### Step 2: Set up filter
1. Open Process Monitor
2. Filter → Process Name → `chrome.exe` (or your target)
3. Filter → Operation → `Load Image`

### Step 3: Inject your DLL
Run MemJect.exe

### Step 4: Check Process Monitor
Look for your DLL being loaded. You should see:
- Operation: `Load Image`
- Path: Your DLL path (if it was loaded via normal means)
- Or: Memory address if manually loaded

**Note**: Manual injection might not show in Process Monitor, so this method is less reliable.

---

## Method 4: Debugger (Most Detailed)

### Step 1: Attach a debugger
Use x64dbg, WinDbg, or Visual Studio Debugger

### Step 2: Set breakpoint
Set a breakpoint in your DLL's DllMain function

### Step 3: Inject
Run MemJect.exe

### Step 4: Observe
The debugger will break when DllMain executes, showing:
- Call stack
- Register values
- Memory contents

---

## Method 5: Create Remote Thread (Advanced)

### Step 1: Create a DLL with an exported function

```c
#include <windows.h>

// Export a function
__declspec(dllexport) void VerifyExecution()
{
    MessageBoxA(NULL, "Exported function called!", "Verification", MB_OK);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved)
{
    switch (ul_reason)
    {
    case DLL_PROCESS_ATTACH:
        // DllMain executed
        MessageBoxA(NULL, "DllMain executed!", "Verification", MB_OK);
        break;
    }
    return TRUE;
}
```

### Step 2: After injection, call the exported function
You would need to:
1. Get the DLL base address in the target process
2. Use GetProcAddress to get the function address
3. CreateRemoteThread to call it

This proves both DllMain AND exported functions work.

---

## Method 6: Network Activity (If DLL connects somewhere)

### Step 1: Create DLL that makes network request

```c
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved)
{
    switch (ul_reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Make HTTP request to prove execution
        HINTERNET hInternet = InternetOpenA("DLLVerifier", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInternet) {
            HINTERNET hConnect = InternetOpenUrlA(hInternet, "http://httpbin.org/get", NULL, 0, 0, 0);
            if (hConnect) {
                // Request made - execution verified
                InternetCloseHandle(hConnect);
            }
            InternetCloseHandle(hInternet);
        }
        break;
    }
    }
    return TRUE;
}
```

### Step 2: Monitor network traffic
Use Wireshark or check your firewall logs

---

## Method 7: Registry Writing

### Step 1: DLL that writes to registry

```c
#include <windows.h>

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved)
{
    switch (ul_reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, 
            "Software\\DLLVerification", 
            0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            DWORD value = GetTickCount();
            RegSetValueExA(hKey, "LastExecution", 0, REG_DWORD, (BYTE*)&value, sizeof(DWORD));
            RegCloseKey(hKey);
        }
        break;
    }
    }
    return TRUE;
}
```

### Step 2: Check registry
After injection, check: `HKEY_CURRENT_USER\Software\DLLVerification`

---

## Quick Test Script

Create `test_injection.bat`:

```batch
@echo off
echo Preparing DLL for injection...

REM Compile DLL
gcc -shared -o TestDll.dll TestDll.c -Wl,--subsystem,windows
if errorlevel 1 (
    echo Compilation failed!
    pause
    exit /b 1
)

REM Encrypt DLL
python encrypt_dll.py
if errorlevel 1 (
    echo Encryption failed!
    pause
    exit /b 1
)

echo.
echo DLL prepared. Make sure chrome.exe is running, then:
echo 1. Run MemJect.exe
echo 2. Look for message box or check C:\temp\dll_executed.txt
echo.
pause
```

---

## Troubleshooting

### If MessageBox doesn't appear:
1. **Check if target process has a window**: Some processes don't show message boxes
2. **Check antivirus**: May be blocking
3. **Try file writing method instead**

### If file isn't created:
1. **Check permissions**: DLL runs with target process privileges
2. **Try different path**: `C:\Windows\Temp\` or current directory
3. **Check if directory exists**: Create `C:\temp\` first

### If nothing happens:
1. **Check exit code**: The loader should return success
2. **Verify DLL is valid**: Test with normal LoadLibrary first
3. **Check architecture match**: 32-bit DLL won't work in 64-bit process

---

## Recommended: Use Multiple Methods

For best verification, use **Method 1 (MessageBox)** + **Method 2 (File Writing)** together:

```c
BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved)
{
    switch (ul_reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Method 1: Visual confirmation
        MessageBoxA(NULL, "DLL Executed!", "Success", MB_OK);
        
        // Method 2: File evidence
        FILE* f = fopen("C:\\temp\\dll_log.txt", "a");
        if (f) {
            fprintf(f, "[%d] DLL loaded at 0x%p\n", GetTickCount(), hModule);
            fclose(f);
        }
        break;
    }
    }
    return TRUE;
}
```

This gives you both immediate visual feedback AND persistent evidence.

