@echo off
REM Build and encrypt DLL for MemJect injection

echo ========================================
echo Building Test DLL for Verification
echo ========================================
echo.

REM Compile the DLL
echo [1/3] Compiling DLL...
gcc -shared -o TestDll_Verification.dll TestDll_Verification.c -Wl,--subsystem,windows
if errorlevel 1 (
    echo ERROR: Compilation failed!
    pause
    exit /b 1
)
echo ✓ DLL compiled successfully
echo.

REM Encrypt the DLL
echo [2/3] Encrypting DLL...
python encrypt_dll.py TestDll_Verification.dll ..\data.bin
if errorlevel 1 (
    echo ERROR: Encryption failed!
    pause
    exit /b 1
)
echo ✓ DLL encrypted to data.bin
echo.

REM Create temp directory for logs
echo [3/3] Creating temp directory...
if not exist "C:\temp" mkdir "C:\temp"
echo ✓ Ready for injection
echo.

echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Make sure your target process (chrome.exe) is running
echo 2. Run MemJect.exe from the main directory
echo 3. Look for:
echo    - Message box popup
echo    - File: C:\temp\dll_execution_log.txt
echo    - Registry: HKEY_CURRENT_USER\Software\DLLVerification
echo.
pause

