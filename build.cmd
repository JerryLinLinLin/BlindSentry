@echo off
rem Build sentry_eye_poc.exe (x64). Adjust the VS path if needed.
setlocal
cd /d "%~dp0"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if errorlevel 1 (echo vcvarsall failed & exit /b 1)
cl /nologo /O2 /W3 sentry_poc.c /Fe:"%~dp0sentry_eye_poc.exe"
if errorlevel 1 (echo cl failed & exit /b 1)
del /q sentry_poc.obj >nul 2>&1
echo Built sentry_eye_poc.exe
