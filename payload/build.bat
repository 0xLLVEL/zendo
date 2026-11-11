@echo off
setlocal
set STAGE=4
if not "%~1"=="" set STAGE=%~1
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
if not exist "%~dp0build" mkdir "%~dp0build"

cl /nologo /LD /O2 /GS- /GR- /EHs-c- /EHa- /DYNAMICBASE /DZENDO_STAGE=%STAGE% ^
   /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0A00 ^
   /Fo:"%~dp0build\\" /Fe:"%~dp0build\zendo.dll" "%~dp0src\dllmain.cpp" ^
   /link /FIXED:NO /NODEFAULTLIB /ENTRY:DllMain /SUBSYSTEM:WINDOWS /MACHINE:X64 /INCREMENTAL:NO
if errorlevel 1 exit /b 1
echo BUILT %~dp0build\zendo.dll
