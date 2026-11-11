@echo off
setlocal
set STAGE=4
if not "%~1"=="" set STAGE=%~1

rem Locate the MSVC environment instead of assuming one install path: CI runners
rem carry the Enterprise toolset, this machine carries BuildTools, and both are
rem found by vswhere which ships with every VS 2022 install.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VCVARS="
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
    )
)
if not defined VCVARS if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS (
    echo build: no MSVC x64 toolset found. Install VS 2022 with "Desktop development with C++".
    exit /b 1
)

call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
if not exist "%~dp0build" mkdir "%~dp0build"

cl /nologo /LD /O2 /GS- /GR- /EHs-c- /EHa- /DYNAMICBASE /DZENDO_STAGE=%STAGE% ^
   /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0A00 ^
   /Fo:"%~dp0build\\" /Fe:"%~dp0build\zendo.dll" "%~dp0src\dllmain.cpp" ^
   /link /FIXED:NO /NODEFAULTLIB /ENTRY:DllMain /SUBSYSTEM:WINDOWS /MACHINE:X64 /INCREMENTAL:NO
if errorlevel 1 exit /b 1
echo BUILT %~dp0build\zendo.dll
