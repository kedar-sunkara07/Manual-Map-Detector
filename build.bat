@echo off
REM Build script for ManualMapDetector using w64devkit (portable MinGW)
REM Usage: build.bat
REM
REM Prerequisites: w64devkit must be extracted in the same directory as this script.
REM Download from: https://github.com/skeeto/w64devkit/releases

echo ========================================
echo Building ManualMapDetector.exe
echo ========================================

REM Use the portable w64devkit compiler
set GPP=%~dp0w64devkit\bin\g++.exe

if not exist "%GPP%" (
    echo ERROR: g++.exe not found at %GPP%
    echo Please extract w64devkit into this directory.
    pause
    exit /b 1
)

set SOURCES=src\main.cpp src\ConsoleUI.cpp src\ProcessScanner.cpp src\ModuleScanner.cpp src\MemoryScanner.cpp src\SignatureChecker.cpp src\PeDetector.cpp
set OUTPUT=ManualMapDetector.exe
set LIBS=-lpsapi -lwintrust -lcrypt32
set FLAGS=-std=c++17 -Wall -Wextra -O2 -static -static-libgcc -static-libstdc++ -Wno-cast-function-type

echo Compiling...
"%GPP%" %FLAGS% -o %OUTPUT% %SOURCES% %LIBS%

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful: %OUTPUT%
    echo.
) else (
    echo.
    echo Build FAILED!
    echo.
)

pause
