@echo off
setlocal enabledelayedexpansion
title [ XYLERA ] Builder
cls

for /f %%A in ('echo prompt $E^| cmd') do set "ESC=%%A"
set "COL_INFO=%ESC%[38;5;207m"
set "COL_OK=%ESC%[38;5;83m"
set "COL_WARN=%ESC%[38;5;214m"
set "COL_ERR=%ESC%[38;5;203m"
set "COL_MSG=%ESC%[37m"
set "RESET=%ESC%[0m"

echo.
echo %COL_INFO%  __ __ __ __ __    _____ _____ _____%RESET%
echo %COL_INFO% ^|  ^|  ^|  ^|  ^|  ^|  ^|   __^| __  ^|  _  ^|%RESET%
echo %COL_INFO% ^|-   -^|_   _^|  ^|__^|   __^|    -^|     ^|%RESET%
echo %COL_INFO% ^|__^|__^| ^|_^| ^|_____^|_____^|__^|__^|__^|__^|%RESET%
echo.
echo %COL_INFO%[ XYLERA ]%RESET% %COL_MSG%Valex Patcher Builder v2.0.1%RESET%
echo %COL_MSG%Make it clean. Make it glow.%RESET%
echo.

set "OUT_EXE=xylera.exe"
set "RES_RC=resources\resource.rc"
set "RES_OBJ=resources\resource.o"
set "FALLBACK_BIN=resources\winmgngnng64\bin"

echo %COL_INFO%[1/5]%RESET% %COL_MSG%prepare resources%RESET%
if not exist resources mkdir resources >nul 2>nul
if exist "%RES_OBJ%" del /q "%RES_OBJ%" >nul 2>nul

echo %COL_INFO%[2/5]%RESET% %COL_MSG%compile icon/resource%RESET%
windres "%RES_RC%" -O coff -o "%RES_OBJ%"
if errorlevel 1 (
  echo %COL_ERR%error:%RESET% %COL_MSG%windres failed%RESET%
  exit /b 1
)

echo %COL_INFO%[3/5]%RESET% %COL_MSG%compile and link%RESET%
g++ -std=c++17 -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 ^
    -static -static-libgcc -static-libstdc++ ^
    -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va ^
    -s ^
    -Lresources ^
    -o "%OUT_EXE%" patcher.cpp "%RES_OBJ%"
if errorlevel 1 (
  echo %COL_WARN%warn:%RESET% %COL_MSG%system g++ failed, trying fallback toolchain%RESET%
  if exist "%FALLBACK_BIN%\g++.exe" (
    "%FALLBACK_BIN%\g++.exe" -std=c++17 -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 ^
        -static -static-libgcc -static-libstdc++ ^
        -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va ^
        -s ^
        -Lresources ^
        -o "%OUT_EXE%" patcher.cpp "%RES_OBJ%"
    if errorlevel 1 (
      echo %COL_WARN%warn:%RESET% %COL_MSG%fallback g++ failed, trying gcc%RESET%
      if exist "%FALLBACK_BIN%\gcc.exe" (
        "%FALLBACK_BIN%\gcc.exe" -std=c++17 -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 ^
            -static -static-libgcc -static-libstdc++ ^
            -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va ^
            -s ^
            -Lresources ^
            -o "%OUT_EXE%" patcher.cpp "%RES_OBJ%"
        if errorlevel 1 (
          echo %COL_ERR%error:%RESET% %COL_MSG%fallback gcc failed%RESET%
          exit /b 1
        )
      ) else (
        echo %COL_ERR%error:%RESET% %COL_MSG%no fallback compiler found in %FALLBACK_BIN%%RESET%
        exit /b 1
      )
    )
  ) else (
    echo %COL_ERR%error:%RESET% %COL_MSG%fallback path missing: %FALLBACK_BIN%%RESET%
    exit /b 1
  )
)

echo %COL_INFO%[4/5]%RESET% %COL_MSG%verify output%RESET%
if not exist "%OUT_EXE%" (
  echo %COL_ERR%error:%RESET% %COL_MSG%output not found%RESET%
  exit /b 1
)
for %%A in ("%OUT_EXE%") do set "OUT_SIZE=%%~zA"
echo %COL_OK%output:%RESET% %COL_MSG%%OUT_EXE% (%OUT_SIZE% bytes)%RESET%

echo %COL_INFO%[5/5]%RESET% %COL_MSG%done%RESET%
echo %COL_OK%build complete%RESET% %COL_MSG%^> %OUT_EXE%%RESET%
echo.
endlocal