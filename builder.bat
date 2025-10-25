@echo off
setlocal

rem Compile the icon resource into an object file
windres resources\resource.rc -O coff -o resources\resource.o

rem Build the executable and link the resource so the icon is embedded
g++ -std=c++17 -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 ^
    -static -static-libgcc -static-libstdc++ ^
    -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va ^
    -s ^
    -Lresources ^
    -o xylera.exe patcher.cpp resources\resource.o

endlocal