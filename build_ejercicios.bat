@echo off
REM Script para compilar todos los ejercicios con MSVC
REM Ejecuta este script desde la carpeta syscall windows
REM Asegúrate de que MSVC esté instalado y vcvarsall.bat esté en el PATH

echo Configurando entorno MSVC...
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
if %errorlevel% neq 0 (
    echo Error configurando MSVC. Verifica la ruta a vcvarsall.bat
    pause
    exit /b 1
)

echo Compilando ejercicios...

REM Ejercicio 1: CreateFile
cl /Fe:ejercicio1.exe c_examples\ejercicio1_createfile.c
if %errorlevel% neq 0 echo Error compilando ejercicio1

REM Ejercicio 1b: Direct syscall example
cl /Fe:ejercicio1syscall.exe c_examples\ejercicio1syscall.c
if %errorlevel% neq 0 echo Error compilando ejercicio1syscall

REM Ejercicio 2: ReadFile
cl /Fe:ejercicio2.exe c_examples\ejercicio2_readfile.c
if %errorlevel% neq 0 echo Error compilando ejercicio2

REM Ejercicio 3: WriteFile
cl /Fe:ejercicio3.exe c_examples\ejercicio3_writefile.c
if %errorlevel% neq 0 echo Error compilando ejercicio3

REM Ejercicio 4: ListDir
cl /Fe:ejercicio4.exe c_examples\ejercicio4_listdir.c
if %errorlevel% neq 0 echo Error compilando ejercicio4

REM Ejercicio 5: CreateProcess
cl /Fe:ejercicio5.exe c_examples\ejercicio5_createprocess.c
if %errorlevel% neq 0 echo Error compilando ejercicio5

REM Ejercicio 6: VirtualAlloc
cl /Fe:ejercicio6.exe c_examples\ejercicio6_virtualalloc.c
if %errorlevel% neq 0 echo Error compilando ejercicio6

REM Ejercicio 7: SocketConnect (necesita ws2_32.lib)
cl /Fe:ejercicio7.exe c_examples\ejercicio7_socketconnect.c ws2_32.lib
if %errorlevel% neq 0 echo Error compilando ejercicio7

REM Ejercicio 8: GetSystemInfo
cl /Fe:ejercicio8.exe c_examples\ejercicio8_getsysteminfo.c
if %errorlevel% neq 0 echo Error compilando ejercicio8

echo Compilación completada. Ejecutables en la carpeta actual.
pause