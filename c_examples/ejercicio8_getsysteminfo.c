/*
 ejercicio8_getsysteminfo.c
 Programa básico: Obtener información del sistema usando GetSystemInfo (llama a NtQuerySystemInformation).
 Compila con: cl ejercicio8_getsysteminfo.c
 Ejecuta: .\ejercicio8_getsysteminfo.exe
 Analiza con depuradores para ver NtQuerySystemInformation.
*/

#include <windows.h>
#include <stdio.h>

int main() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("Número de procesadores: %u\n", si.dwNumberOfProcessors);
    printf("Tipo de procesador: %u\n", si.dwProcessorType);
    printf("Página mínima: %p\n", si.lpMinimumApplicationAddress);
    printf("Página máxima: %p\n", si.lpMaximumApplicationAddress);
    return 0;
}