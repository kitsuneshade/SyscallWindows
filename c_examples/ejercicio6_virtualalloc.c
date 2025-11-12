/*
 ejercicio6_virtualalloc.c
 Programa básico: Asignar memoria usando VirtualAlloc (llama a NtAllocateVirtualMemory).
 Compila con: cl ejercicio6_virtualalloc.c
 Ejecuta: .\ejercicio6_virtualalloc.exe
 Analiza con depuradores para ver NtAllocateVirtualMemory.
*/

#include <windows.h>
#include <stdio.h>

int main() {
    LPVOID addr = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (addr) {
        printf("Memoria asignada en: %p\n", addr);
        strcpy((char*)addr, "Hola memoria!");
        printf("Contenido: %s\n", (char*)addr);
        VirtualFree(addr, 0, MEM_RELEASE);
    } else {
        printf("Error asignando memoria: %d\n", GetLastError());
    }
    return 0;
}