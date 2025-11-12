/*
 ejercicio4_listdir.c
 Programa básico: Listar archivos en un directorio usando FindFirstFile/FindNextFile (llama a NtQueryDirectoryFile).
 Compila con: gcc -o ejercicio4.exe ejercicio4_listdir.c
 Ejecuta: .\ejercicio4.exe
 Analiza para ver NtQueryDirectoryFile.
*/

#include <windows.h>
#include <stdio.h>

int main() {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("*.*", &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Error listando directorio: %d\n", GetLastError());
        return 1;
    }

    do {
        printf("Archivo: %s\n", findData.cFileName);
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
    return 0;
}