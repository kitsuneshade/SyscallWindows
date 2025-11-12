/*
 ejercicio1_createfile.c
 Programa básico: Crear un archivo usando CreateFile (que internamente llama a NtCreateFile).
 Compila con: gcc -o ejercicio1.exe ejercicio1_createfile.c
 Ejecuta: .\ejercicio1.exe
 Luego analiza con WinDbg/x64dbg para ver las syscalls.
*/

#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hFile = CreateFileA("test_file.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error creando archivo: %d\n", GetLastError());
        return 1;
    }
    printf("Archivo creado exitosamente.\n");
    CloseHandle(hFile);
    return 0;
}