/*
 ejercicio2_readfile.c
 Programa básico: Leer un archivo usando ReadFile (llama a NtReadFile).
 Asegúrate de que "test_file.txt" exista (creado por ejercicio1).
 Compila con: gcc -o ejercicio2.exe ejercicio2_readfile.c
 Ejecuta: .\ejercicio2.exe
 Analiza con depuradores para ver NtReadFile.
*/

#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hFile = CreateFileA("test_file.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error abriendo archivo: %d\n", GetLastError());
        return 1;
    }

    char buffer[256];
    DWORD bytesRead;
    if (ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        printf("Leído: %s\n", buffer);
    } else {
        printf("Error leyendo: %d\n", GetLastError());
    }

    CloseHandle(hFile);
    return 0;
}