/*
 ejercicio3_writefile.c
 Programa básico: Escribir en un archivo usando WriteFile (llama a NtWriteFile).
 Compila con: gcc -o ejercicio3.exe ejercicio3_writefile.c
 Ejecuta: .\ejercicio3.exe
 Analiza para ver NtWriteFile.
*/

#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hFile = CreateFileA("output.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error creando archivo: %d\n", GetLastError());
        return 1;
    }

    const char* text = "Hola, este es un ejemplo de escritura.\n";
    DWORD bytesWritten;
    if (WriteFile(hFile, text, strlen(text), &bytesWritten, NULL)) {
        printf("Escrito %d bytes.\n", bytesWritten);
    } else {
        printf("Error escribiendo: %d\n", GetLastError());
    }

    CloseHandle(hFile);
    return 0;
}