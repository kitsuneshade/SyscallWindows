/*
 ejercicio5_createprocess.c
 Programa básico: Crear un proceso usando CreateProcess (llama a NtCreateProcessEx/NtCreateUserProcess).
 Compila con: cl ejercicio5_createprocess.c
 Ejecuta: .\ejercicio5_createprocess.exe
 Analiza con depuradores para ver NtCreateUserProcess.
*/

#include <windows.h>
#include <stdio.h>

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessA("notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Proceso creado: PID %d\n", pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("Error creando proceso: %d\n", GetLastError());
    }
    return 0;
}