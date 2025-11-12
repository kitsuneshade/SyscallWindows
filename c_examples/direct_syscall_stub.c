/*
 direct_syscall_stub.c
 Ejemplo educativo: localizar el número de syscall leyendo el stub en ntdll
 y construir un pequeño stub en memoria para invocar la syscall directamente.

 ADVERTENCIA: Este ejemplo es educativo. Ejecuta en una VM de laboratorio.
*/

#include <windows.h>
#include <stdio.h>

// Helper: obtiene la dirección de un export de ntdll
FARPROC get_ntdll_export(const char* name) {
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return NULL;
    return GetProcAddress(h, name);
}

int main() {
    FARPROC pNtCreateFile = get_ntdll_export("NtCreateFile");
    if (!pNtCreateFile) {
        printf("No se encontró NtCreateFile en ntdll.dll\n");
        return 1;
    }

    unsigned char *p = (unsigned char*)pNtCreateFile;
    printf("Direccion de NtCreateFile: %p\n", p);

    // Mostrar primeros bytes (iniciales del stub)
    printf("Primeros 16 bytes:\n");
    for (int i = 0; i < 16; i++) printf("%02X ", p[i]);
    printf("\n\n");

    // Ejemplo: buscar instrucción mov eax, imm32 (en stubs típicos x64)
    // 0xB8 = mov eax, imm32 en x86; en x64 los stubs suelen usar mov eax, imm32 (B8)
    // Esto es heurístico: puede variar entre versiones.

    for (int i = 0; i < 16; i++) {
        if (p[i] == 0xB8 && i + 4 < 16) {
            unsigned int sysId = *(unsigned int*)(p + i + 1);
            printf("Posible mov eax, imm32 encontrado en offset %d -> syscall id = 0x%X (%u)\n", i, sysId, sysId);
            break;
        }
    }

    printf("\nLectura educativa completada. No ejecutes stubs directos sin entender riesgos.\n");
    return 0;
}
