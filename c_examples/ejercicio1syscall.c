/*
 * ejercicio1syscall.c
 *
 * Ejemplo educativo: extraer el syscall ID de `NtCreateFile` desde ntdll.dll
 * y ejecutar la syscall directamente construyendo un pequeño trampoline en memoria.
 *
 * Nota: este código es pedagógico. Los IDs de syscall cambian entre versiones de
 * Windows. Ejecuta siempre en un entorno controlado/VM.
 */

#include <windows.h>
#include <stdio.h>

// Definiciones mínimas para estructuras NT
typedef LONG NTSTATUS;
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// Macro auxiliar para evaluar NT_SUCCESS (debe estar definida antes del uso)
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Minimal helper to initialize OBJECT_ATTRIBUTES
void InitializeObjectAttributes(POBJECT_ATTRIBUTES p, PUNICODE_STRING name) {
    p->Length = sizeof(OBJECT_ATTRIBUTES);
    p->RootDirectory = NULL;
    p->ObjectName = name;
    p->Attributes = 0;
    p->SecurityDescriptor = NULL;
    p->SecurityQualityOfService = NULL;
}

int main(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        fprintf(stderr, "No se pudo obtener ntdll.dll\n");
        return 1;
    }

    // Obtener la dirección del stub exportado NtCreateFile
    FARPROC pNtCreateFile = GetProcAddress(hNtdll, "NtCreateFile");
    if (!pNtCreateFile) {
        fprintf(stderr, "No se encontro NtCreateFile en ntdll.dll\n");
        return 1;
    }

    // Leer los primeros bytes del stub y buscar la instrucción `mov eax, imm32` (0xB8 imm32)
    unsigned char *s = (unsigned char*)pNtCreateFile;
    DWORD syscallId = 0;
    for (int i = 0; i < 32; ++i) {
        if (s[i] == 0xB8) { // opcode mov eax, imm32
            DWORD *imm = (DWORD*)(s + i + 1);
            syscallId = *imm;
            break;
        }
    }

    if (syscallId == 0) {
        fprintf(stderr, "No se pudo extraer el syscall id de NtCreateFile\n");
        return 1;
    }

    printf("Syscall ID detectado para NtCreateFile: 0x%08x\n", syscallId);

    // Construir un pequeño trampoline en memoria que haga:
    //   mov r10, rcx
    //   mov eax, imm32
    //   syscall
    //   ret
    unsigned char trampoline[] = {
        0x4c, 0x8b, 0xd1,       // mov r10, rcx
        0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, imm32 (rellenar)
        0x0f, 0x05,             // syscall
        0xc3                    // ret
    };

    // Poner el imm32 detectado
    *(DWORD*)(trampoline + 4) = syscallId;

    // Alloc executable memory for trampoline
    void *mem = VirtualAlloc(NULL, sizeof(trampoline), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        fprintf(stderr, "VirtualAlloc fallo: %lu\n", GetLastError());
        return 1;
    }
    memcpy(mem, trampoline, sizeof(trampoline));
    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(trampoline));

    // Typedef para la syscall: el prototipo debe coincidir con NtCreateFile
    typedef NTSTATUS (NTAPI *NtCreateFile_Syscall)(
        PHANDLE,               // FileHandle
        ACCESS_MASK,           // DesiredAccess
        POBJECT_ATTRIBUTES,    // ObjectAttributes
        PIO_STATUS_BLOCK,      // IoStatusBlock
        PLARGE_INTEGER,        // AllocationSize
        ULONG,                 // FileAttributes
        ULONG,                 // ShareAccess
        ULONG,                 // CreateDisposition
        ULONG,                 // CreateOptions
        PVOID,                 // EaBuffer
        ULONG                  // EaLength
    );

    NtCreateFile_Syscall fn = (NtCreateFile_Syscall)mem;

    // Construir la ruta NT (\??\ + ruta completa). Usaremos el directorio TEMP para no requerir elevación.
    WCHAR tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath) == 0) {
        wcscpy_s(tempPath, MAX_PATH, L"C:\\Temp\\");
    }
    // Compose: \??\ + tempPath + ejercicio1_syscall.txt
    WCHAR fullPath[MAX_PATH * 2];
    swprintf(fullPath, _countof(fullPath), L"\\??\\%sEjercicio1_syscall.txt", tempPath);

    // Allocate buffer for the UNICODE_STRING
    UNICODE_STRING ustr;
    SIZE_T lenBytes = wcslen(fullPath) * sizeof(WCHAR);
    ustr.Length = (USHORT)lenBytes;
    ustr.MaximumLength = (USHORT)(lenBytes + sizeof(WCHAR));
    ustr.Buffer = (PWSTR)fullPath;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &ustr);

    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;

    // Parámetros elegidos (educativo): DesiredAccess = GENERIC_WRITE|GENERIC_READ
    // CreateDisposition = 3 (FILE_OPEN_IF) para crear el archivo si no existe.
    ACCESS_MASK desired = GENERIC_READ | GENERIC_WRITE;
    ULONG fileAttributes = FILE_ATTRIBUTE_NORMAL;
    ULONG share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    ULONG createDisposition = 3; // FILE_OPEN_IF (nota: valores estándar: 1=open,2=create,3=open_if,5=overwrite_if)
    ULONG createOptions = 0x40; // FILE_NON_DIRECTORY_FILE

    printf("Intentando invocar syscall directamente...\n");

    NTSTATUS status = fn(&hFile, desired, &objAttr, &iosb, NULL, fileAttributes, share, createDisposition, createOptions, NULL, 0);

    printf("NTSTATUS de la syscall: 0x%08x\n", (unsigned)status);
    if (NT_SUCCESS(status)) {
        printf("Syscall reporto exito. Handle: %p\n", hFile);
        // Si el handle es válido, cerrarlo con CloseHandle para integridad con Win32
        CloseHandle(hFile);
    } else {
        printf("Syscall fallo. No se obtuvo handle. IoStatus.Information=0x%p\n", (PVOID)iosb.Information);
    }

    // Liberar el trampoline
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

// Macro auxiliar para evaluar NT_SUCCESS
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
