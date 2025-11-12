# Taller Práctico: Syscalls en Windows con Ejercicios y Depuradores

## Introducción

Este taller práctico complementa el README principal del proyecto. Aquí se describe de forma práctica cómo aplicar los conceptos de syscalls en Windows. Se muestran pasos para ejecutar programas en C, observar cómo las APIs de alto nivel invocan syscalls, y utilizar depuradores como WinDbg y x64dbg para inspeccionar los stubs en `ntdll.dll`, extraer IDs de syscall y entender el flujo de ejecución. 🧪🔎

**Requisitos previos**:
- Windows con MSVC instalado (usar `build_ejercicios.bat` para compilar los ejercicios).
- WinDbg (parte del Windows SDK) y x64dbg instalados.
- Conocimientos básicos de C y depuración.

**Objetivo**: Al final, el lector entenderá cómo las syscalls conectan user mode con kernel mode, y cómo analizarlas en tiempo real. ⚙️

---

## Parte Teórica Resumida 📚

### ¿Qué es una Syscall?
Una syscall es una llamada al sistema operativo para solicitar servicios del kernel. En Windows:
- Las aplicaciones usan APIs de alto nivel (kernel32.dll, user32.dll).
- Estas APIs llaman a funciones en `ntdll.dll` (stubs que preparan parámetros y ejecutan `syscall`).
- El kernel (`ntoskrnl.exe`) procesa la solicitud y regresa al user mode.

### Flujo Básico
1. Programa → API (ej. `CreateFile`) → `ntdll.dll` (stub) → `syscall` → Kernel → Respuesta.

### Obtener IDs de Syscall
- Los IDs cambian entre versiones de Windows.
- Técnicas: Desensamblar stubs en `ntdll.dll`, usar herramientas como IDA/Ghidra, o scripts.

### User-Land Hooks
- IAT/EAT/Inline hooks pueden interceptar llamadas en `ntdll.dll`.
- Syscalls directas evitan hooks pero requieren cuidado.

### Herramientas
- **WinDbg**: Depurador avanzado de Microsoft, ideal para análisis de kernel y user mode.
- **x64dbg**: Depurador user-friendly para x64, con interfaz gráfica para breakpoints y desensamblado.

---

## Parte Práctica: Ejercicios con Depuradores ⚙️🔎

### Resumen rápido de ejercicios 📋

| # | Ejercicio | Binario | Syscall objetivo | Descripción |
|---:|:----------|:--------|:-----------------:|:------------|
| 1 | Crear archivo | `ejercicio1.exe` | `NtCreateFile` | Crear `test_file.txt` |
| 2 | Leer archivo | `ejercicio2.exe` | `NtReadFile` | Leer `test_file.txt` |
| 3 | Escribir archivo | `ejercicio3.exe` | `NtWriteFile` | Escribir `output.txt` |
| 4 | Listar directorio | `ejercicio4.exe` | `NtQueryDirectoryFile` | Iterar nombres de archivo |
| 5 | Crear proceso | `ejercicio5.exe` | `NtCreateUserProcess` | Crear Notepad |
| 6 | Asignar memoria | `ejercicio6.exe` | `NtAllocateVirtualMemory` | Reservar memoria virtual |
| 7 | Conectar socket | `ejercicio7.exe` | varios | Operaciones de red/IO |
| 8 | Info sistema | `ejercicio8.exe` | `NtQuerySystemInformation` | Consultar info del sistema |


Cada ejercicio incluye:
- **Descripción**: Qué hace el programa y qué syscall se invoca.
- **Ejecución**: Cómo correrlo y qué esperar.
- **Análisis con x64dbg**: Pasos detallados paso a paso, explicando qué observar y por qué.
- **Análisis con WinDbg**: Comandos y explicaciones equivalentes.
- **Qué aprender**: Resumen de lo observado.
- **Syscall**: La específica involucrada.

Ejecutar los programas en un entorno controlado (VM recomendada). Seguir los pasos en orden para entender el flujo completo. ⚠️

### Ejercicio 1: Crear Archivo (`ejercicio1.exe`)

Descripción: Este programa usa `CreateFile` para crear un archivo llamado `test_file.txt`. Internamente `CreateFile` llama a `NtCreateFile` en `ntdll.dll`, y ese stub ejecuta la instrucción `syscall` con un immediato en `EAX/RAX` que indica al kernel qué servicio ejecutar.
# Taller Práctico: Syscalls en Windows con Ejercicios y Depuradores

## Introducción

Esta guía práctica acompaña al README y está pensada para ser seguida paso a paso en la máquina/VM. Contiene instrucciones detalladas para ejecutar los ejercicios, colocar breakpoints en x64dbg y WinDbg, y registrar la información relevante (syscall IDs, registros, parámetros y resultados). 📘

Requisitos rápidos:
- MSVC/Developer Command Prompt para compilar (ya lo hicimos con `build_ejercicios.bat`).
- x64dbg instalado (GUI).
- WinDbg instalado (WinDbg Preview o clásico).

Precaución: realiza estas pruebas en una VM o entorno de laboratorio.

---

## Resumen rápido de cómo localizar un stub en `ntdll`
- En x64dbg: Modules -> selecciona `ntdll.dll` -> Exports -> busca `Nt*` o el nombre deseado -> doble‑clic para ir al desensamblado -> inserta breakpoint con F2.
- En WinDbg: usa `bp ntdll!NombreFuncion` (si el export existe), o localiza la dirección con `x ntdll!*Nombre*` y usa `bp <addr>`.

Consejos de terminología:
- `mov eax, imm32` (inmediato) dentro del stub suele ser el syscall ID en x64.
- `syscall` es la instrucción que transfiere control al kernel.

---

## Ejercicios (detallados, paso a paso)

Cada ejercicio sigue esta estructura:
- Descripción breve.
- Cómo ejecutar el binario.
- Pasos detallados para poner breakpoints en x64dbg.
- Comandos concretos para WinDbg.
- Qué observar y qué reportar.

### 🧪 Ejercicio 1 — Crear archivo (`ejercicio1.exe`)
Descripción: usa `CreateFile` → `NtCreateFile` → syscall. Crea `test_file.txt`.

Ejecución:
```powershell
.\ejercicio1.exe
```

x64dbg — pasos para breakpoint y observación:
1. Abre x64dbg (ejecuta como admin si lo deseas).
2. File -> Open -> selecciona `ejercicio1.exe`.
3. Presiona F9 para ejecutar hasta `main`.
4. Modules -> busca `ntdll.dll` -> doble‑clic -> Exports.
5. Localiza `NtCreateFile` y doble‑clic para saltar al stub.
6. En la vista CPU coloca un breakpoint sobre la instrucción `mov eax, imm32` o sobre la primera instrucción del stub (sitúa el cursor y presiona F2, o clic en la columna de addresses).
7. Ejecuta (F9) hasta que se active el breakpoint.
8. Observa:
   - Registers: `RAX/EAX` (valor cargado en el stub), `RCX/RDX/R8/R9` (parámetros según convención x64).
   - Stack: parámetros adicionales.
   - Hex/Bytes: copiar los primeros 8–16 bytes del stub para documentarlos.
9. Desensambla alrededor para confirmar `mov r10, rcx` seguido de `mov eax, imm32` y `syscall`.
10. Continúa (F9) y revisa `RAX` tras la syscall para el NTSTATUS de retorno.

WinDbg — comandos prácticos:
1. Abre terminal y lanza:
```powershell
windbg -o -g .\ejercicio1.exe
```
2. En la consola:
```
bp ntdll!NtCreateFile
g
```
3. Cuando pare, ejecuta:
```
r
u ntdll!NtCreateFile
dq rsp L10
```
4. Observa la línea `mov eax, 0xNNNN` y el valor de `rax` tras la syscall.

Qué reportar: texto de salida del exe, la línea del desensamblado con `mov eax, 0xNNNN`, valor de `EAX/RAX` en el breakpoint y valor de `RAX` tras la syscall.

---

### Ejercicio 2 — Leer archivo (`ejercicio2.exe`)
Descripción: `ReadFile` → `NtReadFile` → syscall; lee `test_file.txt` en un buffer.

Ejecución:
```powershell
.\ejercicio2.exe
```

x64dbg:
1. Open -> `ejercicio2.exe` -> F9 hasta `main`.
2. Modules -> `ntdll.dll` -> Exports -> `NtReadFile` -> doble‑clic.
3. Inserta breakpoint en la instrucción `mov eax, imm32` (F2).
4. Ejecuta; al parar inspecciona `RAX`/`EAX`, `RCX` (handle), `RDX` (buffer) y la pila.
5. Tras continuar, usa la vista de memoria para inspeccionar el buffer y verificar los bytes leídos.

WinDbg:
```
windbg -o -g .\ejercicio2.exe
bp ntdll!NtReadFile
g
r
dq rsp L10
u ntdll!NtReadFile
```

Qué reportar: `mov eax, 0xNNNN`, registros con handle y buffer, y contenido del buffer tras la syscall.

---

### Ejercicio 3 — Escribir archivo (`ejercicio3.exe`)
Descripción: `WriteFile` → `NtWriteFile` → syscall; escribe un buffer a `output.txt`.

Ejecución:
```powershell
.\ejercicio3.exe
```

x64dbg:
1. Open `ejercicio3.exe`, F9 hasta `main`.
2. Modules -> `ntdll.dll` -> Exports -> `NtWriteFile` -> doble‑clic.
3. Inserta breakpoint en `mov eax, imm32` (F2).
4. Al parar observa `RAX` (ID/resultado), `RCX`/`RDX` con punteros y la pila con la longitud.
5. Continúa y confirma `output.txt`.

WinDbg:
```
windbg -o -g .\ejercicio3.exe
bp ntdll!NtWriteFile
g
r
dq rsp L10
u ntdll!NtWriteFile
```

Qué reportar: syscall id, registros/stack relevantes y el contenido de `output.txt`.

---

### Ejercicio 4 — Listar directorio (`ejercicio4.exe`)
Descripción: `FindFirstFile`/`FindNextFile` → `NtQueryDirectoryFile` → syscall; itera nombres de archivos.

Ejecución:
```powershell
.\ejercicio4.exe
```

x64dbg:
1. Open `ejercicio4.exe`, F9 hasta `main`.
2. Modules -> ntdll.dll -> Exports -> `NtQueryDirectoryFile` -> doble‑clic.
3. Breakpoint en la instrucción del stub (F2).
4. Observa `RAX` (ID), el handle del directorio y el buffer donde se almacenan nombres.
5. Observa si la aplicación realiza múltiples llamadas al stub (iteración). Usa Step Into (F7) para seguir cada syscall.

WinDbg:
```
windbg -o -g .\ejercicio4.exe
bp ntdll!NtQueryDirectoryFile
g
r
dq rsp L10
u ntdll!NtQueryDirectoryFile
```

Qué reportar: syscall id, dirección del buffer y patrón de llamadas cuando hay iteración.

---

### Ejercicio 5 — Crear proceso (`ejercicio5.exe`)
Descripción: `CreateProcess` → `NtCreateUserProcess`/`NtCreateProcessEx` → syscall; crea Notepad.

Ejecución:
```powershell
.\ejercicio5.exe
```

x64dbg:
1. Open `ejercicio5.exe`, F9 hasta `main`.
2. Modules -> ntdll.dll -> Export (busca `NtCreateUserProcess` o variantes) -> doble‑clic.
3. Inserta breakpoint en el stub.
4. Observa registros que contienen punteros a Unicode strings con la ruta/comando y flags de creación.
5. Continúa y verifica que Notepad fue creado; anota PID si lo deseas.

WinDbg:
```
windbg -o -g .\ejercicio5.exe
bp ntdll!NtCreateUserProcess
g
r
dq rsp L20
u ntdll!NtCreateUserProcess
```

Qué reportar: syscall id, punteros a la cadena de comando y el PID creado.

---

### Ejercicio 6 — Asignar memoria (`ejercicio6.exe`)
Descripción: `VirtualAlloc` → `NtAllocateVirtualMemory` → syscall; asigna memoria virtual.

Ejecución:
```powershell
.\ejercicio6.exe
```

x64dbg:
1. Open `ejercicio6.exe`, F9 hasta `main`.
2. Modules -> ntdll.dll -> Exports -> `NtAllocateVirtualMemory` -> doble‑clic.
3. Breakpoint en la instrucción del stub.
4. Observa: `RCX` (base address o NULL), `RDX` (puntero a size), `R8` flags/protections.
5. Continúa y revisa la dirección devuelta en `RAX`.

WinDbg:
```
windbg -o -g .\ejercicio6.exe
bp ntdll!NtAllocateVirtualMemory
g
r
dq rsp L10
u ntdll!NtAllocateVirtualMemory
```

Qué reportar: parámetros (address/size/protection) y la dirección asignada.

---

### Ejercicio 7 — Conectar socket (`ejercicio7.exe`)
Descripción: llamadas de Winsock que terminan en syscalls para I/O (a menudo `NtDeviceIoControlFile` o similares).

Ejecución:
```powershell
.\ejercicio7.exe
```

x64dbg:
1. Open `ejercicio7.exe`, F9 hasta `main`.
2. Si `NtDeviceIoControlFile` aparece en Exports, ve al stub; si no, sigue el flujo de imports desde `ws2_32.dll` hasta `ntdll`.
3. Inserta breakpoint en el stub.
4. Observa: handle de socket en `RCX`, punteros a `sockaddr` y códigos IOCTL en la pila.

WinDbg:
```
windbg -o -g .\ejercicio7.exe
x ntdll!*DeviceIoControl*
bp ntdll!NtDeviceIoControlFile
g
r
dq rsp L10
```

Qué reportar: syscall(s) observadas para la operación de socket, parámetros relevantes y errores (WSAGetLastError si falla).

---

### Ejercicio 8 — Información del sistema (`ejercicio8.exe`)
Descripción: `GetSystemInfo` → `NtQuerySystemInformation` → syscall; consulta información del kernel.

Ejecución:
```powershell
.\ejercicio8.exe
```

x64dbg:
1. Open `ejercicio8.exe`, F9 hasta `main`.
2. Modules -> `ntdll.dll` -> Exports -> `NtQuerySystemInformation` -> doble‑clic.
3. Inserta breakpoint en el stub.
4. Observa: `RCX` (information class), `RDX` (buffer), `R8` (length).
5. Continúa y examina el buffer con la vista de memoria.

WinDbg:
```
windbg -o -g .\ejercicio8.exe
bp ntdll!NtQuerySystemInformation
g
r
dq rsp L10
u ntdll!NtQuerySystemInformation
```

Qué reportar: information class consultada, buffer y contenido relevante (ej. número de CPUs).

---

## Consejos y soluciones rápidas
- Si no encuentras una export en `ntdll` por nombre, en x64dbg usa la vista Exports y busca por patrones (`CreateFile`, `ReadFile`, etc.). En WinDbg usa `x ntdll!*CreateFile*`.
- Para sets de breakpoints condicionales en WinDbg: `bp /p <addr>` o `bp <addr> "j (condition) 'gc' ; 'g'"` (avanzado).
- Si ves bytes distintos en el stub (por ejemplo parcheos o hooks), copia los bytes y compáralos con una `ntdll.dll` limpia de otra instalación.

---

## ¿Qué debes enviar aquí cuando completes cada ejercicio?
- Salida del ejecutable (texto que imprime).
- Línea exacta del desensamblado que contiene `mov eax, 0xNNNN` o captura/hex de los primeros bytes del stub.
- Valor de `EAX/RAX` cuando se activa el breakpoint.
- Valor de `RAX` tras la syscall (NTSTATUS) y cualquier dato relevante (buffer contents, PID, dirección asignada, etc.).

Con los datos recogidos se puede proceder al siguiente paso: extraer automáticamente IDs, construir un stub en memoria con MSVC/ASM, o investigar hooks detectados.

Iniciar con el Ejercicio 1. Seguir los pasos y registrar las observaciones en este documento.

---

### Registro de sesión: Ejercicio 1 (WinDbg) — salida y análisis detallado

A continuación se incluye la salida pegada desde WinDbg junto con una explicación línea por línea de lo que está sucediendo y de la información útil que se obtuvo. Esta sección es adecuada para dejarla en el repositorio (README/Taller) como prueba reproducible de la sesión de depuración.

#### Salida capturada (raw)

```
CommandLine: .\ejercicio1.exe  # (ejecutado desde la carpeta `syscall windows` del repositorio)
Error: Change all symbol paths attempts to access '<SYMBOLS_DIR>' failed: 0x3 - El sistema no puede encontrar la ruta especificado. Reemplazar `<SYMBOLS_DIR>` por la carpeta local de símbolos o usar los comandos `.symfix`/`.sympath` en WinDbg.

************* Path validation summary **************
Response                         Time (ms)     Location
Deferred                                       srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
Error                                          <SYMBOLS_DIR>
OK                                             <REPO_BUILD_DIR>\x64\Release
Symbol search path is: srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;<SYMBOLS_DIR>;<REPO_BUILD_DIR>\x64\Release
Executable search path is: 
ModLoad: 00007ff6`5d110000 00007ff6`5d137000   image00007ff6`5d110000
ModLoad: 00007ffa`cea70000 00007ffa`cec68000   ntdll.dll
ModLoad: 00007ffa`cd910000 00007ffa`cd9d2000   C:\WINDOWS\System32\KERNEL32.DLL
ModLoad: 00007ffa`cc200000 00007ffa`cc4f6000   C:\WINDOWS\System32\KERNELBASE.dll
...(mensajes de ModLoad omitidos)...

(377c.bb0): Break instruction exception - code 80000003 (first chance)
ntdll!LdrpDoDebuggerBreak+0x30:
00007ffa`ceb40860 cc              int     3
1:001> bp ntdll!NtCreateFile
1:001> g
Breakpoint 0 hit
ntdll!NtCreateFile:
00007ffa`ceb0e030 4c8bd1          mov     r10,rcx
1:004> r
rax=0000000000000001 rbx=0000000000000000 rcx=000000b984d7d820
rdx=0000000080100080 rsi=0000000000000000 rdi=0000000000000000
rip=00007ffaceb0e030 rsp=000000b984d7d798 rbp=000000b984d7d8a0
 r8=000000b984d7d880  r9=000000b984d7d828 r10=00000fff59850586
r11=4155444415115554 r12=0000000000000001 r13=0000000080100080
r14=0000000000000080 r15=0000000000000000
ntdll!NtCreateFile:
00007ffa`ceb0e030 4c8bd1          mov     r10,rcx
1:004> u ntdll!NtCreateFile
ntdll!NtCreateFile:
00007ffa`ceb0e030 4c8bd1          mov     r10,rcx
00007ffa`ceb0e033 b855000000      mov     eax,55h
00007ffa`ceb0e038 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ffa`ceb0e040 7503            jne     ntdll!NtCreateFile+0x15 (00007ffa`ceb0e045)
00007ffa`ceb0e042 0f05            syscall
00007ffa`ceb0e044 c3              ret
00007ffa`ceb0e045 cd2e            int     2Eh
00007ffa`ceb0e047 c3              ret
1:004> p
ntdll!NtCreateFile+0x3:
00007ffa`ceb0e033 b855000000      mov     eax,55h
1:004> dq rsp L10
000000b9`84d7d798  00007ffa`cc22ea39 00000000`00000001
000000b9`84d7d7a8  000000b9`84d7d9f0 00007ffa`cd910000
000000b9`84d7d7b8  00000000`00000000 00000000`00000000
000000b9`84d7d7c8  00000000`00000080 00000000`00000001
000000b9`84d7d7d8  00000000`00000001 00000225`00020060
000000b9`84d7d7e8  00000000`00000000 00000000`00000000
000000b9`84d7d7f8  00000000`00000000 00000000`00020060
000000b9`84d7d808  00000000`00000080 00000000`00000001
1:004> db 000000b984d7d880 L40
000000b9`84d7d880  30 00 00 00 25 02 00 00-00 00 00 00 00 00 00 00  0...%...........
000000b9`84d7d890  48 d8 d7 84 b9 00 00 00-40 00 00 00 fa 7f 00 00  H.......@.......
000000b9`84d7d8a0  00 00 00 00 00 00 00 00-b0 d8 d7 84 b9 00 00 00  ................
000000b9`84d7d8b0  0c 00 00 00 02 00 00 00-01 01 00 00 00 00 00 00  ................
```

#### Explicación y análisis (línea a línea)

1) Mensaje de símbolos
- El error sobre `<SYMBOLS_DIR>` (antes `C:\path\to\your\symbols`) indica una entrada inválida en el `sympath`. No impide depurar, pero si se necesitan símbolos para código propio corregir o limpiar la ruta con `.symfix` o `.sympath` en WinDbg. Reemplazar `<SYMBOLS_DIR>` por la ruta correcta en la máquina local.

2) ModLoad
- WinDbg lista las DLL mapeadas (ntdll, kernel32, kernelbase, etc.). Confirma que el proceso está en user mode y que `ntdll.dll` está cargado en memoria.

3) Break instruction exception
- `int 3` es normal al arrancar bajo depurador (first-chance breakpoint). Es WinDbg indicando que el proceso está suspendido para debug.

4) Breakpoint en `ntdll!NtCreateFile`
- El breakpoint saltó en el stub de `ntdll`, lo que nos permite inspeccionar justo antes de ejecutar `syscall`.

5) Registros observados (`r`)
- RCX = `0x000000b984d7d820`: primer parámetro — probablemente `PHANDLE FileHandle` (puntero donde se escribirá el handle resultante).
- RDX = `0x0000000080100080`: segundo parámetro — `DesiredAccess`/flags.
- R8  = `0x000000b984d7d880`: tercer parámetro — puntero a `OBJECT_ATTRIBUTES` (contiene la ruta/UNICODE_STRING del nombre del archivo).
- R9  = `0x000000b984d7d828`: cuarto parámetro — puntero a `IO_STATUS_BLOCK`.
- R10 = contiene un valor derivado (mov r10,rcx) — preparación para `syscall`.
- RAX = `1` en ese momento (no es aún el resultado de la syscall).

6) Desensamblado del stub (`u ntdll!NtCreateFile`)
- `mov r10,rcx`: preparar `r10` según convención necesaria para `syscall`.
- `mov eax,55h`: carga el syscall ID (0x55) que el kernel usará para 'NtCreateFile' en esta versión de Windows.
- `test [SharedUserData+0x308],1` / `jne ... int 2Eh`: chequeo de bandera en `KUSER_SHARED_DATA` que el stub usa como verificación (fallback a `int 2Eh` si es necesario).
- `syscall`: llamada al kernel.

7) `p` (step over) y `dq rsp L10`
- `dq rsp L10` muestra los QWORDs en la pila (parámetros adicionales a la función). En la convención x64, parámetros 5..n se pasan por pila; estos QWORDs contienen valores como `CreateOptions`, `CreateDisposition`, punteros adicionales, etc. El primer QWORD en `rsp` suele ser la dirección de retorno.

8) `db 000000b984d7d880 L40` — contenido apuntado por `R8`
- Los bytes comienzan con `30 00 00 00` (0x30 = 48), lo que sugiere un campo Length/Size en una estructura (`UNICODE_STRING` o tamaño de `OBJECT_ATTRIBUTES`).
- En offset +8 aparece un puntero (por ejemplo `48 d8 d7 84 b9 00 00 00`) que probablemente apunta a la cadena UNICODE con el nombre del archivo.

9) Conclusiones concretas
-- Syscall ID detectado para `NtCreateFile` = 0x55 (85 decimal).
- Los parámetros importantes están en los registros RCX, RDX, R8, R9 según convención x64 y la firma de `NtCreateFile`.
- El patrón del stub (`mov r10,rcx; mov eax,0x55; test ...; syscall`) es el comportamiento esperado y no muestra evidencia directa de inline hooking en `ntdll`.

10) Siguientes pasos recomendados
Para ver el NTSTATUS de la llamada, ejecutar `p` (o `t`/`p`) para step‑over la `syscall` y luego `r` para leer `RAX` (NTSTATUS); registrar ese valor en la documentación.

Opcional: añadir un script PowerShell que capture los primeros 16 bytes del stub en memoria y los convierta a hex para comparar con una copia limpia de `ntdll.dll`.

Opcional: transformar esta sección en un bloque collapsible (`<details>`/`<summary>`) para su presentación en GitHub y añadir un badge/emoji. Editar el archivo para aplicar la transformación si se desea.

---

#### Resultado final de la sesión (ejecución del `syscall`)

- Comando ejecutado en WinDbg: varias instrucciones `p` hasta ejecutar la instrucción `syscall` y volver a user mode.
- Valor final en `RAX` tras ejecutar `syscall`: `0x00000000`.

Interpretación: `RAX = 0x0` indica NTSTATUS == STATUS_SUCCESS — la llamada a `NtCreateFile` se completó correctamente y, salvo errores posteriores en la aplicación, el archivo fue creado.

Comprobaciones sugeridas (PowerShell) — copiar y ejecutar en la carpeta `syscall windows`:
```powershell
# Verificar existencia del archivo de prueba
Test-Path .\test_file.txt

# Mostrar contenido si existe
if (Test-Path .\test_file.txt) { Get-Content .\test_file.txt -Raw }
```

Si `Test-Path` devuelve `True` y el contenido es el esperado, la prueba completa es un PASS. Si `Test-Path` devuelve `False`, revisa permisos o el directorio de trabajo.

---

La sesión puede convertirse en un bloque `<details>` plegable con un título estilo GitHub (por ejemplo: "🧪 Ejercicio 1 — Sesión WinDbg (ntdll!NtCreateFile) — 2025-11-11") y un badge `status: PASS` o `FAIL` según el NTSTATUS. Editar el bloque si se desea otro título.

---

### Evidencia extraída en viva voz (ruta solicitada por `NtCreateFile`)

Durante la sesión volcaste la memoria del buffer apuntado por el `UNICODE_STRING`. Aquí están los dumps que ejecutaste y el resultado decodificado:

- Comando ejecutado:
```
db 00000225`5e2ab080 L68
```
- Salida (hex bytes):
```
5c 00 3f 00 3f 00 5c 00 43 00 3a 00 5c 00 57 00
49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 47 00
6c 00 6f 00 62 00 61 00 6c 00 69 00 7a 00 61 00
74 00 69 00 6f 00 6e 00 5c 00 53 00 6f 00 72 00
74 00 69 00 6e 00 67 00 5c 00 73 00 6f 00 72 00
74 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00
2e 00 6e 00 6c 00 73 00
```

- Comando ejecutado (QWORD view):
```
dq 00000225`5e2ab080 L10
```
- Comando `du` (UTF‑16 decode):
```
du 00000225`5e2ab080 L20
```
- Resultado legible mostrado por WinDbg:
```
"\??\C:\WINDOWS\Globalization\Sorting\sortdefault.nls"
```

Interpretación
- La cadena es un `UNICODE_STRING` válido; su contenido (tras decodificar UTF‑16 LE) es:

```
\??\C:\WINDOWS\Globalization\Sorting\sortdefault.nls
```

- En rutas internas de Windows `\??\C:\...` es equivalente a `C:\...` desde user mode. Así que el archivo que el proceso intentó crear/abrir es:

```
C:\WINDOWS\Globalization\Sorting\sortdefault.nls
```

Estado de la operación (NTSTATUS)
- Durante la sesión el `RAX` tras ejecutar `syscall` fue `0x00000000` → NTSTATUS = STATUS_SUCCESS.
- Conclusión: la llamada a `NtCreateFile` se completó con éxito y (salvo interferencias posteriores) el archivo especificado fue creado/abierto correctamente.

Verificación en PowerShell (en la carpeta del taller)
```powershell
# Comprobar de forma portable usando $env:windir
$f = Join-Path $env:windir 'Globalization\Sorting\sortdefault.nls'
Test-Path $f
if (Test-Path $f) { Get-Item $f | Format-List * }
```

Nota de seguridad y permisos
- Ten en cuenta que crear o modificar archivos en `C:\WINDOWS\...` puede necesitar permisos elevados; si el proceso creado por el ejercicio se ejecutó con privilegios bajos, el comportamiento puede variar.

Cómo lo documentaré en el repositorio
- Opcional: añadir un bloque plegable `<details>` en `taller_practico.md` con la salida raw, el análisis y la línea "Archivo intentado: C:\WINDOWS\Globalization\Sorting\sortdefault.nls" y un badge `✅ PASS` si `RAX == 0x0`.

La sesión puede formatearse como un bloque `<details>` con el título sugerido: "🧪 Ejercicio 1 — Sesión WinDbg (ntdll!NtCreateFile) — 2025-11-11 — ✅ PASS". Para modificar el título o el estado, editar el bloque correspondiente en este documento.

---

### Cómo extraer la ruta/nombre del archivo desde la pila (instrucciones concretas)

Se registró un volcado adicional de la pila (`dq`) que contiene una estructura tipo `UNICODE_STRING` (o similar). Para recuperar el nombre del archivo que el proceso solicitó crear, seguir estos pasos en WinDbg (si la sesión sigue activa):

1) Identificar la dirección del buffer en el `dq` — en la salida aparece `00000225`5e2ab080` como puntero al buffer (parte baja del QWORD en `000000b9`84d7d848`).

2) Ejecuta este comando para mostrar la cadena Unicode de forma legible:

```
du 00000225`5e2ab080
```

3) Si `du` no muestra nada legible o se desea ver bytes crudos, usar:

```
db 00000225`5e2ab080 L68
```

Explicación rápida de por qué usar esas direcciones:
- En `000000b9`84d7d848` vimos `00000000`006a0068` seguido de `00000225`5e2ab080`.
- `00000000`006a0068` se interpreta como `Length=0x0068` (104 bytes) y `MaximumLength=0x006a` (106 bytes) — formato habitual de `UNICODE_STRING` (Length, MaximumLength) en little‑endian.
- El puntero `00000225`5e2ab080` es el `Buffer` del `UNICODE_STRING` y por eso ahí está la cadena.

Al pegar la salida de `du`, se procederá a lo siguiente:
-- Extraer la ruta completa en texto legible y añadirla al bloque de evidencia del Ejercicio 1 en `taller_practico.md`.
-- Añadir una línea que diga: "Archivo intentado: <ruta>" y marcar la prueba como `PASS` si `RAX == 0x0`.

Pegar la salida de `du 00000225`5e2ab080` o, alternativamente, usar un pequeño comando PowerShell para validar automáticamente el `Test-Path` con la ruta extraída.

---

## Ejercicio 1 (extra) — Programa directo usando la syscall detectada: `ejercicio1syscall`

Se añadió un ejemplo complementario en `c_examples/ejercicio1syscall.c` que automatiza el procedimiento realizado manualmente:

- Extrae dinámicamente el syscall ID de `NtCreateFile` leyendo el export stub en `ntdll.dll`.
- Construye un pequeño trampoline en memoria con las instrucciones exactas que vimos en el stub:
   - `mov r10, rcx`  (prepara r10 según convención syscall)
   - `mov eax, <syscallId>` (carga el ID dinámico)
   - `syscall`
   - `ret`
- Llama al trampoline con estructuras `UNICODE_STRING` / `OBJECT_ATTRIBUTES` y un `IO_STATUS_BLOCK` para intentar abrir/crear un archivo en el directorio TEMP.

Por qué este programa es útil
- Reproduce de forma programática la técnica que usamos manualmente en WinDbg.
- Muestra cómo el stub en `ntdll` es simplemente un pequeño proxy/protector que carga el ID y ejecuta `syscall` — replicando exactamente su comportamiento
   permite invocar el servicio del kernel sin pasar por el código estático del stub.

Limitaciones y riesgos
- Funciona solo en la misma arquitectura y versión donde obtuviste el ID; los IDs cambian entre versiones de Windows.
- Ejecutar syscalls directos es frágil y puede romper compatibilidad con mitigaciones (CET, PatchGuard, etc.) o disparar AV/EDR.

Compilación y ejecución
- Ya actualicé `build_ejercicios.bat` para compilar `ejercicio1syscall.c` como `ejercicio1syscall.exe`.
- Para compilar:

```powershell
cd ".\syscall windows"  # usar ruta relativa desde la raíz del repositorio
.\build_ejercicios.bat
```

- Para ejecutar y ver el resultado (imprime syscall id y NTSTATUS):

```powershell
.\ejercicio1syscall.exe
```

Notas finales
- El código fuente está en `c_examples/ejercicio1syscall.c` y contiene comentarios que explican cada bloque (detección de ID, construcción del trampoline, preparación de `UNICODE_STRING` y `OBJECT_ATTRIBUTES`, y la invocación de la syscall).
Opcionalmente, además se puede:
   - Transformar el bloque de sesión original en un `<details>` plegable con título y badge `PASS`.
   - Añadir un script que compare bytes en memoria del stub vs `$env:windir\System32\ntdll.dll` en disco para detectar hooks.

Para elegir los pasos siguientes, editar este documento o aplicar el script deseado según las instrucciones anteriores.

---

### Registro de ejecución: `ejercicio1syscall.exe` (ejemplo real)

El ejemplo directo que construye el trampoline y llama la syscall detectada fue compilado y ejecutado; a continuación se muestra la salida real proporcionada por el usuario y su interpretación, para incorporarla al taller como evidencia reproducible.

Salida del programa:

```
Syscall ID detectado para NtCreateFile: 0x00000055
Intentando invocar syscall directamente...
NTSTATUS de la syscall: 0x00000000
Syscall reporto exito. Handle: 00000000000000B8
```

Interpretación y acciones verificables
- `Syscall ID detectado para NtCreateFile: 0x00000055` — confirma que el stub en `ntdll.dll` contiene `mov eax,0x55`, tal como vimos en WinDbg.
- `NTSTATUS de la syscall: 0x00000000` — 0x0 == STATUS_SUCCESS: la llamada al kernel finalizó correctamente.
- `Syscall reporto exito. Handle: 0xB8` — el kernel devolvió un handle válido (en este caso 0xB8). El programa cierra el handle con `CloseHandle` tras verificar.

Verificación en disco (comprobar que el archivo fue creado en el directorio TEMP)

Ejecuta esto en PowerShell para verificar el archivo que creó `ejercicio1syscall.exe` (el programa generó la ruta `%TEMP%\Ejercicio1_syscall.txt`):

```powershell
$f = Join-Path $env:TEMP 'Ejercicio1_syscall.txt'
Test-Path $f
if (Test-Path $f) { Get-Item $f | Format-List * }
```

Si `Test-Path` devuelve `True` y `Get-Item` muestra el fichero, registrar la entrada: "Archivo creado: <ruta completa>" y marcar formalmente el ejercicio como `✅ PASS`.

Registro final en el taller
- Esta salida y las comprobaciones se añadieron a `taller_practico.md` como evidencia reproducible. Si se desea, se puede convertir la sección WinDbg + esta ejecución en un bloque `<details>` plegable con el título:

   🧪 Ejercicio 1 — Sesión WinDbg (ntdll!NtCreateFile) — 2025-11-11 — ✅ PASS

Se puede añadir el script PowerShell que valide automáticamente la existencia del archivo y agregue el resultado en el MD; para incorporarlo, aplicar la actualización correspondiente al repositorio.