# 🧠🧪 Taller: Syscall en Windows — Teórico y práctico

Bienvenido al taller sobre syscalls en Windows. Este documento está escrito en español y busca ser accesible a un público con conocimientos básicos de programación en C y del ecosistema Windows. Vamos desde los conceptos más elementales hasta temas avanzados, con ejemplos prácticos y guías para usar herramientas como WinDbg y x64dbg.

**Guía práctica separada**: Para un enfoque más práctico con ejercicios y depuradores, consulta `taller_practico.md`.

## Objetivo

- Explicar qué es una syscall y por qué existen.
- Entender la arquitectura de Windows (user mode / kernel mode) y el papel de `ntdll.dll` y las WinAPI.
- Aprender a localizar los IDs de syscall y cómo cambian entre versiones.
- Entender y demostrar cómo funcionan los hooks en user-land (IAT/EAT/inline) y su relación con las syscall.
- Mostrar cómo realizar llamadas directas a syscalls desde C (con advertencias y contexto).
- Proveer ejercicios guiados con WinDbg y x64dbg.

## Requisitos previos

- Conocimientos básicos de C.
- Un sistema Windows (preferiblemente en una VM para pruebas).
- Compilador: Visual Studio (MSVC) o Mingw-w64/clang para los ejemplos.
- Instalar herramientas: WinDbg (parte del Windows SDK / WinDbg Preview), x64dbg, IDA/Ghidra u otra para desensamblado.

> Nota de seguridad y legal: investigar internals de sistemas y técnicas de hooking/syscalls puede ser sensible. Hazlo sólo en entornos controlados y con permisos. No uses estas técnicas para actividades ilícitas.

---

---

## Archivos añadidos

- `build_ejercicios.bat` — Script para compilar todos los ejercicios con MSVC.
- `taller_practico.md` — Guía práctica separada con ejercicios y depuradores.
- `c_examples/direct_syscall_stub.c` — Lectura de stub en ntdll.
- `c_examples/ejercicio1_createfile.c` — Crear archivo.
- `c_examples/ejercicio2_readfile.c` — Leer archivo.
- `c_examples/ejercicio3_writefile.c` — Escribir archivo.
- `c_examples/ejercicio4_listdir.c` — Listar directorio.
- `c_examples/ejercicio5_createprocess.c` — Crear proceso.
- `c_examples/ejercicio6_virtualalloc.c` — Asignar memoria.
- `c_examples/ejercicio7_socketconnect.c` — Conectar socket.
- `c_examples/ejercicio8_getsysteminfo.c` — Información del sistema.

---

## Siguientes pasos sugeridos

- Practica los ejercicios en una VM.
- Experimenta con más APIs (como networking: `socket`, `connect`).
- Aprende sobre EDR evasion y cómo detectan syscalls directas.
- Si se desea, se pueden añadir ejemplos con stubs directos o scripts para extraer IDs automáticamente.

*(Este README ha sido limpiado para eliminar caracteres de encoding y formateado para una lectura consistente.)*



## 1) Arquitectura de Windows: conceptos clave

- User Mode (Modo usuario): aquí se ejecutan las aplicaciones y muchas librerías (kernel32.dll, user32.dll, gdi32.dll, ntdll.dll).
- Kernel Mode (Modo kernel): aquí corre el núcleo del sistema (`ntoskrnl.exe`) y controladores. Tiene acceso privilegiado al hardware y recursos del sistema.

La separación protege al sistema: un fallo en user mode no tumba inmediatamente al kernel.

Componentes importantes:
- `kernel32.dll` / `user32.dll`: librerías de alto nivel que exponen la Win32 API.
- `ntdll.dll`: contiene funciones `Nt*`/`Zw*` que son trampolines hacia las syscalls; habitualmente es la última biblioteca en user mode antes de entrar al kernel.
- `ntoskrnl.exe`: el kernel de Windows que expone las funciones internas que implementan las llamadas del sistema.

## 2) ¿Qué es una syscall? Flujo de ejecución

Una syscall (abreviatura de "system call" o llamada al sistema) es una interfaz fundamental que permite a las aplicaciones en modo usuario (user mode) solicitar servicios del núcleo del sistema operativo (kernel mode). Imagina que el sistema operativo es como un restaurante: tú (la aplicación) estás en la sala de comensales (user mode), y la cocina (kernel mode) es donde se prepara la comida. Para pedir algo, no puedes entrar directamente a la cocina; en su lugar, llamas al camarero (la syscall) que lleva tu pedido al chef (el kernel) y te trae el plato de vuelta.

### ¿Por qué existen las syscalls?

- **Seguridad y estabilidad**: El kernel maneja recursos críticos como memoria, discos, red y hardware. Si cualquier aplicación pudiera acceder directamente, un error podría tumbar todo el sistema. Las syscalls actúan como un "puente controlado" que valida y ejecuta las solicitudes.
- **Abstracción**: Los programas no necesitan saber detalles del hardware; el kernel se encarga de traducir las peticiones genéricas (como "abre este archivo") en operaciones específicas del dispositivo.
- **Multitarea**: El kernel coordina quién usa qué recurso cuándo, evitando conflictos.

### Cómo funcionan las syscalls en Windows (detalles paso a paso)

Vamos a desglosar el proceso con un ejemplo simple: cuando tu programa llama a `CreateFile` para abrir un archivo.

1. **Llamada desde tu código C**: Tú escribes `HANDLE h = CreateFile("test.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);`. Esta función está en `kernel32.dll` (parte de la Win32 API).

2. **Preparación en kernel32.dll**: `CreateFile` no es una syscall directa; es una función de alto nivel que:
   - Valida parámetros (por ejemplo, convierte rutas relativas a absolutas).
   - Maneja errores comunes.
   - A menudo llama a funciones más bajas en `ntdll.dll`, como `NtCreateFile`.

3. **Tránsito a ntdll.dll**: `NtCreateFile` es un "stub" (un pequeño fragmento de código) en `ntdll.dll`. Este stub:
   - Prepara los registros del CPU según la convención de llamadas de Windows (en x64: RCX, RDX, R8, R9 para los primeros parámetros; el resto en pila).
   - Carga el número de syscall (un identificador único, como 0x55 para `NtCreateFile` en algunas versiones) en el registro EAX/RAX.
   - Ejecuta la instrucción `syscall` (en x64) o `sysenter`/`int 0x2e` en versiones más antiguas. Esta instrucción es una "trampa" que cambia el CPU de user mode a kernel mode.

4. **Ejecución en el kernel (ntoskrnl.exe)**: El kernel recibe la syscall:
   - Usa el número en EAX para buscar la función interna correspondiente (por ejemplo, la implementación de `NtCreateFile` en `ntoskrnl`).
   - Ejecuta la lógica: valida permisos, interactúa con el sistema de archivos (NTFS), asigna handles, etc.
   - Regresa un resultado (éxito/error) y datos (como el handle del archivo).

5. **Regreso a user mode**: El CPU vuelve a user mode, y el stub en `ntdll` devuelve el control a `kernel32`, que a su vez regresa a tu programa.

### Analogía cotidiana

Piensa en pedir un taxi:
- Tú llamas a la app (tu código).
- La app contacta al servicio central (kernel32/ntdll).
- El servicio envía un taxi (syscall al kernel).
- El taxi te lleva (ejecuta la tarea).
- Regresas a casa (resultado a tu app).

### Diferencias entre versiones de Windows

- En x86 (32 bits): Usaba `int 0x2e` (interrupción) o `sysenter`.
- En x64: Usa `syscall` para eficiencia.
- Los números de syscall cambian entre versiones (por ejemplo, `NtCreateFile` es 0x55 en Windows 10 1903, pero puede ser diferente en 11 o 21H2). Esto es intencional para forzar compatibilidad a través de APIs de alto nivel.

### ¿Por qué ntdll actúa como proxy?

`ntdll.dll` es el último eslabón en user mode. Las WinAPI (como kernel32) usan ntdll para:
- Mantener estabilidad: Si el kernel cambia, solo ntdll se actualiza.
- Proveer wrappers: Algunas funciones en ntdll transforman parámetros (por ejemplo, convertir strings Unicode).
- Permitir hooks: Como ntdll es user mode, se puede parchear fácilmente para interceptar llamadas (más en sección 6).

En resumen, las syscalls son el mecanismo que permite a tus programas "hablar" con el corazón del sistema de forma segura y controlada. Sin ellas, no podrías leer archivos, conectar a internet o incluso imprimir en pantalla.

## 3) Niveles y componentes relevantes

- WinAPI (kernel32/user32/etc.): API de alto nivel estable.
- ntdll.dll: contiene funciones `Nt*` y `Zw*` que son la interfaz directa hacia el kernel (stubs). `Rtl*` también contiene utilidades.
- ntoskrnl.exe: implementa los servicios del kernel.

Diferencia `Nt*` vs `Zw*`: históricamente `Zw*` son funciones del kernel que usan la convención para pasar desde kernel-mode; desde user mode usualmente hablamos de `Nt*`.

## 4) Cómo funcionan los stubs en `ntdll`

Si desensamblas `ntdll.dll` y buscas el comienzo de `NtCreateFile`, verás algo parecido a:

- En x64: una pequeña rutina que carga un número inmediato en `eax` y luego ejecuta `syscall`.
- En x86: implementaciones variadas según versión (a veces `sysenter`, `int 0x2e`, trampas indirectas).

Ejemplo conceptual (x64, pseudocódigo ensamblador):

mov r10, rcx
mov eax, 0xNNNN   ; número de syscall
syscall
ret

El número de syscall (0xNNNN) es el identificador que `ntoskrnl` usa para enrutar a la función interna.

## 5) Obtener los IDs de syscall

Los IDs no son fijos entre versiones de Windows; Microsoft NO garantiza estabilidad de estos números entre releases, por lo que técnicas que dependen de IDs exactos son frágiles.

Técnicas para obtenerlos:

- Desensamblar `ntdll.dll` y leer el inmediato en los stubs (por ejemplo con IDA/Ghidra/x64dbg): el inmediato es el syscall number.
- Usar herramientas y scripts (por ejemplo `syswhispers`/`scylla` y otras) que analizan `ntdll` y extraen tables.
- Leer listados mantenidos por la comunidad (no fiables para producción).

Herramientas útiles:
- IDA Pro / Ghidra: para inspeccionar `ntdll.dll` y ver stubs.
- x64dbg: poner un breakpoint en la entrada del stub para ver el `eax`/`rax`.
- WinDbg: similar, para trampas y seguimiento.

Ejercicio breve: en x64dbg, carga `ntdll.dll`, busca símbolo `NtCreateFile`, desensambla la función y observa el valor cargado en `eax`.

## 6) User-land hooks

Tipos comunes:

- IAT hooks: cambiar la entrada de la Import Address Table de un módulo para que apunte a una función propia.
- EAT hooks: cambiar la Export Address Table para que otros módulos que la buscan obtengan la función modificada.
- Inline hooks / trampolines: parchear los primeros bytes de una función (por ejemplo en `ntdll` o en cualquier DLL) para saltar a código propio.

Impacto sobre syscalls:
- Si parcheas `ntdll` (inline hook) puedes interceptar las llamadas antes de que se ejecute `syscall` (en user mode), alterando parámetros o comportamiento.
- Algunas soluciones de seguridad usan estas técnicas para instrumentar o prevenir ciertas syscalls.

Ejercicio: con x64dbg, establece un breakpoint en la entrada al stub de `NtCreateFile` y observa los bytes iniciales; prueba a reemplazarlos (en un entorno controlado) para ver el efecto.

## 7) Syscall directas

Hacer "syscall directo" significa evitar la función wrapper de `ntdll` y ejecutar la instrucción `syscall` con el número adecuado desde tu propio código.

Por qué hacerlo:
- Evitar hooks en `ntdll` que interceptan y alteran la llamada.
- Experimentos académicos para entender cómo funciona el kernel.

Por qué tener cuidado:
- No es compatible entre versiones. Los números cambian.
- Algunas funciones requieren parámetros transformados por wrappers; un syscall directo puede romper esas suposiciones.
- Puede desencadenar detección por EDR/AV si su uso no es legítimo.

Ejemplo teórico (x64, pseudocódigo):

1. Localiza el número de syscall en `ntdll`.
2. Crea un stub en memoria que haga `mov eax, num; mov r10, rcx; syscall; ret`.
3. Llama al stub con la convención de Windows x64 (rcx, rdx, r8, r9, stack).

A continuación se incluye un ejemplo en C (archivo en `c_examples/`) que muestra cómo localizar el número leyendo los bytes del export de `ntdll` y cómo construir un stub. Este ejemplo es educativo. Prueba en una máquina de laboratorio.

## 8) Ejercicios prácticos con WinDbg y x64dbg

Ejercicio A — Ver stub en `ntdll` con x64dbg:
1. Abrir x64dbg.
2. Cargar un ejecutable sencillo (por ejemplo `notepad.exe`) o usar `ntdll` como módulo objetivo.
3. En la ventana de módulos, localizar `ntdll.dll`.
4. Buscar la export `NtCreateFile`.
5. Desensamblar y observar el `mov eax, 0xNNNN` seguido por `syscall`.

Ejercicio B — Poner breakpoint y seguir la ejecución con WinDbg:
1. Ejecuta el programa bajo WinDbg: `windbg -o -g <app>`.
2. Coloca breakpoint en `ntdll!NtCreateFile` con `bp ntdll!NtCreateFile`.
3. Ejecuta la aplicación que abrirá un archivo (p. ej. `CreateFile` desde un pequeño programa C).
4. Cuando el breakpoint se dispare, observa registros y pila (`r`, `k`, `dds` para ver memoria si es necesario).

Ejercicio C — Extraer ID con script o a mano:
1. Desensambla `ntdll!NtCreateFile`.
2. Observa el inmediato en la instrucción `mov eax, imm32`.
3. Ese `imm32` es el syscall ID en esa versión concreta.

## 9) Código de ejemplo y cómo compilar

He incluido un ejemplo en `c_examples/direct_syscall_stub.c` que muestra los pasos descritos arriba. Está pensado para compilar con MSVC (cl.exe) o MSBuild. En MSVC/x64 algunas construcciones de ensamblador deben escribirse en un archivo `.asm` separado.

Pasos rápidos para compilar (MSVC con PowerShell, asumiendo Developer Command Prompt o vcvarsall.bat ejecutado):

# Ejemplo (PowerShell)
# Ejecuta primero: vcvarsall.bat x64 (o x86) para configurar entorno MSVC
cl /Fe:direct_syscall_example.exe c_examples/direct_syscall_stub.c

(Usa MSBuild si tienes un .vcxproj, o Visual Studio para compilar con MSVC si prefieres; puede requerir cambios en la sintaxis de ensamblador.)

**Script de compilación automática**: Ejecuta `build_ejercicios.bat` para compilar todos los ejercicios de una vez. Asegúrate de ajustar la ruta a `vcvarsall.bat` si es necesario.

## 10) Ejercicios prácticos en C con análisis de syscalls

A continuación, varios ejercicios en C que usan APIs comunes. Cada uno incluye código, compilación, ejecución y guías para analizar las syscalls con WinDbg y x64dbg. Estos programas son simples y seguros para ejecutar en un entorno de laboratorio.

### Ejercicio 1: Crear un archivo (`ejercicio1_createfile.c`)

**Objetivo**: Ver cómo `CreateFile` invoca `NtCreateFile`.

**Compilación**:
```powershell
gcc -o ejercicio1.exe c_examples/ejercicio1_createfile.c
```

**Ejecución**:
```powershell
.\ejercicio1.exe
```
Debería crear `test_file.txt` en el directorio actual.

**Análisis con x64dbg**:
1. Abre x64dbg.
2. Carga `ejercicio1.exe` (File > Open).
3. Ejecuta hasta el main (F9 o Run).
4. Pon breakpoint en `ntdll!NtCreateFile` (busca en Symbols > ntdll.dll > NtCreateFile, right-click > Toggle breakpoint).
5. Ejecuta (F9). Cuando pare, observa EAX (syscall ID) y pila (parámetros).
6. Desensambla el stub: ve a la dirección de NtCreateFile y mira el `mov eax, imm32`.

**Análisis con WinDbg**:
1. Ejecuta: `windbg -o -g ejercicio1.exe`.
2. Pon breakpoint: `bp ntdll!NtCreateFile`.
3. Ejecuta: `g`.
4. Cuando pare: `r` (ver registros, nota EAX), `k` (stack trace), `dds esp` (ver parámetros en pila).

### Ejercicio 2: Leer un archivo (`ejercicio2_readfile.c`)

**Objetivo**: Ver `NtReadFile`.

**Compilación y ejecución**: Similar al ejercicio 1, pero ejecuta después de crear `test_file.txt` con el ejercicio 1.

**Análisis**: Pon breakpoint en `ntdll!NtReadFile`. Observa cómo se pasan el handle y buffer.

### Ejercicio 3: Escribir en un archivo (`ejercicio3_writefile.c`)

**Objetivo**: Ver `NtWriteFile`.

**Compilación y ejecución**: Similar.

**Análisis**: Breakpoint en `ntdll!NtWriteFile`. Nota el buffer de escritura en parámetros.

### Ejercicio 4: Listar directorio (`ejercicio4_listdir.c`)

**Objetivo**: Ver `NtQueryDirectoryFile`.

**Compilación y ejecución**: Similar.

**Análisis**: Breakpoint en `ntdll!NtQueryDirectoryFile`. Observa cómo se itera sobre archivos.

### Ejercicio 5: Crear un proceso (`ejercicio5_createprocess.c`)

**Objetivo**: Ver `NtCreateUserProcess` o `NtCreateProcessEx`.

**Compilación**:
```powershell
cl /Fe:ejercicio5.exe c_examples/ejercicio5_createprocess.c
```

**Ejecución**:
```powershell
.\ejercicio5.exe
```
Abre Notepad y espera a que se cierre.

**Análisis**: Pon breakpoint en `ntdll!NtCreateUserProcess`. Observa parámetros de creación de proceso.

### Ejercicio 6: Asignar memoria (`ejercicio6_virtualalloc.c`)

**Objetivo**: Ver `NtAllocateVirtualMemory`.

**Compilación**:
```powershell
cl /Fe:ejercicio6.exe c_examples/ejercicio6_virtualalloc.c
```

**Ejecución**:
```powershell
.\ejercicio6.exe
```
Asigna y libera memoria.

**Análisis**: Breakpoint en `ntdll!NtAllocateVirtualMemory`. Nota direcciones y tamaños.

### Ejercicio 7: Conectar socket (`ejercicio7_socketconnect.c`)

**Objetivo**: Ver syscalls de networking como `NtDeviceIoControlFile`.

**Compilación**:
```powershell
cl /Fe:ejercicio7.exe c_examples/ejercicio7_socketconnect.c ws2_32.lib
```

**Ejecución**:
```powershell
.\ejercicio7.exe
```
Intenta conectar a localhost:80 (puede fallar si no hay servidor).

**Análisis**: Breakpoint en `ntdll!NtDeviceIoControlFile` o funciones de socket. Observa operaciones de red.

### Ejercicio 8: Información del sistema (`ejercicio8_getsysteminfo.c`)

**Objetivo**: Ver `NtQuerySystemInformation`.

**Compilación**:
```powershell
cl /Fe:ejercicio8.exe c_examples/ejercicio8_getsysteminfo.c
```

**Ejecución**:
```powershell
.\ejercicio8.exe
```
Muestra info del sistema.

**Análisis**: Breakpoint en `ntdll!NtQuerySystemInformation`. Observa qué información se consulta.
- En x64dbg: Usa la ventana de CPU para desensamblar, Registers para ver EAX, y Stack para parámetros.
- En WinDbg: Comandos útiles: `u ntdll!NtCreateFile` (desensamblar), `r` (registros), `dv` (variables locales si tienes símbolos).
- Extrae el syscall ID: En el stub, busca `mov eax, 0xXXXX` y anota el valor.
- Compara entre versiones: Ejecuta en diferentes builds de Windows y nota si cambia el ID.

Estos ejercicios te ayudarán a entender cómo las APIs de alto nivel traducen a syscalls específicas.

## 11) Recursos y lecturas recomendadas

- **Libros**:
  - "Windows Internals" de Mark Russinovich et al. — La biblia para internals de Windows.
  - "Windows System Programming" de Johnson M. Hart.

- **Documentación oficial**:
  - MSDN: Documentación de Win32 API y ntdll.
  - Microsoft Learn: Arquitectura de Windows.

- **Herramientas y proyectos**:
  - WinDbg Preview (Microsoft).
  - x64dbg (open source).
  - IDA Pro / Ghidra para desensamblado avanzado.
  - SysWhispers: Herramientas para extraer syscall IDs.

- **Comunidades**:
  - Reddit: r/ReverseEngineering, r/windowsinternals.
  - Foros: Tuts4You, OpenSecurityTraining.

- **Precauciones legales**: Estudia internals para aprendizaje, no para bypass de seguridad sin permiso. Respeta leyes locales.

---

## Archivos añadidos

- `build_ejercicios.bat` — Script para compilar todos los ejercicios con MSVC.
- `taller_practico.md` — Guía práctica separada con ejercicios y depuradores.
- `c_examples/direct_syscall_stub.c` — Lectura de stub en ntdll.
- `c_examples/ejercicio1_createfile.c` — Crear archivo.
- `c_examples/ejercicio2_readfile.c` — Leer archivo.
- `c_examples/ejercicio3_writefile.c` — Escribir archivo.
- `c_examples/ejercicio4_listdir.c` — Listar directorio.
- `c_examples/ejercicio5_createprocess.c` — Crear proceso.
- `c_examples/ejercicio6_virtualalloc.c` — Asignar memoria.
- `c_examples/ejercicio7_socketconnect.c` — Conectar socket.
- `c_examples/ejercicio8_getsysteminfo.c` — Información del sistema.

---

## Siguientes pasos sugeridos

- Practica los ejercicios en una VM.
- Experimenta con más APIs (como networking: `socket`, `connect`).
- Aprende sobre EDR evasion y cómo detectan syscalls directas.
- Si se desea, se pueden añadir ejemplos con stubs directos o scripts para extraer IDs automáticamente.
