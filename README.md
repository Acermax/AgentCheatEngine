# AgentCheatEngine

Repositorio: https://github.com/Acermax/AgentCheatEngine

AgentCheatEngine es un servidor MCP para inspeccionar memoria de procesos en
Windows desde clientes compatibles con Model Context Protocol, como Codex,
Claude Desktop u otros agentes. La idea es ofrecer una capa reutilizable estilo
Cheat Engine para automatizar lecturas, scans, desensamblado y analisis de
estructuras de memoria.

El proyecto esta pensado para investigacion, debugging, aprendizaje de reverse
engineering y trabajo sobre procesos propios o con autorizacion. Algunas
herramientas pueden modificar memoria, asi que usalas con cuidado y solo en
entornos donde tengas permiso.

## Contenido

- `memory_mcp_server.py`: servidor MCP principal.
- `requirements.txt`: dependencias Python.
- `install.bat`: instalador rapido para Windows.
- `docs/agent_usage.md`: guia con ejemplos de llamadas MCP.

## Caracteristicas

- Listado de procesos, modulos y mapa de memoria.
- Lectura de memoria con interpretacion basica y hexdump.
- Resolucion de expresiones como `DemoApp.exe+0x414F6D0+0x4`.
- Lectura tipada de estructuras y cadenas de punteros.
- Lecturas batch para reducir llamadas MCP.
- Busquedas de valores numericos, flotantes y strings.
- Sesiones de scan persistentes con filtros tipo `changed`, `decreased`,
  `increased`, `eq_prev` y otros.
- AOB scans con wildcards y preflight para evitar scans demasiado amplios.
- Jobs a archivo para scans largos con resultados JSONL.
- Desensamblado x86-64 con Capstone.
- Busqueda de callers directos mediante resolucion matematica de `CALL rel32`.
- Comparacion de memoria contra lecturas anteriores.
- Escritura de bytes con `mem_write` para casos autorizados y controlados.

## Requisitos

- Windows.
- Python 3.10 o superior.
- Permisos suficientes para abrir el proceso objetivo. Para algunos procesos
  puede hacer falta ejecutar el cliente MCP como administrador.

Dependencias principales:

```txt
mcp[cli]>=1.0.0
pydantic>=2.0.0
psutil>=5.9.0
capstone>=5.0.0
```

## Instalacion

Instalacion rapida:

```bat
install.bat
```

Instalacion manual:

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Configuracion MCP

Ejemplo de configuracion para un cliente MCP stdio:

```json
{
  "mcpServers": {
    "memory": {
      "command": "C:\\Users\\Acermax\\PycharmProjects\\AgentCheatEngine\\venv\\Scripts\\python.exe",
      "args": [
        "C:\\Users\\Acermax\\PycharmProjects\\AgentCheatEngine\\memory_mcp_server.py"
      ]
    }
  }
}
```

Si clonas el repositorio en otra ruta, ajusta `command` y `args` a la ruta
local correspondiente.

## Uso Para Agentes

Muchos clientes MCP exponen estas herramientas con un unico argumento requerido
llamado `params`. Cuando el schema lo pida asi, envuelve siempre los parametros
dentro de `params`.

Correcto:

```json
{
  "params": {
    "pid": 1234,
    "address": "DemoApp.exe+0x123456",
    "size": 128
  }
}
```

Incorrecto:

```json
{
  "pid": 1234,
  "address": "DemoApp.exe+0x123456",
  "size": 128
}
```

Lee tambien [docs/agent_usage.md](docs/agent_usage.md).

## Herramientas MCP

| Herramienta | Uso |
| --- | --- |
| `mem_list_processes` | Lista procesos con filtro opcional por nombre. |
| `mem_get_modules` | Lista modulos cargados y sus direcciones base. |
| `mem_memory_map` | Enumera regiones legibles con `VirtualQueryEx`. |
| `mem_read` | Lee bytes y devuelve hexdump e interpretacion basica. |
| `mem_disassemble` | Desensambla x86-64 con Capstone. |
| `mem_find_callers` | Encuentra llamadas directas hacia funciones objetivo. |
| `mem_read_struct` | Lee varios campos tipados desde una base. |
| `mem_follow_pointers` | Sigue cadenas de punteros. |
| `mem_watch_batch` | Lee muchas direcciones tipadas en una sola llamada. |
| `mem_search_value` | Busca valores o strings en memoria. |
| `mem_scan_start` | Inicia una sesion persistente de candidatos. |
| `mem_scan_next` | Filtra candidatos por valor actual o valor previo. |
| `mem_scan_results` | Pagina y refresca resultados de una sesion. |
| `mem_scan_clear` | Limpia sesiones de escaneo. |
| `mem_aob_scan` | Busca patrones de bytes con wildcards. |
| `mem_aob_scan_file_start` | Lanza AOB scans largos en background. |
| `mem_scan_file_status` | Consulta el estado de un scan a archivo. |
| `mem_scan_file_cancel` | Cancela un scan a archivo. |
| `mem_scan_linked_list` | Recorre listas enlazadas o buckets genericos. |
| `mem_compare` | Compara memoria actual contra bytes previos. |
| `mem_write` | Escribe bytes en memoria. Operacion destructiva. |
| `mem_close` | Cierra el handle cacheado de un PID. |

## Ejemplos Rapidos

Listar procesos:

```json
{
  "params": {
    "filter_name": "demo"
  }
}
```

Leer memoria:

```json
{
  "params": {
    "pid": 1234,
    "address": "DemoApp.exe+0x414F6D0+0x4",
    "size": 64,
    "interpret": true
  }
}
```

Desensamblar:

```json
{
  "params": {
    "pid": 1234,
    "address": "DemoApp.exe+0x123456",
    "size": 160,
    "max_instructions": 40,
    "syntax": "intel"
  }
}
```

Buscar callers directos:

```json
{
  "params": {
    "pid": 1234,
    "target_addresses": ["0x4630", "0x4710"],
    "module_name": "DemoApp.exe"
  }
}
```

AOB scan acotado:

```json
{
  "params": {
    "pid": 1234,
    "pattern": "48 8B ?? ?? B0 01 C3",
    "module_name": "DemoApp.exe",
    "max_results": 30
  }
}
```

## Reglas De Uso Recomendadas

- Acota scans con `module_name`, `region_start` o `region_end` siempre que sea
  posible.
- Si una herramienta devuelve `scan_too_broad`, no repitas la misma llamada:
  estrecha el rango o usa un job a archivo.
- Usa `mem_disassemble` antes de contar bytes manualmente.
- Usa `mem_find_callers` para callers directos en vez de buscar `E8` a mano.
- Usa `mem_watch_batch` para muchas lecturas pequenas.
- Trata `mem_write` como una operacion destructiva: valida direccion, bytes y
  proceso antes de ejecutarla.
- Cierra handles con `mem_close` al terminar una sesion.

## Scans Grandes A Archivo

Para consultas que pueden tardar mucho, usa jobs a archivo. La llamada vuelve
rapido y el servidor escribe progreso/resultados en `artifacts/scan_jobs/`.

```json
{
  "params": {
    "pid": 1234,
    "pattern": "B0 01 C3",
    "module_name": "DemoApp.exe",
    "max_results": 100000
  }
}
```

Herramienta: `mem_aob_scan_file_start`.

Despues consulta:

```json
{
  "params": {
    "job_id": "abc123def456",
    "tail_results": 5
  }
}
```

Herramienta: `mem_scan_file_status`.

## Errores Comunes

- `params Field required`: envuelve los argumentos dentro de `params`.
- `scan_too_broad`: acota el modulo o rango antes de repetir.
- `ERROR_PARTIAL_COPY` / WinError 299: la lectura cruzo una pagina no legible o
  cambiante; reduce `size` o alinea la lectura.
- `Access denied` / WinError 5: ejecuta el cliente MCP como administrador.
- `missing_dependency capstone`: instala dependencias con
  `pip install -r requirements.txt`.

## Desarrollo

Comprobar sintaxis:

```bat
python -m py_compile memory_mcp_server.py
```

El repositorio ignora `venv/`, `__pycache__/`, `.pytest_cache/` y los resultados
temporales de `artifacts/scan_jobs/`.

## Licencia

Este proyecto se distribuye bajo licencia MIT. Consulta [LICENSE](LICENSE).
