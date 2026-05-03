@echo off
echo === Instalando Memory MCP Server ===
echo.

REM Crear venv si no existe
if not exist "venv" (
    echo Creando entorno virtual...
    python -m venv venv
)

echo Activando entorno virtual...
call venv\Scripts\activate.bat

echo Instalando dependencias...
pip install -r requirements.txt

echo.
echo === Instalacion completada ===
echo.
echo Para configurar en Claude Desktop, agrega esto a:
echo   %%APPDATA%%\Claude\claude_desktop_config.json
echo.
echo {
echo   "mcpServers": {
echo     "memory": {
echo       "command": "%CD%\venv\Scripts\python.exe",
echo       "args": ["%CD%\memory_mcp_server.py"]
echo     }
echo   }
echo }
echo.
echo IMPORTANTE: Ejecuta Claude Desktop como Administrador para acceso completo.
pause
