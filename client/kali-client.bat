@echo off
REM kali-client.bat - Windows launcher for the Kali MCP client.
REM
REM Usage:
REM   kali-client.bat --list
REM   kali-client.bat --call nmap --kwargs "{\"target\": \"127.0.0.1\"}"
REM   kali-client.bat -t sse -u http://10.0.0.5:8080/sse --auth-token secret123 -i
REM
REM Environment:
REM   KALI_MCP_AUTH_TOKEN   Auth token (or pass --auth-token)
REM   KALI_MCP_TRANSPORT    stdio ^| sse ^| streamable-http
REM   KALI_MCP_SERVER_DIR   Where the kali_mcp package lives (for stdio)
REM   KALI_MCP_PYTHON       Python interpreter to use (default: python)

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "PYTHON=%KALI_MCP_PYTHON%"
if "%PYTHON%"=="" set "PYTHON=python"
set "CLIENT=%SCRIPT_DIR%kali_mcp_client.py"

if not exist "%CLIENT%" (
    echo [error] client not found: %CLIENT% >&2
    exit /b 1
)

"%PYTHON%" -c "import mcp" >nul 2>&1
if errorlevel 1 (
    echo [error] the 'mcp' package is required: pip install mcp >&2
    exit /b 1
)

REM For stdio transport, make sure the server package is importable.
set "TRANSPORT=%KALI_MCP_TRANSPORT%"
if "%TRANSPORT%"=="" set "TRANSPORT=stdio"
echo %* | findstr /i "stdio" >nul
if not errorlevel 1 set "TRANSPORT=stdio"

if "%TRANSPORT%"=="stdio" (
    "%PYTHON%" -c "import kali_mcp" >nul 2>&1
    if errorlevel 1 (
        if defined KALI_MCP_SERVER_DIR (
            set "PYTHONPATH=%KALI_MCP_SERVER_DIR%\src;%PYTHONPATH%"
        ) else if exist "%SCRIPT_DIR%..\src" (
            set "PYTHONPATH=%SCRIPT_DIR%..\src;%PYTHONPATH%"
        )
    )
)

"%PYTHON%" "%CLIENT%" %*
endlocal
