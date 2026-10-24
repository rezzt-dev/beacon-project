@echo off
rem lanza `beacon watch` y abre en el navegador la web en vivo (se refresca sola).
rem uso: scripts\beacon-live.bat [opciones de beacon watch, p. ej. -n 30 --target 192.168.1.0/24]
setlocal

cd /d "%~dp0.."
set "ROOT=%CD%"
if defined BEACON_LIVE_OUTPUT (set "OUTPUT=%BEACON_LIVE_OUTPUT%") else (set "OUTPUT=%ROOT%\vivo.html")

where uv >nul 2>nul
if %errorlevel%==0 (
  set "BEACON=uv run beacon"
) else (
  where beacon >nul 2>nul
  if errorlevel 1 (
    echo error: no se encontro "uv" ni "beacon". instala uv ^(https://docs.astral.sh/uv/^) y ejecuta "uv sync".
    exit /b 1
  )
  set "BEACON=beacon"
)

rem borra la web anterior para abrir el navegador solo cuando exista la nueva
if exist "%OUTPUT%" del /q "%OUTPUT%"

rem espera en segundo plano a que exista el fichero y lo abre con el navegador por defecto
start "" /b powershell -NoProfile -Command "for ($i=0; $i -lt 120; $i++) { if (Test-Path -LiteralPath '%OUTPUT%') { Start-Process '%OUTPUT%'; break }; Start-Sleep -Seconds 1 }"

echo web en vivo: %OUTPUT% ^(se abrira al terminar el primer escaneo^). ctrl+c para parar.
%BEACON% watch -o "%OUTPUT%" %*
endlocal
