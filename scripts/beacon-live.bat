@echo off
rem abre beacon en el navegador. dos modos:
rem   scripts\beacon-live.bat [opciones de beacon live]            aplicacion live (p. ej. --monitor 60)
rem   scripts\beacon-live.bat --report [opciones de beacon watch]  informe html autonomo que regenera `beacon watch -o`
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

if not "%~1"=="--report" (
  echo beacon live: la aplicacion se abrira en el navegador. ctrl+c para parar.
  %BEACON% live %*
  exit /b %errorlevel%
)
shift

rem borra el informe anterior para abrir el navegador solo cuando exista el nuevo
if exist "%OUTPUT%" del /q "%OUTPUT%"

rem espera en segundo plano a que exista el fichero y lo abre con el navegador por defecto
start "" /b powershell -NoProfile -Command "for ($i=0; $i -lt 120; $i++) { if (Test-Path -LiteralPath '%OUTPUT%') { Start-Process '%OUTPUT%'; break }; Start-Sleep -Seconds 1 }"

echo informe html en vivo: %OUTPUT% ^(se abrira al terminar el primer escaneo^). ctrl+c para parar.
set "ARGS="
:collect
if "%~1"=="" goto run
set "ARGS=%ARGS% %1"
shift
goto collect
:run
%BEACON% watch -o "%OUTPUT%"%ARGS%
endlocal
