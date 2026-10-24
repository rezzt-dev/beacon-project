###  BEACON PROJECT  |  SEGUIMIENTO DE LA EVOLUCION INTEGRAL
> estado de cada tarea de la evolución descrita en `PROMPT-MEJORA-INTEGRAL.md`. estados: `pendiente`, `en curso`, `verificado`, `bloqueado`. una tarea solo pasa a `verificado` con pruebas o evidencia ejecutada.
---
####   LINEA BASE (2026-10-24)
   - 241 pruebas superadas (`python -m pytest -q`, 1,45 s) y `ruff check app tests` sin errores, con python 3.13 en `~/.cache/beacon/venv`.
   - el `.venv` del repositorio está roto (sin `pyvenv.cfg`): el disco es exfat y no admite symlinks; se usa `UV_PROJECT_ENVIRONMENT=~/.cache/beacon/venv`.
---
####   FASE 1 · DOMINIO
| tarea | estado |
|---|---|
| ssh fuera de protocolos sin cifrar; separar protocolo observado, servicio inferido y exposición administrativa | verificado |
| host local y gateway sin inmunidad; estado "sin datos suficientes" en vez de "seguro" | verificado |
| estados de puerto: abierto, cerrado confirmado, filtrado, no examinado, error; subconjuntos sin falsos cierres | verificado |
| cobertura y frescura por dispositivo y puerto en lugar de `ports_ever_scanned()` | verificado |
| eventos de riesgo acotados en el tiempo, con razones, pesos y versión de reglas; confiar no borra evidencias | verificado |
| distinguir caída del monitor, escaneo incompleto y desaparición de dispositivos | verificado |
| ámbito de red estable y migración de claves, referencias, identidades, eventos y sesiones | verificado |
| cancelación, limpieza y errores por host sin presentar escaneos incompletos como completos | verificado |
---
####   FASE 2 · SERVICIOS, API Y TRABAJOS
| tarea | estado |
|---|---|
| capa de servicios compartida por cli y api | verificado |
| conexiones sqlite por hilo, `busy_timeout`, transacciones breves | verificado |
| registro de cambios monotónico para sse con reanudación y snapshot | verificado |
| api versionada `/api/v1` con validación, paginación, filtros, errores y control de concurrencia | verificado |
| seguridad local: loopback, host/origin, sesión, csrf, límites | verificado |
| gestor de trabajos con propietario único por ámbito, cola acotada y cancelación | verificado |
---
####   FASE 3 · APLICACION LIVE
| tarea | estado |
|---|---|
| comando `beacon live` y lanzadores actualizados | verificado |
| contenedor con navegación agrupada, rutas estables y estado en la url | verificado |
| vistas resumen, dispositivos, detalle, revisión y eventos con acciones reales | verificado |
| informe html autónomo conservado y separado en plantilla, estilos y script | verificado |
---
####   FASE 4 · ANALISIS
| tarea | estado |
|---|---|
| identidades: rechazo persistente, separación, trazabilidad | verificado |
| presencia con cobertura del monitor, zona horaria e incertidumbre | verificado |
| servicios: inventario por protocolo, cobertura y antigüedad | verificado |
| histórico de mediciones de latencia y puertos con retención | verificado |
| comparación entre escaneos con diferencias de alcance | verificado |
| perfiles de red persistentes | verificado |
---
####   FASE 5 · CAPACIDADES AVANZADAS
| tarea | estado |
|---|---|
| políticas de alerta con silencios y mantenimiento | verificado |
| notificaciones de escritorio y webhook con reintentos e idempotencia | verificado |
| enriquecimiento tls | verificado |
| escucha pasiva opcional (arp, dhcp, mdns) | verificado |
| ipv6 incremental con ndp | verificado |
| ejecución sin terminal y unidad de servicio opcional | verificado |
---
####   FASE 6 · CALIDAD Y DISTRIBUCION
| tarea | estado |
|---|---|
| pruebas de navegador (teclado, móvil, accesibilidad) | verificado |
| benchmarks con datasets sintéticos de 50, 500 y 5.000 dispositivos y 100.000 eventos | verificado |
| copia de seguridad, restauración y retención | verificado |
| integración continua, construcción y verificación del paquete | verificado |
| documentación, changelog y versión | verificado |

---
####   CIERRE DE IMPLEMENTACION · 2026-10-24 · V0.2.0
Las filas anteriores describen implementación y validación automatizada local. No equivalen a certificación de todas las plataformas ni a mediciones de redes físicas.

| área | evidencia ejecutada |
|---|---|
| dominio, cobertura, riesgo, cancelación y redes | `test_risk.py`, `test_ports.py`, `test_diff.py`, `test_pipeline.py`, `test_api.py`; regresión para conflictos de IP entre redes |
| caché y concurrencia | `test_inventory_cache.py`: reutilización entre páginas/órdenes, caducidad temporal, invalidación por otra conexión, bases en memoria independientes y conflicto de confianza durante una escritura |
| revisión paginada | API: total y evidencia acotada; Chromium: segunda página y recuperación cuando se agota la última página, conservación del foco |
| alertas y notificaciones | `test_alerts.py`: políticas, silencios, enfriamiento, webhook real en loopback con firma, reintentos, idempotencia y escritorio con transporte sustituido |
| escucha pasiva, TLS e IPv6 | `test_passive.py`, `test_tls.py`, `test_ipv6.py`: paquetes sintéticos, colas acotadas, certificados y parsers |
| servicio y lanzadores | `test_service.py`: definiciones y activación simulada; proceso live real sin terminal y parada por SIGTERM; `bash -n scripts/beacon-live.sh` |
| migraciones, copias y retención | `test_migrations.py`, `test_admin_cli.py`, `test_storage.py`: migración desde v1–v4, copia previa, integridad y restauración |
| interfaz | Chromium a 360, 768, 1280 y 1920 px, teclado, contraste, nombres accesibles, edición, revisión, reconexión y exportación |
| rendimiento | `benchmarks.json`, `benchmarks-anterior.json`, `rendimiento.md`: 50/500/5.000 dispositivos, 100.000 eventos, memoria RSS y consultas SQL |
| distribución | wheel y sdist 0.2.0, instalación del wheel fuera del repositorio y comprobación de sus recursos; CI configurada en `.github/workflows/ci.yml` |

Validación final y límites detallados en `validacion-final.md`. El esquema sigue siendo v5; las mejoras de esta continuación no añaden otra migración.

####   VALIDACIONES EXTERNAS PENDIENTES
| tarea | estado | motivo |
|---|---|---|
| ejecutar la matriz CI en Linux, macOS y Windows / Python 3.11–3.13 | pendiente | configuración preparada; no se ha ejecutado un runner remoto desde esta sesión |
| captura pasiva y escaneo privilegiado sobre una red física | pendiente | se han probado parsers y flujos simulados; no se han lanzado barridos ni capturas sobre la red del usuario |
| activar systemd/launchd y validar notificaciones de escritorio reales | pendiente | pruebas de definiciones, transporte sustituido y proceso sin terminal; no se han modificado servicios del sistema |
| calibración de heurísticas con datos reales | pendiente | los pesos actuales siguen siendo heurísticos y están versionados |
