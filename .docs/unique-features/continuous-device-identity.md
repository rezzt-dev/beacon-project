###  BEACON PROJECT  |  IDENTIDAD CONTINUA DE DISPOSITIVOS
> propuesta de funcionalidad (no implementada). reconoce que un móvil con mac aleatorizada que vuelve con otra mac es el mismo dispositivo, con evidencias visibles y sin heredar la confianza de forma automática.
---
####   1. IDENTIFICACION
| campo | valor |
|---|---|
| nombre | identidad continua de dispositivos |
| categoría | motor de limpieza, fingerprinting, reinvención de una limitación conocida |
| propósito | que la identidad de un dispositivo sobreviva a los cambios de mac aleatorizada |
| prioridad | 2 (alta) |
| complejidad | alta (≈ 8-12 días): nuevo scanner de servicios mdns, módulo de puntuación, migración y comandos |

**resumen ejecutivo.** `estado-y-siguientes-pasos.md` reconoce que "algunos móviles cambian de mac al reconectarse, por lo que pueden aparecer como dispositivos nuevos" y que hoy no se correlacionan. la clave de un dispositivo es su mac (`Device.key`), de modo que cada mac nueva produce una alerta `new-device` y un historial roto. esta funcionalidad añade un **resolvedor de identidad**: compara un dispositivo aleatorizado recién aparecido con los aleatorizados que ahora están offline usando una huella (nombre, servicios mdns, puertos, familia de ttl) y devuelve una puntuación con **las evidencias que la sustentan**. los vínculos fuertes se proponen al usuario; los confirmados fusionan alias e historial. la confianza nunca se hereda sin confirmación.

---
####   2. PROBLEMA Y OPORTUNIDAD
**problema.** una red doméstica o de oficina con móviles modernos genera "intrusos" falsos de forma recurrente, y cada uno acostumbra al usuario a ignorar alertas. es el origen principal de la fatiga de alertas en beacon.

**limitaciones actuales (verificadas en el código).**
   - `core/mac.py` detecta `is_randomized()` y `core/engine.py` marca `randomized_mac`, pero no hay ningún mecanismo que relacione dos dispositivos distintos.
   - `Repository.find_device()` y `detect_changes()` identifican solo por `key` (mac o `ip:<ip>`).
   - el hostname se conserva entre escaneos del mismo `key` (`_carry_history` en `pipeline.py`), pero nunca se usa para vincular claves distintas.
   - la resolución actual de mdns (`scanners/hostname.py`, `mdns()`) solo hace una consulta PTR inversa; no consulta qué servicios anuncia el dispositivo (`_services._dns-sd._udp.local`).
   - `Device.to_dict()` no incluye ninguna huella reutilizable.

**necesidades del usuario.** (a) ver una única entrada por dispositivo físico a lo largo del tiempo, (b) que el alias y el historial no se pierdan, (c) que una alerta de "nuevo" signifique realmente nuevo.

**diferencias frente a alternativas.** las herramientas que se consultaron (netalertx, watchyourlan, fing) describen la detección de nuevos dispositivos y cambios de ip, pero en lo revisado no se documenta la correlación de macs aleatorizadas con evidencias; es una comparación basada solo en descripciones públicas, no verificada empíricamente. el enfoque propuesto es diferenciador porque (1) muestra cada evidencia en lenguaje claro, (2) es conservador ante suplantación y (3) usa solo datos obtenibles sin privilegios.

---
####   3. CONCEPTO Y FUNCIONAMIENTO
**principios de diseño.**
   - **la mac sigue siendo la clave física**; la identidad es una capa superior (`identity_id`) que agrupa claves.
   - **solo se comparan candidatos plausibles:** un dispositivo aleatorizado nuevo contra aleatorizados con estado `offline`. dos dispositivos online a la vez no pueden ser el mismo.
   - **evidencia explícita:** cada coincidencia aporta un motivo ("mismo hostname `iphone-de-ana`", "mismos 3 servicios mdns", "mismos puertos abiertos").
   - **fallar hacia "nuevo":** ante la duda se mantiene el comportamiento actual (alerta de dispositivo nuevo).
   - **la confianza no se hereda automáticamente.** un atacante puede copiar un hostname; heredar `trusted` convertiría el vínculo en una vía de suplantación.

**huella (`Fingerprint`), calculada solo con datos que beacon ya tiene o puede obtener sin root.**

| rasgo | peso orientativo | origen |
|---|---|---|
| hostname normalizado (sin sufijos `-2`, `(2)`, minúsculas) idéntico | 0.55 | `Device.hostname` (dns/mdns/netbios) |
| conjunto de tipos de servicio mdns anunciados | hasta 0.25 (jaccard) | **nuevo:** exploración de servicios |
| conjunto de puertos abiertos idéntico y no vacío | 0.10 | `Device.open_ports` |
| misma familia de ttl | 0.05 | `Device.ttl` |
| mismo prefijo de red / patrón de latencia | 0.05 (desempate) | `Device.latency` |

umbrales propuestos: `≥ 0.80` → vínculo **probable** (se propone y se registra el evento); `0.50-0.79` → **posible** (solo se muestra en `devices candidates`); `< 0.50` → ninguno. **los pesos y umbrales son una hipótesis inicial y deben calibrarse con capturas reales de varios móviles antes de fijarlos.** una coincidencia solo por ttl o latencia nunca alcanza el umbral.

**comportamiento.**
   1. tras `CleaningEngine.merge` y el enriquecimiento, para cada dispositivo aleatorizado sin historial se calcula la huella.
   2. `IdentityResolver.match(new, offline_candidates)` devuelve candidatos ordenados con evidencias.
   3. si el mejor candidato supera `0.80` y es único (el segundo queda al menos 0.15 por debajo), se emite el evento `identity-candidate` (severidad `warning`, en lugar de `new-device` con `alert`) con el texto "probablemente `<alias>` con una nueva mac privada (0.86: hostname, 3 servicios)".
   4. el usuario confirma con `beacon devices link <nueva> <antigua>`: se asigna el mismo `identity_id`, se copia el alias, se conserva `first_seen` más antiguo para la identidad y la mac nueva puede marcarse de confianza (pregunta explícita).
   5. `beacon devices unlink` deshace el vínculo.

**casos de uso.**
   - un iphone con dirección privada rotatoria vuelve con otra mac y el mismo nombre `iphone-de-ana`: se propone el vínculo en lugar de una alerta de intruso.
   - un portátil desconocido anuncia por casualidad el mismo hostname que un dispositivo de confianza: se propone vínculo `posible/probable`, **no** se hereda confianza, y `beacon review`/alertas lo siguen tratando como no confiable hasta confirmar.
   - dos móviles idénticos de la misma familia con hostname genérico (`android`): hostnames genéricos se marcan en una lista de "nombres no discriminantes" (`android`, `localhost`, `iphone`) y no suman puntos.

**limitaciones.**
   - dispositivos sin hostname ni servicios mdns (muchos iot) no se pueden correlacionar de forma fiable; se quedan como hoy.
   - la fiabilidad depende de la red: mdns puede estar bloqueado entre segmentos o por aislamiento de clientes en wi-fi.
   - los sistemas operativos cambian su comportamiento de direcciones privadas entre versiones; el diseño no asume una política concreta de rotación. **conviene verificar con dispositivos reales qué rasgos permanecen estables.**
   - solo ipv4, como el resto de beacon.

---
####   4. EXPERIENCIA DE USUARIO
**ubicación.** subcomandos nuevos de `beacon devices` (`candidates`, `link`, `unlink`), línea de identidad en `beacon devices show`, eventos en `beacon scan` / `watch` y una marca visible en la tabla.

**componentes visuales.**
   - en `devices_table` (`ui/render.py`), el nombre de un dispositivo vinculado muestra el sufijo `~ana-iphone` o un indicador `⛓` en estilo `accent` junto a las etiquetas `gateway` / `this host` de `fmt_name`.
   - `device_detail` gana un bloque "identidad" con las macs conocidas de la identidad, sus fechas y las evidencias del vínculo.
   - `devices candidates` muestra una tabla `nueva mac | candidata | puntuación | evidencias`.

**estados.**
   - *vacío:* "no hay candidatos de vínculo" (`muted`).
   - *carga:* el sondeo de servicios mdns se integra como etapa del `ProgressReporter` ("mdns services") con el mismo progreso que el resto del enriquecimiento.
   - *error:* mdns sin respuesta no es un error; la huella queda sin ese rasgo y se reduce la confianza. un vínculo con referencia inexistente falla con el mismo mensaje que `find_device_or_exit`.
   - *éxito:* `✓ vinculado b4:... con 9a:... (ana-iphone)`.
   - *deshabilitado:* `--no-identity` en `scan`/`watch` desactiva la etapa (por privacidad o velocidad).

**accesibilidad.** el estado del vínculo siempre se expresa con texto (`probable`, `posible`), no solo con color o símbolo; las evidencias son frases completas.

**coherencia visual.** estilos existentes: `accent` (identidad), `warning` (candidato), `muted` (sin datos); sin colores nuevos.

---
####   5. ARQUITECTURA E IMPLEMENTACION
**dependencias.** ninguna nueva. el cliente mdns se construye sobre `scanners/protocols/dns.py` (`encode_name`, `read_name`, `build_query`, `DnsParseError` ya existen) y `udp_request` de `scanners/hostname.py`.

**archivos nuevos.**
   - `app/beacon/core/identity.py`: `Fingerprint`, `IdentityMatch`, `fingerprint(device)`, `score(a, b)`, `IdentityResolver`. función pura, sin red.
   - `app/beacon/scanners/services.py`: `discover_services(ip) -> list[str]` consulta unicast a `_services._dns-sd._udp.local` (PTR) en el puerto 5353.
   - `tests/test_identity.py`, ampliación de `tests/test_scanners.py` para el parser de servicios.

**archivos existentes a modificar.**
   - `app/beacon/scanners/protocols/dns.py`: `parse_ptr_records(data) -> list[str]`, que devuelva todos los PTR de la respuesta (el `parse_ptr_response` actual solo devuelve el primero).
   - `app/beacon/core/models.py`: campos `services: list[str]` e `identity_id: int | None` en `Device`; incluirlos en `to_dict()`.
   - `app/beacon/pipeline.py`: etapa de servicios dentro de `_enrich` (con el semáforo de hosts existente) y llamada al resolvedor entre `_enrich` y `detect_changes`.
   - `app/beacon/core/diff.py`: aceptar los candidatos y emitir `identity-candidate` en lugar de `new-device` cuando corresponda.
   - `app/beacon/core/events.py`: `EventType.IDENTITY_CANDIDATE = "identity-candidate"`.
   - `app/beacon/storage/database.py` y `repository.py`: migración (ver abajo) y métodos `link_devices`, `unlink_device`, `list_candidates`.
   - `app/beacon/cli/commands/devices.py`: `candidates`, `link`, `unlink`.
   - `app/beacon/ui/render.py`: marca de identidad y bloque en `device_detail`.

**modelo de datos (migración propuesta).**
```sql
ALTER TABLE devices ADD COLUMN services TEXT NOT NULL DEFAULT '[]';
ALTER TABLE devices ADD COLUMN identity_id INTEGER;
CREATE TABLE identities (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  label      TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_devices_identity ON devices (identity_id);
```
(si se implementa a la vez que el triage, ambas migraciones se numeran en el orden de fusión; cada una es aditiva.)

**flujo de datos.** `_enrich` (servicios) → `IdentityResolver.match` contra `previous` offline aleatorizados → `detect_changes` recibe candidatos → eventos → `save_scan` persiste `services` → el usuario confirma con `devices link` → `Repository.link_devices` en una transacción.

**seguridad.**
   - la confianza no se hereda; `link` pregunta explícitamente si se confía en la mac nueva.
   - las respuestas mdns son datos no confiables: se limitan en longitud (reutilizar `clean_hostname` y un tope por número y longitud de servicios) y se parsean con los mismos controles contra bucles de puntero que `read_name`.
   - el hostname puede ser suplantado: por eso nunca basta por sí solo para concederse confianza.
   - privacidad: la huella se guarda solo en la base local y se incluye en exportaciones únicamente con `--include-fingerprint`.

**rendimiento.** una consulta udp adicional por host aleatorizado; la comparación es O(nuevos × offline aleatorizados), trivial en redes de cientos de hosts.

**compatibilidad.** funciona sin root (udp unicast). si el parseo mdns falla en una plataforma, el resolvedor continúa con hostname y puertos.

---
####   6. PLAN DE DESARROLLO
| fase | tareas | depende de |
|---|---|---|
| 0. calibración | capturar respuestas mdns reales de varios dispositivos y documentar qué rasgos son estables | — |
| 1. protocolo | `parse_ptr_records`, `scanners/services.py`, tests con respuestas capturadas | 0 |
| 2. núcleo | `core/identity.py` con puntuación y lista de nombres no discriminantes | 0 |
| 3. persistencia | migración, repositorio, tests de enlace/desenlace | — |
| 4. integración | etapa en `pipeline.py`, evento en `diff.py`, `--no-identity` | 1, 2, 3 |
| 5. cli y ui | `candidates`, `link`, `unlink`, marca en tablas | 3, 4 |
| 6. documentación | `descubrimiento-y-scanners.md`, `motor-de-limpieza.md`, `persistencia-y-eventos.md`, `changelog.md` | todas |

**riesgos y mitigación.**
   - *falsos positivos de vínculo:* umbral alto, unicidad del mejor candidato, confianza no heredada.
   - *falsos negativos:* aceptables; el comportamiento por defecto sigue siendo "nuevo".
   - *datos de calibración insuficientes:* fase 0 obligatoria antes de fijar pesos; documentar el resultado.
   - *dependencia de mdns:* degradación elegante, y limitación documentada.

**pruebas necesarias.** parser PTR múltiple con compresión y bucles; puntuación por rasgo y combinada; nombres genéricos sin puntos; dos dispositivos online simultáneos nunca se vinculan; candidato único vs ambiguo; `link`/`unlink` con migración; el vínculo no modifica `trusted`; escaneo completo con servidor mdns simulado (como el servidor tcp local de `tests/test_scanners.py`).

**criterios de aceptación verificables.**
   1. dadas dos fixtures de dispositivo aleatorizado con el mismo hostname y servicios, `score()` ≥ 0.80 y las evidencias listan ambos rasgos.
   2. un candidato ambiguo (dos con puntuaciones a menos de 0.15) no genera vínculo propuesto.
   3. tras `devices link`, `devices show` muestra ambas macs y el alias; `trusted` de la mac nueva sigue en `False` si el usuario respondió que no.
   4. con `--no-identity` el comportamiento es idéntico al actual (los tests existentes pasan sin cambios).
   5. `uv run pytest` y `uv run ruff check app tests` pasan.

**terminada cuando** la fase 0 está documentada con datos reales, los criterios pasan y la limitación de `estado-y-siguientes-pasos.md` sobre macs aleatorizadas se actualiza.

---
####   7. EVOLUCION FUTURA
   - huella dhcp (opción 55 y nombre de host) con la escucha pasiva con `AsyncSniffer` ya prevista en las siguientes fases: es el rasgo más estable y requiere privilegios.
   - banners tls (cn del certificado) como rasgo adicional.
   - clasificación de tipo de dispositivo (móvil, tv, impresora) a partir de la misma huella, útil para el triage (`guided-triage-and-risk-score.md`).
   - exportar la historia por identidad (todas las macs usadas) en json/html.
   - cadena de macs por identidad como base de `presence-rhythm-anomalies.md`, que necesita una identidad estable para agrupar presencias.
