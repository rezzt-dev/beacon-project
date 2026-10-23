###  BEACON PROJECT  |  ARQUITECTURA
> cómo está organizado el código de la versión cli y cómo fluye un escaneo de principio a fin.
---
####   ARBOL DE DIRECTORIOS
```
beacon-project/
├── pyproject.toml              # metadatos, dependencias, entry point `beacon`, pytest y ruff
├── app/
│   ├── app.py                  # lanzador original: `python app/app.py`
│   └── beacon/
│       ├── __init__.py         # versión del paquete
│       ├── __main__.py         # `python -m beacon`
│       ├── config.py           # rutas de datos (BEACON_HOME, BEACON_DB) y constantes
│       ├── pipeline.py         # orquestador de un escaneo completo
│       ├── core/               # modelos, limpieza, diff, eventos, fabricantes, riesgo, identidad y presencia
│       ├── scanners/           # red: arp, icmp, puertos, latencia, hostnames, servicios mdns
│       │   └── protocols/      # parsers propios de dns/mdns y netbios
│       ├── storage/            # sqlite: esquema, migraciones y repositorio
│       ├── ui/                 # rich: consola, tablas, progreso y vista en vivo
│       ├── export/             # json, csv y html
│       └── cli/                # typer: aplicación, contexto y comandos
└── tests/                      # pytest, sin acceso a red
```
---
####   CAPAS Y RESPONSABILIDADES
la arquitectura sigue la división definida en `general-info.md`: los scanners producen datos crudos, el core los limpia y genera eventos, storage guarda el estado y ui/export consumen los eventos.

| capa | responsabilidad | depende de |
|---|---|---|
| `scanners/` | hablar con la red y devolver `Observation` crudas, sin interpretarlas. | `core.models` |
| `core/` | modelos (`dataclass`), limpieza, deduplicación, estimación de so, fabricantes, detección de cambios, puntuación de riesgo (`risk.py`), resolución de identidad (`identity.py`) y perfiles de presencia (`presence.py`). todo puro, sin red ni base de datos. | nada externo |
| `storage/` | persistir dispositivos, puertos, sesiones de presencia, identidades, escaneos y eventos en sqlite. todo el sql vive en `Repository`. | `core` |
| `pipeline.py` | coordinar un escaneo: descubrir → limpiar → enriquecer → comparar → persistir → publicar. | todas |
| `ui/` | renderizar con `rich`: tablas, progreso y la vista de `watch`. | `core` |
| `export/` | convertir dispositivos y eventos a json, csv y html. | `core` |
| `cli/` | traducir argumentos de terminal en llamadas al pipeline y al repositorio. | todas |

`core/` no importa nada de red ni de terminal, por lo que toda la lógica de negocio se prueba sin sockets. si en el futuro un scanner se queda corto de rendimiento, puede reescribirse en rust con `pyo3` manteniendo la misma salida (`list[Observation]`).
---
####   FLUJO DE UN ESCANEO
```
resolve_target ──► _discover ──► CleaningEngine.merge ──► _enrich ──► detect_changes ──► presencia ──► save_scan ──► EventBus
 (interfaz y red)   (observaciones   (dispositivos por mac,    (puertos, latencia,  (eventos frente a   (anomalías    (sqlite,     (ui, alertas,
                    crudas)          conflictos, descartes)    hostnames, ttl,      la base e identi-   de perfil)    atómico)     exportación)
                                                               servicios mdns)      dades candidatas)
```
   1. **resolución del objetivo:** `scanners/network.py` elige la interfaz (la que usa la ruta por defecto) y la red a escanear; rechaza redes mayores de `/16`.
   2. **descubrimiento:** según el modo, barrido arp con scapy o barrido icmp + lectura de la tabla arp + confirmación tcp de entradas antiguas. también se añaden todas las ips locales del equipo como observaciones `local`.
   3. **limpieza:** `CleaningEngine` normaliza, filtra y fusiona por mac (ver `motor-de-limpieza.md`).
   4. **enriquecimiento:** por dispositivo, en paralelo y con semáforos: puertos, latencia (que también aporta ttl), hostname y, solo en macs aleatorizadas, los servicios mdns que anuncia (omitible con `--no-identity`).
   5. **detección de cambios:** `IdentityResolver` busca, entre los aleatorizados que desaparecieron en este mismo escaneo, a quién se parece cada mac aleatorizada nueva; `detect_changes` compara contra el inventario guardado y genera eventos (un `identity-candidate` sustituye al `new-device` correspondiente). un inventario vacío se trata como línea base: sin alertas masivas.
   6. **historial:** se conservan alias, confianza, identidad, `first_seen` y los datos que este escaneo no refrescó (por ejemplo, los puertos si no se pidió `--ports`).
   7. **presencia:** para los dispositivos que vuelven o desaparecen, se carga su perfil de las sesiones guardadas y `detect_anomalies` añade `unusual-presence` y `routine-broken` (omitible con `--no-presence`).
   8. **persistencia:** `Repository.save_scan` guarda todo, también las sesiones de presencia, en una única transacción.
   9. **publicación:** los eventos se publican en el `EventBus`; `watch` los usa para la vista en vivo y el aviso sonoro.
---
####   DECISIONES DE DISEÑO
   - **`dataclass` en lugar de `pydantic`:** los modelos son internos y no se validan contra entradas externas; `dataclass(slots=True)` evita una dependencia pesada y es más rápido. la validación de datos de red la hace el motor de limpieza.
   - **la mac es la identidad:** la clave de un dispositivo es su mac normalizada; si no hay mac (caso raro en lan), la clave es `ip:<dirección>`.
   - **typer + rich:** typer da tipado, ayuda y autocompletado; rich cubre tablas, progreso y `Live` sin necesitar una tui completa. la tui con `textual` queda para una fase posterior.
   - **asyncio en todo el escaneo:** las operaciones bloqueantes (scapy `srp`, `gethostbyaddr`) se ejecutan en executors para no frenar el bucle de eventos.
   - **protocolo `ProgressReporter`:** el pipeline no conoce `rich`; recibe un objeto con `stage()` y `advance()`. la cli usa barras de progreso y `watch` usa su propia vista.
   - **inyección de dependencias ligera:** `AppContext` crea bajo demanda el repositorio y la base de fabricantes, de modo que comandos como `--version` no abren la base de datos.
---
