# Rendimiento medido · 0.2.0 · 24 de octubre de 2026

Los datos proceden de `scripts/bench.py`; solo se generan redes simuladas y conexiones de loopback. `benchmarks-anterior.json` conserva las mediciones recibidas del agente anterior; `benchmarks.json` contiene la repetición tras esta continuación. No se ha medido una duración de escaneo físico.

Equipo: {'platform': 'Linux-6.18.56-1-lts-x86_64-with-glibc2.44', 'python': '3.13.13', 'cpus': 12, 'cpu': 'Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz', 'memory_gb': 31.2}.

Cada lectura API se repite 30 veces con TestClient en el mismo proceso. La tabla muestra p95, incluyendo el primer acceso de cada serie; no es latencia de Internet. `first_ms` es la primera petición **de esa serie**, que puede reutilizar resultados de otra ruta anterior. La tabla SQL posterior vacía explícitamente la caché para medir la primera evaluación completa. Las pruebas de navegador y SSE usan un servidor HTTP real en loopback.

| Lectura (p95 ms) | 50 dispositivos | 500 dispositivos | 5.000 dispositivos | 5.000 antes |
|---|---:|---:|---:|---:|
| devices page (50, sorted by ip) | 3.4 | 5.8 | 43.9 | 728.1 |
| devices page sorted by risk | 3.5 | 7.1 | 45.4 | 594.3 |
| devices search q=phone | 2.1 | 3.2 | 6.7 | 393.5 |
| device detail | 2.8 | 4.6 | 30.8 | 288.9 |
| events page (50) | 2.3 | 2.8 | 5.7 | 4.7 |
| events filtered (alerts) | 2.3 | 3.2 | 12.9 | 13.5 |
| summary | 4.1 | 9.1 | 82.9 | 1832.0 |
| review queue | 5.1 | 7.4 | 62.2 | 1044.8 |
| services | 4.9 | 19.3 | 224.0 | 792.7 |
| status | 2.7 | 3.9 | 36.5 | 44.0 |

El benchmark anterior llamaba `q=demo` a una petición que realmente buscaba `phone`; se ha corregido la etiqueta. La carga y la consulta son equivalentes. La mejora de revisión también cambia el tamaño de la respuesta: ahora entrega una página y conserva `total`, en lugar de enviar toda la cola.

| Tamaño de respuesta (5.000 equipos) | Antes | Ahora |
|---|---:|---:|
| review queue | 9,477,134 bytes | 52,380 bytes |
| services | 1,145,825 bytes | 92,910 bytes |
| summary | 15,882 bytes | 13,354 bytes |

| Comprobación con 500 equipos | Antes p95 | Ahora p95 | Objetivo |
|---|---:|---:|---|
| Filtro visual (8 búsquedas distintas) | 259.1 ms | 173.7 ms | <200 ms |
| Escritura persistida → trama SSE (10 cambios) | 511.5 ms | 512.2 ms | <2.000 ms |

El filtro incluye la espera de 75 ms desde la última tecla (antes 150 ms), petición y actualización del DOM. Las 8 búsquedas deben finalizar; el script falla si una no llega a mostrar resultados. SSE mide recepción de la trama, no el repintado posterior de cada vista (que agrupa cambios durante 300 ms).

| Evaluación del inventario | Equipos | Tiempo ms | Sentencias SQL |
|---|---:|---:|---:|
| inventory_uncached | 50 | 6.2 | 7 |
| inventory_cached | 50 | 1.6 | 2 |
| inventory_resorted | 50 | 1.0 | 2 |
| inventory_uncached | 500 | 50.9 | 7 |
| inventory_cached | 500 | 2.7 | 2 |
| inventory_resorted | 500 | 3.5 | 2 |
| inventory_uncached | 5000 | 512.2 | 7 |
| inventory_cached | 5000 | 24.2 | 2 |
| inventory_resorted | 5000 | 27.7 | 2 |

La consulta inicial de 5.000 equipos aún supera 300 ms. La caché no elimina ese coste: se vuelve a pagar al cambiar el inventario o el minuto. Las ordenaciones y páginas siguientes comparten evaluación. Las peticiones API repetidas cumplen el objetivo p95 <300 ms, pero ese objetivo **no se garantiza en frío**.

| Dataset | Eventos | Mediciones | Base MB | RSS del proceso tras API/consultas MB |
|---|---:|---:|---:|---:|
| 50 | 1000 | 5114 | 1.4 | 51.4 |
| 500 | 10000 | 51169 | 11.9 | 61.0 |
| 5000 | 100000 | 220202 | 71.3 | 107.0 |

RSS es una muestra del proceso de benchmark después de cada tamaño, no memoria máxima ni memoria aislada del servidor; incluye Python, generación de datos y bibliotecas. Los tamaños se ejecutan consecutivamente en el mismo proceso. Los datasets contienen 169 escaneos/7 días para 50 y 500 equipos y 73 escaneos/3 días para 5.000. La semilla es determinista; las fechas se anclan al momento de ejecución.

La comparación de almacenamiento con el commit de partida permanece en `benchmarks-anterior.json` → `storage.baseline`; la repetición actual está en `benchmarks.json` → `storage.current`. Usa un dataset equivalente más sencillo (tres escaneos, 100.000 avisos solo en el mayor tamaño), por lo que no debe mezclarse con los tiempos API de las tablas anteriores. No hay un servidor live equivalente en la línea base CLI.

Para reproducir:

```bash
UV_PROJECT_ENVIRONMENT="$HOME/.cache/beacon/venv" uv run python scripts/bench.py --sizes 50,500,5000 --events 100000 --repeat 30
# Opcional: --baseline /ruta/a/checkout/anterior para repetir también almacenamiento del código anterior
```

Los percentiles describen este equipo y esta carga, no todos los equipos. No se ha medido el comportamiento de un /16 físico ni se ha calibrado el riesgo con capturas reales.
