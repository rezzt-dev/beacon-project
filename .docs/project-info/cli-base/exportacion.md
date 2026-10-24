###  BEACON PROJECT  |  EXPORTACION
> formatos de salida, exportación en vivo con preview y medidas de seguridad. código en `app/beacon/export/`.
---
####   FORMATOS
| formato | fichero | contenido |
|---|---|---|
| json | `json_export.py` | documento con generador, fecha, red, dispositivos completos (latencia, puertos, fuentes) y eventos. es el mismo modelo que `--json`. |
| csv | `csv_export.py` | una fila por dispositivo con columnas planas (latencia media, jitter, pérdida, puertos `22/tcp 80/tcp`...), pensado para hojas de cálculo. |
| html | `html_export.py` | informe autocontenido (sin recursos externos): resumen en una frase, bloque de dispositivos sin confianza con su riesgo, tabla de dispositivos con filtros, búsqueda y orden, y lista de eventos filtrable por severidad. respeta el modo claro/oscuro del sistema y se adapta a móvil. |

el formato se deduce de la extensión (`.json`, `.csv`, `.html`/`.htm`) o se fuerza con `--format`.
---
####   ORIGENES DE LA EXPORTACION
   - `beacon scan -o fichero`: exporta el resultado de ese escaneo y sus eventos.
   - `beacon export fichero`: exporta el inventario guardado (online y offline, o solo online con `--online`) y los últimos eventos.
   - `beacon watch -o fichero`: reescribe el fichero tras cada ciclo con el inventario completo y los últimos 100 eventos.
---
####   EXPORTACION EN VIVO CON PREVIEW
con `beacon watch -o vivo.html` (o `scripts/beacon-live.sh`, que además abre el navegador), basta con abrir el fichero para tener una web en vivo que se actualiza sola mientras la terminal muestra la vista de `rich`. `watch` añade a la exportación la interfaz, el modo, la duración del escaneo y el intervalo, que la página usa para saber cuándo habrá datos nuevos.

| parte | qué hace |
|---|---|
| barra de estado | red, interfaz y modo; estado `live` con el tiempo desde la última actualización y la cuenta atrás, una línea de progreso hasta la siguiente comprobación y un botón para pausar (tecla `p`). |
| recarga | la página se recarga cuando el siguiente escaneo debería haber reescrito el fichero (`generado + intervalo + duración`); si al recargar sigue igual, lo vuelve a mirar a los 5 segundos. conserva el scroll, el filtro, la búsqueda, el orden y el foco. |
| datos obsoletos | si no llega nada en `3 × intervalo`, el estado pasa a `stale` y pregunta si `beacon watch` sigue en marcha, en lugar de mostrar datos viejos como si fueran actuales. |
| lo nuevo | los dispositivos y eventos que aparecen después de abrir la pestaña quedan resaltados con la etiqueta `new` hasta pulsar "mark as seen". |
| atención | los dispositivos online sin confianza aparecen arriba, del más al menos arriesgado, con los motivos de su riesgo y el comando para decidir. el título de la pestaña muestra cuántos son y el favicon cambia a rojo. |
| tabla | estado y confianza, dirección (ip y mac), hostname (con su fuente: `dns`, `router`, `mdns`, `netbios` o `local`), dispositivo (alias, etiquetas y fabricante), so, latencia, puertos (los de administración o en claro, destacados), riesgo y última vez visto en tiempo relativo. filtros `all`, `online`, `untrusted`, `open ports` y `offline` con su recuento, búsqueda (tecla `/`) y orden por columna. en móvil cada fila pasa a una ficha de etiqueta y valor. |
| eventos | hora local, severidad escrita y con color, tipo y mensaje, con filtro por severidad. |

sin javascript la página sigue funcionando: una etiqueta `<meta http-equiv="refresh">` dentro de `<noscript>` mantiene el autorrefresco y la tabla se muestra completa. una exportación normal (`scan -o`, `export`) genera la misma página como `snapshot`, sin recarga.

la escritura es **atómica** (fichero temporal en el mismo directorio + `os.replace`), de modo que un navegador u otro programa nunca lee un fichero a medio escribir.
---
####   SEGURIDAD
los datos exportados vienen de la red (hostnames, banners) y pueden estar manipulados por un dispositivo hostil:
   - **html:** todos los valores se escapan con `html.escape`, también dentro de atributos; un hostname como `<script>` se muestra como texto. los datos viajan en el propio html (atributos `data-*`), nunca como json dentro de un `<script>`.
   - **política de contenido:** la página declara una `Content-Security-Policy` con `default-src 'none'` y solo permite el estilo y el script en línea cuyo hash sha-256 coincide con el de `html_export.py`. si un fallo de escape dejara pasar una etiqueta, el navegador no la ejecutaría. tampoco se carga nada de la red (ni fuentes ni imágenes), así que funciona sin conexión y no filtra la visita a terceros.
   - **csv:** las celdas que empiezan por `=`, `+`, `-`, `@`, tabulador o retorno de carro se prefijan con `'` para evitar la inyección de fórmulas en excel, libreoffice o google sheets.
---
