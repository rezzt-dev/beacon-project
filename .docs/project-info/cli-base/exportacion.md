###  BEACON PROJECT  |  EXPORTACION
> formatos de salida, exportación en vivo con preview y medidas de seguridad. código en `app/beacon/export/`.
---
####   FORMATOS
| formato | fichero | contenido |
|---|---|---|
| json | `json_export.py` | documento con generador, fecha, red, dispositivos completos (latencia, puertos, fuentes) y eventos. es el mismo modelo que `--json`. |
| csv | `csv_export.py` | una fila por dispositivo con columnas planas (latencia media, jitter, pérdida, puertos `22/tcp 80/tcp`...), pensado para hojas de cálculo. |
| html | `html_export.py` | informe autocontenido (sin recursos externos) con tarjetas de resumen, tabla de dispositivos y tabla de eventos. respeta el modo claro/oscuro del sistema. |

el formato se deduce de la extensión (`.json`, `.csv`, `.html`/`.htm`) o se fuerza con `--format`.
---
####   ORIGENES DE LA EXPORTACION
   - `beacon scan -o fichero`: exporta el resultado de ese escaneo y sus eventos.
   - `beacon export fichero`: exporta el inventario guardado (online y offline, o solo online con `--online`) y los últimos eventos.
   - `beacon watch -o fichero`: reescribe el fichero tras cada ciclo con el inventario completo y los últimos 100 eventos.
---
####   EXPORTACION EN VIVO CON PREVIEW
con `beacon watch -o vivo.html`, el html incluye `<meta http-equiv="refresh">` con el intervalo de escaneo, así que basta con abrirlo en el navegador para tener una tabla en vivo que se actualiza sola mientras la terminal muestra la vista de `rich`.

la escritura es **atómica** (fichero temporal en el mismo directorio + `os.replace`), de modo que un navegador u otro programa nunca lee un fichero a medio escribir.
---
####   SEGURIDAD
los datos exportados vienen de la red (hostnames, banners) y pueden estar manipulados por un dispositivo hostil:
   - **html:** todos los valores se escapan con `html.escape`; un hostname como `<script>` se muestra como texto.
   - **csv:** las celdas que empiezan por `=`, `+`, `-`, `@`, tabulador o retorno de carro se prefijan con `'` para evitar la inyección de fórmulas en excel, libreoffice o google sheets.
---
