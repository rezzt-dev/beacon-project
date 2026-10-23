# COMMIT GUIDELINES

> instrucciones para cualquier agente de ia (o persona) que redacte el titulo
> y la descripcion de un commit de git en este repositorio. se aplica siempre
> que se pida algo equivalente a:
>
> *"sacame el titulo y la descripcion para el commit con los cambios
> realizados desde el ultimo commit. fijate en los anteriores commits para
> que tengan el mismo formato."*
>
> y, de forma general, **cada vez que se vaya a crear un commit en este
> repositorio**, se haya pedido explicitamente o no.

---

## FORMATO FIJO DEL TITULO

```
<prefijo> | <resumen corto en imperativo>
```

el separador es siempre espacio, barra vertical, espacio: ` | `. el
`<prefijo>` es siempre una de estas cinco palabras, en minusculas, y nunca
se combinan ni se inventan otras nuevas:

| prefijo | cuando usarlo |
|---|---|
| **update** | trabajo normal hacia adelante: se añade o mejora una funcionalidad, contenido o documento existente. es el prefijo por defecto. |
| **fix** | se corrige un error o comportamiento incorrecto detectado durante el desarrollo, sin urgencia de publicacion inmediata. |
| **hotfix** | se corrige algo urgente que afecta a una version ya publicada o a un bloqueo critico. debe usarse solo cuando la correccion es realmente urgente. |
| **changes** | cambios estructurales o no funcionales: reorganizar carpetas, renombrar ficheros, tocar configuracion o tooling, dependencias. no anade funcionalidad ni corrige un bug. |
| **changelog** | el unico proposito del commit es editar `changelog.md` (por ejemplo, al cerrar una version). |

ejemplos de titulos correctos:

```
update | añadir vista previa de mapeo de columnas al asistente de importación csv
fix | detección de duplicados fallando en filas con importes negativos
hotfix | fallo al iniciar cuando falta el archivo de perfil de importación
changes | reorganizar la documentación en la subcarpeta project-context
changelog | cerrar la sección de changelog para la versión mvp fase 0
```

---

## FORMATO DE LA DESCRIPCION (CUERPO)

- el cuerpo es siempre **una lista de markdown no numerada**: cada item empieza
  por `-`. nunca se usan listas numeradas ni parrafos sueltos.
- cada item es un bloque logico en imperativo, escrito como **una sola linea
  continua**, sin saltos de linea internos: no son esteticos ni utiles, deja
  que el cliente de git lo ajuste. no se dejan lineas en blanco entre items.
- usa markdown dentro de cada item: nombres de ficheros, rutas, comandos e
  identificadores siempre entre backticks.
- explica el que y el por que, no el detalle linea a linea.
- cierra con una linea en blanco y la linea de atribucion que corresponda al
  entorno.

---

## COMO PRESENTAR EL RESULTADO

al responder con el titulo y la descripcion hay que usar **bloques de codigo
separados**: uno para el titulo del commit y otro para el cuerpo del commit (mas
otro para el fragmento del changelog). nunca se juntan el titulo y el cuerpo en
el mismo bloque.