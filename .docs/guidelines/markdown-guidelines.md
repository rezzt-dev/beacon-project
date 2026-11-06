# MARKDOWN GUIDELINES

## ESPAÑOL DE ESPAÑA: USO OBLIGATORIO DE Ñ

- todo texto en castellano debe usar español de españa (`es-ES`) y su ortografia, tambien en titulos y cuerpos de commits, changelogs, pull requests, merges y documentacion
- escribir siempre `ñ` en las palabras que la llevan y `Ñ` cuando corresponda la mayuscula; nunca sustituirlas por `n` o `N`
- la `ñ` es una letra distinta de la `n`; las instrucciones «sin acentos» o «sin tildes» solo afectan a las tildes de las vocales y nunca permiten eliminar la eñe
- ejemplos correctos: `añadir`, `diseño`, `año`, `tamaño`, `contraseña`, `español`, `españa` y `AÑADIDO`; sus formas con `n` son incorrectas cuando se refieren a esas palabras españolas
- conservar literalmente rutas, urls, nombres de archivo, identificadores tecnicos y texto de otros idiomas; esta regla no autoriza renombrarlos ni aplicar sustituciones indiscriminadas
- antes de entregar o publicar texto en castellano, revisar que ninguna palabra haya perdido su `ñ` o `Ñ`; esta regla prevalece sobre cualquier normalizacion a ascii o instruccion generica de eliminar acentos


> instrucciones para cualquier agente de ia (o persona) que cree o edite un
> fichero markdown en este repositorio. se aplica siempre que se pida algo
> equivalente a:
>
> *"genera el fichero `.md` de ..."*
>
> y, de forma general, **cada vez que se vaya a crear o modificar un fichero
> markdown en este repositorio**, se haya pedido explícitamente o no.

---

## REGLA GENERAL

todos los ficheros markdown del repositorio siguen el mismo formato de texto:

- **contenido en minúsculas y con los acentos ortográficos necesarios.** esto
  incluye párrafos, items de listas, celdas de tablas, citas y notas.
- **títulos y encabezados en mayúsculas y sin acentos (conservando siempre `ñ` y `Ñ`).** esto aplica a todos
  los niveles (`#`, `##`, `###`, `####`...).

---

## DETALLES DE LA REGLA

- la primera letra de una frase va en minúscula, también tras un punto. no se
  usan mayúsculas iniciales en el contenido.
- los acentos ortográficos se mantienen siempre en el contenido (`configuración`,
  `qué`, `código`), y se eliminan siempre en los títulos (`CONFIGURACION`,
  `QUE`, `CODIGO`).
- la `ñ` no es un acento: se conserva en el contenido y pasa a `Ñ` en los
  títulos (`diseño` → `DISEÑO`).
- siglas, nombres propios y marcas se escriben en minúsculas en el contenido
  (`python`, `github`, `arp`, `sqlite`) y en mayúsculas en los títulos.
- el formato aplica por igual a los textos en castellano y en inglés.

---

## EXCEPCIONES

el formato **no** se aplica a contenido que debe conservarse literal:

- bloques de código y código en línea (entre backticks): comandos, rutas,
  nombres de ficheros e identificadores se escriben tal cual son.
- urls y nombres de ramas, tags o etiquetas.
- el texto legal de `license.md`, que sigue la misma regla de minúsculas y
  acentos pero no se resume ni se reformula.

si un título incluye un fragmento entre backticks, ese fragmento se conserva
literal y el resto del título va en mayúsculas sin acentos (conservando siempre `ñ` y `Ñ`).

---

## EJEMPLOS

correcto:

```
## ARQUITECTURA Y DISEÑO

el módulo `core/` normaliza las direcciones mac y genera los eventos.
```

incorrecto:

```
## Arquitectura y Diseño

El módulo `core/` normaliza las direcciones MAC y genera los eventos.
```

---

## PRECEDENCIA

esta guía es la referencia de formato para cualquier fichero `.md`. si otro
documento del repositorio indica "sin acentos (conservando siempre `ñ` y `Ñ`)" para el contenido, prevalece
esta guía: contenido con acentos ortográficos, títulos sin acentos (conservando siempre `ñ` y `Ñ`).
