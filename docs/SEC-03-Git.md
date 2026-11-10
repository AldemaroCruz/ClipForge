# SEC-03: preparación de Git y selección del primer commit

**Nota posterior GIT-01:** el usuario aclaró que solo creó el repositorio web;
no ejecutó los comandos sugeridos por GitHub. Autoriza ahora el arranque en
`ci/bootstrap-sec03`, las exclusiones mínimas, la selección explícita y el envío
tras verificar identidad/autenticación/visibilidad, remoto vacío y scan exacto
del índice. No se presupone `main` ni se crea un PR sin base. El cuerpo siguiente
conserva el registro de preparación SEC-03 y sus comandos entonces propuestos;
el nombre de rama vigente para GIT-01 es `ci/bootstrap-sec03`.

Fecha: 2026-11-10, Guatemala. Carpeta única autorizada:
`C:\Users\itres\Desktop\clipforge-mvp`.
**No se inicializó Git, añadió contenido al índice, configuró identidad,
creó un commit, conectó un remoto o ejecutó push.** El estado de los gates de
seguridad se conserva; esta preparación no declara CI verde.

## Ubicación comprobada mediante metadatos

Se comprobó exclusivamente la entrada `.git` de cada ubicación, sin enumerar
el contenido de esas carpetas ni leer configuración, HEAD o credenciales:

| Carpeta | Entrada `.git` |
|---|---|
| `C:\Users\itres\Desktop\clipforge-mvp` | Ausente |
| `C:\Users\itres\Desktop` | Ausente |
| `C:\Users\itres` | Ausente |
| `C:\Users` | Ausente |
| `C:\` | Ausente |

No fue necesario ejecutar `git rev-parse` para buscar un repositorio existente.
La eventual inicialización debe crear el repositorio exactamente dentro de
`clipforge-mvp`; el Escritorio, perfil del usuario y demás ancestros no forman
parte del alcance. La copia `C:\Users\itres\source\repos\clipforge` no se
inspeccionó ni modificó.

## Lista explícita propuesta

La selección parte de las 123 rutas del manifiesto preservado
`.ci-local/sec02-6a96aae0/final-source/source-scan-manifest.json`. Se añaden
únicamente estas cuatro rutas de SEC-03:

```text
tests/test_capture_runtime.py
docs/SEC-03.md
docs/SEC-03-SAST-policy.md
docs/SEC-03-Git.md
```

La lista resultante contiene **127 rutas de archivos**, sin directorios ni
globs. Sus formatos exactos están fuera de la selección versionable:

- `.ci-local/sec03-e214edcb/git/selection-paths.txt`: UTF-8 sin BOM, una ruta
  relativa POSIX por línea, ordenada y con LF.
- `.ci-local/sec03-e214edcb/git/selection-paths.nul`: las mismas 127 rutas
  UTF-8, separadas y terminadas por NUL para `--pathspec-file-nul`.
- `selection-audit.json`: procedencia, hashes de las listas, comprobaciones de
  nombres y metadatos/enlaces, archivos nuevos pendientes de existir si los hay.
- `git-location-metadata.json`: comprobación dirigida de las cinco entradas
  `.git`; no contiene información de configuración Git.

Antes de consultar metadatos de los archivos seleccionados se validan todas las
rutas del manifiesto y las cuatro adiciones: relativas, normalizadas, sin
traversal, ADS, comodines o componentes privados. Después se comprueban los
componentes de cada ruta dentro del proyecto, rechazando symlinks/reparsepoints.
Solo `.env.ai.example` en la raíz se admite como ejemplo. No se abren contenidos
de credenciales, datos, modelos, videos, respaldos o estados Terraform.

El manifiesto SEC-02 fija los nombres de partida; sus hashes históricos no se
presentan como hashes del contenido SEC-03 todavía en edición. La selección
debe congelarse, verificarse y pasar el scanner de secretos sobre su snapshot
antes de cualquier `git add`. El coordinador ejecuta esa validación con
`prepare_ci_scan.py`; esta revisión no la sustituye.

## Revisión estática de .gitignore

El archivo actual ya excluye datos, caché, respaldos, releases, evidencias,
restauraciones, resultados CI, estados/planes Terraform y ubicaciones locales
conocidas de credenciales. Preserva explícitamente `.env.ai.example`.
La selección propuesta no contiene ninguna ruta privada ni una de esas salidas.

Hay diferencias entre esa política y los patrones actuales que conviene cerrar
en una edición autorizada separadamente:

| Política | Brecha estática observada | Propuesta mínima, todavía no aplicada |
|---|---|---|
| Excluir archivos dotenv salvo el ejemplo raíz | `.env` y `.env.*` no cubren nombres como `.envrc`; la excepción sin `/` inicial también puede alcanzar ejemplos en subcarpetas | Sustituir esas tres reglas por `.env*` seguida de `!/.env.ai.example` |
| No versionar medios privados o archivos exportados | Se excluyen sus carpetas operativas, pero no hay patrones generales de videos/audio/ZIP/TAR colocados fuera de ellas | Añadir extensiones de medios y archivos generados que no aparecen en las 127 rutas seleccionadas |
| No versionar claves o contenedores de credenciales | Las ubicaciones conocidas están protegidas, pero faltan patrones como `*.pem`, `*.key`, `*.p12`, `*.pfx`; varios directorios de credenciales solo están anclados a la raíz | Añadir esas extensiones y estudiar patrones de directorio coherentes con el rechazo de privados en cualquier nivel |

Ejemplo del ajuste dotenv propuesto, en sustitución de las reglas actuales y
manteniendo este orden:

```gitignore
.env*
!/.env.ai.example
```

Para medios/archivos generados, el ajuste acotado propuesto es `*.mp4`, `*.mov`,
`*.mkv`, `*.webm`, `*.wav`, `*.mp3`, `*.flac`, `*.zip`, `*.tar`, `*.tar.gz`,
`*.tgz` y `*.7z`. No se propone ignorar todos los recursos gráficos de la app.
No se descubrieron ni abrieron archivos privados para fundamentar estas brechas:
se trata de comparar patrones fuente con la política documentada.

No se modificó `.gitignore`. Tampoco se ejecutó `git check-ignore`: todavía no
hay un repositorio y no se creará uno para ensayar los patrones. Su semántica
efectiva queda pendiente de comprobar después de una inicialización autorizada.
Ningún ignore protege frente a un `add --force`; la selección explícita y el
scanner que rechaza nombres privados siguen siendo obligatorios.
La interpretación de anclaje, negación y comodines se contrastó con la
[documentación oficial de gitignore](https://git-scm.com/docs/gitignore);
esa lectura no se presenta como un ensayo de Git sobre esta carpeta.

## Comandos propuestos, no ejecutados

Requieren autorización posterior para crear el repositorio y, por separado,
para escribir índice/commit. Antes de iniciar, comprobar que no hay variables
Git de redirección de repositorio, sin imprimir valores ni consultar variables
de credenciales. Detenerse si la ubicación Git resultante difiere del proyecto.
En particular, quedan por comprobar las presencias de `GIT_DIR`, `GIT_WORK_TREE`,
`GIT_COMMON_DIR`, `GIT_OBJECT_DIRECTORY` y `GIT_ALTERNATE_OBJECT_DIRECTORIES`.
La [documentación de git init](https://git-scm.com/docs/git-init) confirma que
algunas variables pueden redirigir la ubicación que se inicializa.

```powershell
git -C 'C:\Users\itres\Desktop\clipforge-mvp' init --initial-branch=main
git -C 'C:\Users\itres\Desktop\clipforge-mvp' rev-parse --show-toplevel
```

El siguiente paso requiere congelar la selección y verificar su snapshot/scan.
El [formato NUL de git add](https://git-scm.com/docs/git-add) conserva los nombres
literales; el comando también solicita explícitamente `--literal-pathspecs`.

```powershell
git --literal-pathspecs -C 'C:\Users\itres\Desktop\clipforge-mvp' add --pathspec-from-file='C:\Users\itres\Desktop\clipforge-mvp\.ci-local\sec03-e214edcb\git\selection-paths.nul' --pathspec-file-nul
git -C 'C:\Users\itres\Desktop\clipforge-mvp' diff --cached --name-only -z
git -C 'C:\Users\itres\Desktop\clipforge-mvp' diff --cached --stat
git -C 'C:\Users\itres\Desktop\clipforge-mvp' diff --cached --check
```

Comparar los nombres del índice con las 127 rutas exactas, sin extras ni
ausencias; revisar el diff de contenido. No usar `git add .`, `git add -A` o
`--force`. El fichero de pathspec permanece fuera de la selección y no debe
añadirse al índice.

La identidad real de autor y committer sigue pendiente de verificar con el
usuario. No se inventó nombre/correo ni se ejecutó `git config`. Tras esa
verificación, revisión del índice y autorización del commit, el comando
propuesto es:

```powershell
git -C 'C:\Users\itres\Desktop\clipforge-mvp' commit -m 'chore: versionar fuentes y controles de CI de ClipForge'
```

No se proponen comandos de remoto, autenticación o push en este incremento.
Un commit local no acredita GitHub Actions ejecutado ni cierra los bloqueos de
seguridad conservados en los informes.
