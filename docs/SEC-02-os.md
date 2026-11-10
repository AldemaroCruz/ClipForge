# SEC-02: componentes CUPS y bloqueos OS de la imagen de navegador

Fecha: 2026-11-10, Guatemala. **El gate continúa bloqueado. No se corrigen,
suprimen o reclasifican CVEs mediante este análisis de componentes.** No se
modificaron dependencias, Dockerfiles, workflows ni los expedientes anteriores.
GitHub Actions no se considera ejecutado por estas comprobaciones locales.

## Imagen y evidencia

Se inspeccionó realmente la imagen de navegador SEC-01 Linux/amd64
`sha256:38d7f04281674ec3c1663104ef89c8488897486722ed9e5ca7401e87ed88542c`.
La identidad se verificó por ID antes de crear un contenedor exclusivo, sin pull,
red, puertos, montajes o acceso a la instalación operativa; raíz readonly,
capacidades eliminadas y `no-new-privileges`. No se iniciaron CUPS, filtros o
pruebas de explotación. La sonda solo leyó archivos, metadatos dpkg y su propio
namespace de procesos; emitió JSON por stdout y terminó con salida 0.

Los artefactos nuevos están en `.ci-local/sec02-6a96aae0/os/`:

- `image-inspection-1/image-identity.txt`, `command.json`, `components.stdout.json`
  y `components.stderr.log`: identidad, comando, restricciones y observaciones
  reales del contenedor; recogidas el 10 de noviembre a las 07:53 de Guatemala.
- `probe_cups_components.py`: sonda stdlib reproducible, sin ejecutar los ELF
  examinados ni abrir conexiones. Su hash se conserva en `command.json`.
- `official-cups-and-chromium-metadata.json`: cuatro respuestas oficiales HTTP
  200, con URL, fecha y SHA-256; distingue declaración de paquetes de inspección
  real de la imagen.
- `debian-tracker-current.json`: consulta HTTP 200 a la API pública Debian a las
  07:49 de Guatemala; contenido filtrado a los 54 CVEs y huella del payload.
- `remaining-os-groups.json`: los otros 52 CVEs y 226 hallazgos, agrupados por
  paquete fuente y enlazados a su estado oficial actual.
- `sec01-input-hashes.json`: hashes de las cinco entradas preservadas SEC-01:
  report y SBOM de `comparison-browser/`, inventarios dpkg, toolchain y binarios.

La lectura de esos inventarios anteriores se utilizó para identificar el
candidato; no sustituyó la inspección nueva de archivos.

## Hallazgos del scanner conservados

Los dos findings siguen atribuidos a `libcups2t64==2.4.10-3+deb13u2`:

| CVE | Severity original | SeveritySource original | Status original | FixedVersion original |
|---|---|---|---|---|
| CVE-2026-34980 | HIGH | nvd | affected | campo ausente |
| CVE-2026-55453 | HIGH | campo ausente | affected | campo ausente |

`DataSource` es Debian Security Tracker en ambos casos. El paquete fuente `cups`
y su versión se resolvieron desde dpkg/SBOM; no se presentan como campos crudos
de esos findings. Los niveles de severidad de los advisories upstream no
reemplazan los valores originales ni modifican el umbral del gate.

## Qué está instalado y qué se observó en el filesystem

| Componente o condición | Evidencia real en la imagen candidata | Límite |
|---|---|---|
| Biblioteca cliente CUPS | `/usr/lib/x86_64-linux-gnu/libcups.so.2` existe; paquete `libcups2t64` instalado, source `cups`, versión `2.4.10-3+deb13u2` | La presencia de la biblioteca no demuestra ni descarta una cadena de explotación completa |
| Scheduler y herramientas servidor | No existen las rutas comprobadas de `cupsd` en `/usr/sbin`, `/sbin`, `/usr/local/sbin`, ni las de `lpadmin` | Observación acotada a esas rutas y a PATH; no es una búsqueda de ejecutables renombrados arbitrariamente |
| Backend y filtros citados | No existen las rutas comprobadas de backend `ipp`, filtro `pstops` o `foomatic-rip`; tampoco `/usr/bin/foomatic-rip` | No se instaló ni ejecutó un servicio para ensayar la vulnerabilidad |
| Configuración, PPD y spool | Ausentes `/etc/cups`, `/usr/lib/cups`, `/usr/libexec/cups`, `/usr/share/cups`, `/run/cups` y `/var/spool/cups`; ausentes rutas comprobadas de archivos `.conf`, PPD y socket | Se registraron 23 rutas y seis árboles concretos, no una prueba universal de ausencia de código equivalente |
| Paquetes servidor | dpkg no los identifica instalados: `cups`, `cups-daemon`, `cups-core-drivers`, `cups-client`, `cups-filters`, `cups-filters-core-drivers`, `foomatic-filters`; `cups-common` devuelve explícitamente `unknown ok not-installed` | Un código 0 de dpkg-query no se interpretó por sí solo como instalado |
| Procesos y sockets del probe | Solo proceso `python`; cero filas de conexiones/listeners en `/proc/net/tcp` y `tcp6` | Corresponde al contenedor de auditoría con entrypoint sustituido y red deshabilitada, no a cualquier modo futuro de ejecutar la imagen |

SHA-256 de `libcups.so.2`:
`4a1b185e46ed19f279a437d16619c0bfec8a0c21a25afc1b3e85320f4d219e4c`.
El listado real `dpkg-query -L libcups2t64` muestra esa biblioteca y archivos de
documentación, ejemplo de cliente y lintian. Coincide con el
[listado oficial del paquete](https://packages.debian.org/trixie/amd64/libcups2t64/filelist),
que por sí solo no habría probado qué otros archivos existen en la imagen.
El campo legado `cupds_on_path: null` de SEC-01 tampoco se usó como prueba
exhaustiva de ausencia del daemon.

## Dependencia real del navegador

Se leyeron directamente las tablas ELF64 `DT_NEEDED`, sin invocar los binarios
ni su loader. Chromium normal conserva dependencia directa de `libcups.so.2`:

| Binario | SHA-256 | DT_NEEDED directo de libcups |
|---|---|---|
| `/opt/ci-browsers/chromium-1248/chrome-linux64/chrome` | `377a9fc07b495c3b8d0ab8ec1fdfd153641759f9756fea34d8dfce4de82f5025` | Sí |
| `/opt/ci-browsers/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell` | `4fa61f0ba0b4f89b7bec242c32ca16d3bccf69dbfef0651924a9ba8fede5f9d6` | No directo |

Las huellas coinciden con el inventario de binarios preservado de SEC-01.
La [declaración oficial de dependencias de Playwright 1.64.1 para Debian 13](https://github.com/microsoft/playwright/blob/v1.64.1/packages/playwright-core/src/server/registry/nativeDeps.ts)
también incluye `libcups2t64`. No se propone quitar la biblioteca: el ejecutable
normal que usan los recorridos existentes la requiere. La ausencia de una
entrada directa en headless shell no es un análisis de sus dependencias
transitivas, una declaración de no afectado o autorización para cambiar de
navegador con el propósito de perder un finding.

## Contraste de los dos advisories

[CVE-2026-34980 / GHSA-4852-v58g-6cwf](https://github.com/OpenPrinting/cups/security/advisories/GHSA-4852-v58g-6cwf)
describe scheduler `cupsd` expuesto, una cola PostScript compartida, trabajos IPP
aceptados, filtros y actualización de la PPD, seguida de ejecución como `lp`.
La cadena descrita utiliza componentes servidor y filtros; **no exige Foomatic**.
La imagen conserva la biblioteca cliente, pero no se observaron los componentes
servidor/configuración en las rutas inspeccionadas. No se intentó explotar la
cadena. El [tracker Debian de esa CVE](https://security-tracker.debian.org/tracker/CVE-2026-34980)
mantiene trixie vulnerable; el fix publicado de otra suite no es un backport
aplicable automáticamente.

[CVE-2026-55453 / GHSA-7hqf-mfhx-7r3v](https://github.com/OpenPrinting/cups/security/advisories/GHSA-7hqf-mfhx-7r3v)
describe datos de una impresora alcanzando el backend IPP, después el flujo de
estado del scheduler y cambios en PPD. La ejecución demostrada depende además
de una cola que use `foomatic-rip`. Backend, scheduler, PPD y ese filtro no se
observaron en las rutas comprobadas. Esa diferencia de condiciones se documenta
sin borrar el finding. El [tracker Debian de esta CVE](https://security-tracker.debian.org/tracker/CVE-2026-55453)
también mantiene trixie vulnerable y no publica aquí un fix para esa suite.

Este contraste limita qué puede afirmarse sobre las cadenas descritas; no es
un dictamen de no afectado, VEX, excepción o falso positivo. Tampoco certifica
todo el código de la biblioteca cliente o todas las variantes de explotación.
La raíz readonly y la red deshabilitada son restricciones efectivas de esta
ejecución, no una corrección del paquete instalado.

## Los otros 52 CVEs OS

La [API oficial Debian](https://security-tracker.debian.org/tracker/data/json),
consultada de nuevo el 10 de noviembre, mantiene abiertos en trixie los 54 CVEs
del navegador: los dos de CUPS y los otros 52. Los 52 restantes abarcan 15
paquetes fuente y 226 hallazgos paquete/CVE:

| Familia de revisión | Paquetes fuente | CVEs únicos | Hallazgos |
|---|---|---:|---:|
| Multimedia | ffmpeg, libsndfile, tiff | 20 | 156 |
| Bibliotecas de formatos y datos | libxml2, cjson, expat, sqlite3 | 20 | 20 |
| Base del sistema | util-linux, acl, ncurses, systemd, perl | 8 | 44 |
| Bibliotecas X11 | libx11, libxi, libxrender | 4 | 6 |

Opciones concretas dentro del alcance actual:

1. Conservar el bloqueo y los IDs/huellas de este candidato. No hay un fix trixie
   aplicable verificado para esos 52 CVEs en la respuesta consultada; no actualizar
   snapshots o dependencias esperando que el conteo desaparezca.
2. Seguir los 15 paquetes fuente y conservar respuestas oficiales fechadas. Un
   backport futuro necesita candidato APT firmado de la misma suite, comparación
   dpkg, diagnóstico y autorización antes de cambiar la resolución congelada.
3. Preparar regresiones según el grupo que reciba un fix: multimedia requiere
   decode/audio/render/subtítulos/ZIP/recuperación; formatos y datos requieren
   sus fixtures negativos y la suite completa; base/X11 exige además lanzamiento
   real de Chromium y los seis recorridos HTTP. Ninguna prueba verde elimina un
   finding pendiente de remediar.
4. Mantener aislamiento de CI y entradas sintéticas; registrar esas condiciones
   separadamente de los CVEs. No importar sid, cambiar distribución, recompilar,
   retirar componentes necesarios o introducir una excepción para abrir el gate.

En este incremento no existe una corrección técnica verificada y autorizada que
cierre esos 52 CVEs. Las alternativas anteriores conservan evidencia y preparan
un cambio posterior; no presentan las restricciones de ejecución como remedio.

## Ejecutado, pendiente y límites

Ejecutado: contraste de inventarios SEC-01; consulta oficial actual de 54 CVEs;
cuatro respuestas oficiales adicionales; inspección nueva readonly de archivos,
paquetes, dependencias ELF, procesos y tablas TCP del candidato fijado.
La inspección no modificó la imagen ni inició servicios de impresión.

No ejecutado: PoCs o reproducción de explotación, nueva suite funcional, nuevo
build, nuevos scanners/SBOM o GitHub Actions. Los scanners SEC-01 siguen siendo
evidencia conservada, no ejecuciones nuevas de SEC-02. Las limitaciones de SCA
para los binarios vendorizados Chromium/Node/FFmpeg auxiliar continúan abiertas.
Se mantienen los dos findings CUPS, los otros 52 CVEs OS y el bloqueo completo.
