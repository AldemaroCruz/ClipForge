# Propuesta independiente para PostgreSQL de pruebas

La candidata construida conserva PostgreSQL 18.6 y los layers de la base oficial
fijada. Cambia solamente `zlib1g` a
`1:1.3.dfsg+really1.3.1-1+deb13u1` y reconstruye gosu 1.20 desde el commit
`29b939aa5bd4dc588af765b8248f6e39150d2565` con Go 1.27.4. El Dockerfile está en
`config/postgres-ci-security.Dockerfile`. No está seleccionada por el CI actual.

Imagen observada: `clipforge-pg-security:versioned-5eadef4`, configuración
`sha256:a660cf5d31da83d183a3c89aaa9ffaed073ea903cadfd493f6c84c91759b510d`.
El inventario verifica que todos los layers de la base fijada siguen como prefijo
de los layers de esta imagen. La ejecución de gosu devuelve
`1.20 (go1.27.4 on linux/amd64; gc)`.

Se conserva la identidad real emitida por `go install @commit`:
`github.com/tianon/gosu v0.0.0-20261025094355-29b939aa5bd4`. No se convierte en
una versión inventada ni se elimina el módulo del inventario. El build inicial
con módulo `(devel)` quedó descartado y sus resultados no se atribuyen a esta
imagen. Los otros componentes Go observados son `github.com/moby/sys/user v0.4.1`,
`golang.org/x/sys v0.1.0` y `stdlib v1.27.4`.

El commit de gosu identifica la actualización a 1.20 en la
[fuente oficial](https://github.com/tianon/gosu/commit/29b939aa5bd4dc588af765b8248f6e39150d2565).
[Go 1.27.4](https://go.dev/doc/devel/release#go1.27.4) incluye correcciones de
seguridad; el [tracker de Debian para zlib](https://security-tracker.debian.org/tracker/source-package/zlib)
identifica la versión de seguridad trixie utilizada. Estas fuentes justifican
el parche concreto; el resultado se decide con el escaneo de la imagen real.

## Resultado observado

Trivy 0.76.2, fijado al digest utilizado en CI, examinó el archivo Docker de esta
imagen sin red, sin actualizar la DB, sin exclusiones y con severidades
`HIGH,CRITICAL`, `--list-all-pkgs` y `--exit-code 1`. Se copió la DB autorizada,
con `UpdatedAt=2026-11-13T19:05:12.362756469Z`, a scratch propio. No se descargó
otra DB. Inventario independiente, SBOM CycloneDX y SCA coinciden en los
145 paquetes Debian y los cuatro componentes Go.

| Target real | CRITICAL | HIGH | Resultado |
| --- | ---: | ---: | --- |
| Debian 13.7 | 1 | 120 | Bloqueado |
| `usr/local/bin/gosu` | 0 | 0 | Sin HIGH/CRITICAL detectados |

Hay 34 IDs CVE distintos y 121 incidencias paquete/CVE. `zlib1g` no presenta
HIGH/CRITICAL en esta captura. El crítico restante es `CVE-2026-6653` en
`libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3`, sin `FixedVersion` informado.
Los HIGH se distribuyen por fuente: krb5 56, util-linux 36, gnupg2 7,
libxml2 7, ncurses 4, perl 4, sqlite3 3, systemd 2 y acl 1. No se aceptan ni
se ocultan esos hallazgos; cada regla, paquete, severidad, versión y fuente queda
en `postgres-security-review.json` y el reporte Trivy completo.

## Evidencia y reproducción

Captura nueva y externa a la instalación:
`C:\Users\itres\AppData\Local\ClipForge\pg-ci-security\attempt-8c97357a76dd4909abacd1e9630b61b1`.
`reports/` conserva inventario, SBOM, SCA, revisión, metadatos/hash de DB,
versión Trivy, log del build y hashes de las entradas. El recibo corregido es
`capture-context-v2.json`; el primer recibo se conserva, pero su campo de hash
del archivo Docker no era un SHA256 y no se usa como evidencia de integridad.
`inputs/image.tar` conserva exactamente la imagen examinada.

El collector se ejecuta con un nombre propio de candidata y su ID inmutable:

```powershell
python -B scripts/new_pg_security_inventory.py --image clipforge-pg-security:versioned-5eadef4 --image-id sha256:a660cf5d31da83d183a3c89aaa9ffaed073ea903cadfd493f6c84c91759b510d --output NUEVO_INVENTARIO.json
python -B scripts/new_pg_security_review.py --inventory NUEVO_INVENTARIO.json --sbom SBOM.json --scan SCA.json --execution EJECUCION.json --output NUEVA_REVISION.json
python -B -m unittest tests.test_pg_security_proposal -v
```

El probe usa usuario 65534, root filesystem de solo lectura, `--network none`,
sin capacidades ni montajes de datos/credenciales y sin ejecutar el entrypoint
de PostgreSQL. La limpieza exige nombre, ID y etiqueta aleatoria coincidentes.
Las cinco regresiones son sintéticas: identidad real del módulo, rechazo de
versiones antiguas, hash alterado y rechazo por los contratos CI históricos.
La captura/SBOM/SCA anteriores son ejecuciones reales; no son fixtures.

## Decisión pendiente

CI continúa bloqueado. El productor histórico exige gosu 1.19 y el validador
histórico exige el módulo `v1.19.0`; este incremento no los modifica. Integrar
la candidata requiere revisar y actualizar de forma explícita selección,
productor y contrato de validación, conservando todo el inventario y probando
el lifecycle/migraciones/browser con esa misma imagen. También permanecen los
hallazgos Debian señalados. No se cambia distribución, umbral, scanner,
`ignore-unfixed` ni `continue-on-error`.

Esta evidencia corresponde únicamente a la candidata PostgreSQL de pruebas.
No demuestra resultados de la aplicación, herramientas del navegador, imágenes
operativas ni futura VM. No se inició una base de datos ni se leyó estado de
PostgreSQL para obtenerla.
