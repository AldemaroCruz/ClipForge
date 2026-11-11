# AUTH-01: cuentas y espacios privados en desarrollo local

AUTH-01 añade autenticación a FastAPI y al frontend existente, con PostgreSQL
local, sin nuevas suscripciones. La instalación operativa v0.4.2 se conserva.
Publicación, release, despliegue y commit/push no están autorizados.
Pro/ESM y la comparación de distribuciones quedan aplazados; SEC-05 permanece
intacto y no forma parte del patch de este incremento.

## Funcionalidad y límites

Cada usuario tiene un espacio privado. PostgreSQL almacena usuarios,
pertenencias, propiedad de proyectos, sesiones y límites de login; los medios
y documentos editoriales siguen en el almacén de archivos de la candidata.
El servidor asigna propietario/espacio al crear un proyecto. No se acepta un
rol o propietario enviado por el cliente ni se asignan archivos antiguos a
quien inicie sesión. Una pertenencia ausente o recurso sin propietario se deniega.

`AuthenticationBoundary` comprueba sesión/origen/CSRF antes de consumir un upload.
La dependencia global vuelve a comprobar el `job_id` resuelto por FastAPI antes
de entrar al endpoint. Las bibliotecas y métricas se filtran por propietario;
plantillas personalizadas se guardan en el espacio privado. Clips, originales,
subtítulos, thumbnails, exports, ZIP y HTTP Range comparten el control de acceso.
Las respuestas privadas usan `no-store` para no reutilizar contenido de otra
sesión desde la caché del navegador. El último proyecto recordado se separa por
usuario; no se guardan tokens en localStorage.

El primer administrador se crea expresamente con una herramienta local.
`users:manage` permite crear usuarios normales y desactivarlos, sin acceso global
al contenido. No hay registro público ni endpoint para autopromoción de roles.
Las pantallas `/login` y `/account` ofrecen inicio/cierre de sesión, cuenta,
cambio de contraseña y administración mínima.

Las contraseñas usan Argon2id de `argon2-cffi` (64 MiB, tres iteraciones,
paralelismo cuatro), de 12 a 128 caracteres. Sesiones aleatorias de 256 bits,
hash SHA-256 almacenado, expiración absoluta de 12 horas por defecto y rotación
al autenticar. Logout revoca la sesión actual; cambio de contraseña y
desactivación revocan todas las del usuario. No se guardan identificadores
secretos de sesión en claro en la base.

Cookies HttpOnly y SameSite Strict. El perfil predeterminado requiere HTTPS y
Secure. Solo `local-http`, con origen loopback exacto, permite HTTP explícito.
La comprobación CSRF usa desafío previo al login y token asociado a la sesión,
además de Origin exacto; no confía en X-Forwarded-For. Cinco fallos por identidad
y 30 por dirección en 15 minutos bloquean temporalmente; hay límite adicional
de emisión de desafíos. Los errores de login no distinguen cuenta inexistente,
desactivada o contraseña incorrecta. Contraseñas/cookies/tokens no se registran.

Esto sigue siendo un proceso Uvicorn y un ejecutor multimedia en threads.
No cancela trabajo nativo ya iniciado al revocar una sesión. No implementa MFA,
correo externo, OAuth, recuperación de contraseña, registro público, organizaciones
compartidas o worker separado. El aislamiento de cuentas no reemplaza la
remediación del decoder ni aprueba exposición a Internet.

## Iniciar una candidata propia

La candidata de esta entrega ya está activa en **http://127.0.0.1:54125/login**.
No requiere reconstruirla. Para crear su primer administrador, desde una consola
interactiva en la carpeta del proyecto:

```powershell
$authState = 'C:\Users\itres\AppData\Local\Temp\clipforge-auth01-ec509377-v1c68pet\infra\development-state-2'
python -B scripts/dev_local.py admin --state $authState --username mi_admin
```

La contraseña se introduce dos veces sin eco; no se incluye en el comando.
No se ha creado ninguna cuenta en esta candidata. Tras iniciar sesión, abre
Mi cuenta para crear un segundo usuario y comprueba su espacio independiente.
Conserva este estado externo para los comandos `status`, `restart` y `down`.
Los pasos siguientes son para preparar **otra** candidata cuando sea necesario.

Requisitos: Docker Desktop con contenedores Linux, Git y Python del host para
preparar fuentes. Ejecutar desde `C:\Users\itres\Desktop\clipforge-mvp`.
Las descargas públicas se hacen al construir; ninguna prueba usa servicios IA.

```powershell
$authState = Join-Path $env:TEMP ('clipforge-auth01-dev-' + [guid]::NewGuid().ToString('N'))
python -B scripts/dev_local.py prepare --state $authState --local-http
python -B scripts/dev_local.py build --state $authState --browser
python -B scripts/dev_local.py up --state $authState
python -B scripts/dev_local.py admin --state $authState --username mi_admin
python -B scripts/dev_local.py status --state $authState
```

Cada paso debe terminar con salida 0 antes de continuar. `prepare` muestra el
origen loopback elegido; abre **esa URL exacta**, no el puerto operativo 8080.
El puerto se elige entre los disponibles, sin asumir 8081. Una colisión posterior
se informa como fallo; no se ocupa ni detiene otro servicio. Guarda `$authState`
para retomar la candidata; no vuelvas a preparar sobre un directorio existente.

El lanzador valida todos los nombres versionados antes de copiar, usa
`prepare_ci_context.py` y verifica el manifiesto fuera del checkout antes de
cada build. No envía la raíz como contexto. `Dockerfile.dev` deriva de una imagen
CI exclusiva verificada por ImageID, sobre la misma base Trixie del CI anterior.
No se utiliza una imagen ni lock de la instalación operativa.

`compose.dev.yaml` se ejecuta con proyecto propio, env-file y directorio de
proyecto externos explícitos. Genera claves de desarrollo nuevas fuera del repo;
no lee `.env` operativo ni reutiliza credenciales. La aplicación usa el rol
PostgreSQL no-superusuario `clipforge`, un volumen propio, UID/GID1001, raíz RO,
capabilities retiradas y NNP. PostgreSQL tiene su volumen y UID/GID999; no publica
puertos y solo pertenece a la red privada Docker **internal**. La aplicación de
desarrollo también tiene una red bridge de entrada para que Docker Desktop
publique el puerto loopback. Esa candidata puede tener salida a red: no se
presenta como aislada del exterior, aunque no tiene claves de proveedores y
la IA está deshabilitada. Las pruebas de integración usan otra red **internal**,
sin esa bridge, con salida externa comprobada como bloqueada. No se describen
como `--network none`.

La candidata permanece en modo IA deshabilitado y modelos offline. El modo
manual permite probar el flujo sin pesos Whisper. Las fixtures de prueba generan
medios sintéticos; ningún video del operador se usó como prueba.

Para reiniciar exclusivamente esa candidata, o detenerla conservando volúmenes:

```powershell
python -B scripts/dev_local.py restart --state $authState
python -B scripts/dev_local.py down --state $authState
```

No hay limpieza global ni `down --volumes`. Conserva también el estado externo:
contiene las claves nuevas necesarias para volver a abrir esos volúmenes.
Los modos POSIX de archivos generados no acreditan por sí solos ACL de Windows;
el directorio temporal del usuario debe permanecer privado.

## Migración y primer administrador

`app/auth_migrations.py` contiene la revisión congelada `auth01_0001`, con DDL
PostgreSQL transaccional, bloqueo asesor y tabla de revisiones. `up` ejecuta
`scripts/auth_migrate.py` explícitamente antes de iniciar la app. Repetir una
revisión aplicada devuelve `current`; una revisión desconocida o error no inicia
una migración alternativa. No hay `create_all` automático ni migración de medios.

```powershell
python -B scripts/dev_local.py migrate --state $authState
python -B scripts/dev_local.py admin --state $authState --username mi_admin
```

`auth_admin.py` requiere terminal interactiva, pide la contraseña dos veces
con `getpass`, rechaza fallback con eco, argumentos con contraseña y stdin
redirigido. El bootstrap se serializa y se cierra cuando ya existen usuarios.
No hay contraseña predeterminada. Después, el administrador crea usuarios desde
Mi cuenta; cada usuario puede cambiar su contraseña verificando la actual.
No se probó ni ejecutó una adopción de proyectos reales: las asignaciones de
proyectos anteriores existen solamente en fixtures explícitas de PostgreSQL.

## Pruebas y matriz de autorización

La suite conserva los 566 IDs previos. Las fixtures HTTP ahora crean usuarios,
inician sesión y registran únicamente IDs sintéticos declarados. No hay bandera
que desactive autenticación en la aplicación. PostgreSQL real complementa las
pruebas unitarias; los contratos de terminal usan mocks expresamente rotulados.

| Criterio | Evidencia ejecutada en la suite final |
| --- | --- |
| Dos sesiones, espacios y bibliotecas independientes | `test_users_private_workspaces_and_independent_sessions` |
| Hashes Argon2id y secretos de sesión solo hash | `test_passwords_argon2id_and_sessions_store_only_hashes` |
| Login genérico y límites persistentes | `test_login_errors_do_not_enumerate_accounts`, `test_login_rate_limit_persists_across_clients` |
| CSRF previo al login y en mutaciones | Tests `test_csrf_*`, `test_authenticated_mutations_require_session_csrf` y token ajeno |
| Rotación, expiración y revocación | Tests `test_login_rotates_*`, `test_expired_and_revoked_*`, `test_logout_*` |
| Contraseña actual y revocación global | `test_change_password_checks_current_and_revokes_all_sessions` |
| Creación/desactivación y rechazo de roles ajenos | `test_admin_creates_and_deactivates_*`, `test_user_admin_permissions_*` |
| Administrador sin contenido global | `test_admin_has_no_implicit_private_content_access` |
| A usa proyecto; B no accede por IDs/URL/Range/ZIP | `test_cross_user_all_artifacts_and_mutations_denied`; suite multimedia anterior conserva render real |
| Huérfanos y futura adopción solo fixtures | `test_ownerless_legacy_project_remains_inaccessible_after_login` |
| Propiedad del upload y plantillas privadas | `test_upload_ownership_*`, `test_custom_templates_private_to_workspace` |
| Rechazo antes de consumir multipart | `test_anonymous_upload_body_not_consumed_before_authentication` |
| Migración nueva, idempotencia y errores controlados | `test_migration_*`, `test_unknown_migration_*`, `test_database_failure_*` |
| Persistencia tras reinicio | Prueba PostgreSQL y `browser_auth.py` reiniciando Uvicorn con base/archivos propios |
| UI login/cuenta/admin/logout y móvil | `browser_auth.py`, real HTTP/PostgreSQL, siete pasos |
| CLI sin eco ni contraseña en argumentos | Cuatro fixtures `test_auth_cli.py`; bootstrap real probado aparte |

Los seis escenarios browser anteriores conservan su contrato: cinco HTTP real
contra fixtures y uno `simulated_fetch`; AUTH añade un recorrido aparte.
Whisper/LLM siguen simulados. Los renders/codecs/decoder/VAD originales siguen
siendo comprobaciones nativas reales. No se acredita calidad editorial por ello.

## Resultados registrados de esta entrega

Expediente: `.ci-local/auth01-ec509377/`. Cada comando conserva sus argumentos,
tiempos y código de salida; cada comprobación identifica la imagen y manifiesto.

| Comprobación final | Resultado real | Informe relativo al expediente |
| --- | --- | --- |
| Builds CI, desarrollo y browser | Los tres terminaron con salida 0; contexto verificado | `infra/build-result-2.json`, logs en su directorio `attempt` |
| Suite Python y controles nativos | 612 tests, sin fallos, errores ni skips; 11 checks aprobados | `suite-2/test-summary.json` |
| Inventario de tests | 566 IDs anteriores conservados, 46 añadidos, ninguno retirado | `test-inventory-delta.json` |
| Browser anterior | 6 escenarios aprobados: 5 HTTP real y 1 fetch simulado | `browser-2/browser-summary.json` |
| UI AUTH | 7 pasos aprobados con PostgreSQL real, sin mock de auth; reinicio real de Uvicorn y persistencia | `auth-browser-2/auth-browser-summary.json` |
| JavaScript e inventario de imagen | Sintaxis de los 4 archivos aprobada; inventario capturado, salida 0 | `javascript-2/`, `inventory-2/` |
| Candidata desde Windows | Login y health HTTP 200; puerto solo loopback; reinicio con volúmenes conservados | `infra/development-final-after-restart.json` |
| Red de integración | PostgreSQL alcanzable; dos destinos externos bloqueados, sin ruta por defecto | `infra/infra-final-summary.json` y evidencia referenciada |
| SAST actual | 32 LOW: 13 B404 y 19 B603; salida 1, **no aprobado** | `sast-2/bandit.json` |

Los 46 tests nuevos son 26 de autenticación/PostgreSQL, cuatro contratos de CLI
con mocks, 14 del lanzador y dos de inclusión/privacidad de fuentes. La cobertura
medida es 77,98 % con ramas en el proceso unittest (`app` y `scripts`); no incluye
browser ni subprocesses nativos y no se inventa un umbral de aprobación.

Se conservan los intentos fallidos: la primera suite tuvo 603 tests y dos fallos
(Origin ausente en una fixture y texto del 404); el primer browser pasó cinco
escenarios y falló entrega por una fixture que buscaba plantillas en la antigua
carpeta global. Las correcciones mantienen las comprobaciones. Docker Desktop
no publicó el primer puerto con una única red interna; la segunda preparación
separó la entrada bridge de desarrollo de la red privada PostgreSQL y comprobó
el acceso desde Windows. El primer SAST tuvo 33 LOW, incluido B607 por buscar Git
en PATH; el selector de ejecutables absolutos lo eliminó sin suprimir reglas.
Todos esos resultados permanecen registrados; los segundos intentos corresponden
a las fuentes corregidas, no a reintentos ciegos del mismo contenido.

Identidades finales:

```text
CI:      sha256:21c0a4448ffcf54a3f54c36b97f1999fb267e3ce03bde61bddd4ba0b75cd09f9
dev:     sha256:42a85a20236089b92e6baacf81bdba300c04c81c29971aa0d83008be06ff70b5
browser: sha256:2fa12b36bd11e99297c063b20514ac49ea980fa46afc22209713928e0fd07adf
```

La primera candidata quedó detenida conservando sus volúmenes. La segunda sigue
activa sin administrador. La persistencia de usuarios/sesiones se demostró con
fixtures en la base de integración, sin sembrar usuarios en la candidata entregada.
El resultado final del escaneo de secretos y la huella del patch se entregan en
`final-summary.json`; este documento no anticipa su aprobación.

## Dependencias, seguridad y siguiente incremento

Se añadieron SQLAlchemy 2.1.8, psycopg/psycopg-binary 3.3.8 y argon2-cffi 25.1.0.
El lock añade además argon2-cffi-bindings 26.1.0, cffi 2.1.1 y pycparser 3.12.
Se conservan las 38 versiones/hashes de aplicación anteriores y el lock de
herramientas. Resolución real CPython3.12/Linux amd64 desde PyPI y wheels con
hashes; instalación sin red. Los metadatos del solver se conservan en el expediente.

El [registro de riesgos](RISK-REGISTER.md) conserva los findings reales, sin
aceptaciones ni cambios de severidad/reglas/umbrales. El SAST nuevo se registra
por archivo/imagen propios. No se hizo una nueva auditoría general de CVEs ni se
reutilizan los scans anteriores como si fueran de AUTH-01.

El workflow GitHub no se ejecutó para este incremento. El runner local incorpora
PostgreSQL; una futura ejecución GitHub necesita preparar esa base y la red interna
explícitamente. El workflow histórico no se declara compatible ni aprobado por
los resultados locales. Los contratos de fuentes nuevas sí tienen regresiones
de inclusión exacta y rechazo de archivos privados.

Siguiente incremento funcional mínimo propuesto: recuperación local de cuentas
por un administrador, con revocación y registro de la acción, sin correo externo
ni acceso al contenido privado. La adaptación de GitHub a PostgreSQL aislado
queda como trabajo técnico separado antes de ejecutar allí la suite. Ninguno
requiere reabrir SEC-05 o contratar servicios; no incluye publicación o despliegue.

## Expediente local

`.ci-local/auth01-ec509377/` conserva cada intento, comandos/exit codes, imágenes,
contextos, logs, inventarios y resultados. Los informes fallidos no se reemplazan.
El patch se genera por selección explícita de AUTH-01; excluye `experiments/`,
`docs/SEC-05.md`, datos y expedientes. La entrega no modifica el índice Git.
