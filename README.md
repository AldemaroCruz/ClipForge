# ClipForge AI v0.4.2 — Base operativa local

**Actualización desde v0.4.1.** Mantiene edición, subtítulos, plantillas, propuestas IA, aprobación y ZIP. Añade respaldo/restauración con hashes, métricas por etapa, tiempo humano, evidencia de aceptación y una ruta de actualización que hereda el runtime que ya funcionó.

**Base local confirmada por el operador:** v0.4.2 con hotfixes funciona en Docker Desktop; se verificaron restauración con hashes/fechas exactas y apertura funcional de un proyecto recuperado. La aceptación editorial y los resultados de CI se registran por separado. No hay nube ni autenticación nuevas.

**Desarrollo CI:** la carpeta autorizada es `C:\Users\itres\Desktop\clipforge-mvp`; la copia de `source\repos\clipforge` se conserva sin sincronizar. El CI usa un contexto de fuentes permitido y una imagen independiente; no utiliza Compose, datos, claves ni locks operativos. Actions ya se ejecutó: [run 42866539507](https://github.com/AldemaroCruz/ClipForge/actions/runs/42866539507), commit `2c5ea13e4c5935bad84a0ce7ad6c453fe221e52c`. Pasaron permisos, 541 tests, 11 checks y seis escenarios browser; Bandit/Trivy mantienen bloqueado CI. [SEC-04](docs/SEC-04.md) documenta el incremento local posterior, sin promoción operativa. No se recuperaron archivos del candidato v0.5.0-rc1.

**Resultado local de CI-01:** 436 pruebas y los ocho checks obligatorios aprobados, sin omisiones. El gate de seguridad permanece **ROJO**: Trivy reportó 1 hallazgo CRITICAL y 233 HIGH en la imagen de CI. No se redujeron umbrales ni cambiaron los pins de producción; detalle, límites y evidencia en [docs/CI.md](docs/CI.md).

**SEC-01 local (histórico):** remediación mínima compatible de FastAPI/Starlette/multipart y zlib, con locks de hashes. Pasaron 480 tests sin omisiones y seis recorridos browser (cinco HTTP directos, uno simulado). Cobertura: 79,95% líneas y 69,41% ramas. Seguridad seguía bloqueada: CI conservaba 226 findings/52 CVE y navegador 228/54; Bandit registraba 47 LOW bloqueantes. Ese resultado es anterior a Actions. [Informe y pendientes](docs/SEC-01.md). No se actualizó el contenedor operativo.

**SEC-02:** validador versionado con controles de alcance/paquetes y 40 tests permanentes; actionlint obligatorio y temprano; siete asserts de branding sustituidos por validaciones equivalentes, probadas también con `python -O`. La revisión subprocess/CUPS conserva los bloqueos y no autoriza release. [Informe actual](docs/SEC-02.md). Los resultados SEC-01 anteriores se conservan como históricos.

**SEC-03:** import sin uso retirado y consulta de versión FFmpeg con timeout y rechazo explícito de respuesta vacía. Incluye pruebas aisladas y preparación de una selección explícita para el primer commit, sin inicializar Git ni inventar autor. SEC-02 terminó su alcance técnico local; Bandit/Trivy siguen bloqueantes y Actions pendiente. [Estado y evidencia](docs/SEC-03.md).

**Referencia Git GIT-01:** arranque en `ci/bootstrap-sec03` con las 127 rutas revisadas y escaneo del índice exacto antes del commit. El remoto creado en GitHub debe verificarse vacío; no se presupone `main` ni se abre un PR sin base. El versionado no elimina los 39 LOW de Bandit ni los 226 hallazgos/52 CVE OS de la candidata CI. La instalación operativa no se promueve y Actions solo se acredita con su ejecución real.

## Actualizar

1. Espera a que terminen los trabajos. **Deja el contenedor v0.4.1 en ejecución; no hagas down ni un build nuevo primero.**
2. Copia el contenido del ZIP sobre la carpeta de proyecto. Conserva `data/`, `cache/`, `.env.ai`, `.env`, `release/`, `backups/` y `evidence/`.
3. En PowerShell desde la carpeta del proyecto:

```powershell
.\scripts\Prepare-Upgrade.ps1
if (-not $?) { throw 'Revisa la preparacion antes de continuar.' }
.\scripts\Start-Release.ps1
Invoke-RestMethod http://127.0.0.1:8080/health
```

La preparación detiene el contenedor, conserva su imagen, captura paquetes/revisión de modelo y hace un backup privado verificado. El inicio utiliza `Dockerfile.runtime`, sin reinstalar dependencias. El archivo `compose.runtime.yaml` se genera **en tu equipo**; no hay una imagen, un digest o un lock inventados dentro de este ZIP.

Espera `version: 0.4.2`. Abre `http://127.0.0.1:8080`, Ctrl+F5. **Operación y métricas** abre `/ops`. Guía detallada, errores, restauración, pruebas y rollback: **[docs/OPERACION.md](docs/OPERACION.md)**.

## Capacidades nuevas

- Tiempos de validación, modelo, transcripción, selector y render; espera en cola separada. Históricos sin tiempo → «No medido».
- Conteos de aprobados, consumo IA reportado, espacio del volumen y RSS de la API. No inventa costos monetarios.
- Registro explícito e idempotente de minutos de revisión por proyecto.
- Respaldo ZIP64 en streaming, SHA-256, exclusión de archivos de credenciales reconocidos, bloqueo contra API activa y detección de archivos cambiantes.
- Restauración a carpeta nueva, sin sobreescritura, preservando bytes y fechas precisas para reutilizar las propuestas existentes.
- Captura del runtime real + revisión/hashes del modelo. Verifica el snapshot local antes de cargar; no hace cambios silenciosos al modelo.
- Verificador de una entrega existente sin consultas a IA: trazabilidad → ZIP/hash → decodificación MP4. La revisión humana no se automatiza.

Los backups contienen contenido privado **sin cifrado**. No son paquetes para enviar a un cliente. Copia de respaldo y entrega ZIP son cosas diferentes.

## Documentación y seguimiento

- [Operación y aceptación](docs/OPERACION.md)
- [Estado actual y puertas de salida](docs/PROJECT_STATUS.md)
- [Roadmap](docs/ROADMAP.md) · [Backlog](docs/BACKLOG.md)
- [Informe real de pruebas](TEST-REPORT.md)
- [Guía IA heredada](GUIA-IA.md): proveedor y consentimiento no cambian. Sus comandos antiguos de construcción no sustituyen la ruta de runtime congelado.

El Dockerfile/Compose base siguen disponibles para desarrollo, pero no representan una reconstrucción hermética. **No uses `docker compose up --build` a secas para reemplazar una release aceptada.** Usa `Start-Release.ps1 -NoBuild` para iniciar el mismo artefacto después de validarlo.

## Límites conservados

Solo localhost; un proceso Uvicorn y un trabajo pesado a la vez; sin autenticación, cola durable, cuentas o facturación SaaS. No se envían videos a IA. Las llamadas de selección siguen requiriendo autorización. El modelo editorial configurado no se sustituye. La aplicación no recupera automáticamente trabajos interrumpidos.
