# SEC-03: propuesta de decisión individual sobre SAST

**Estado: PROPUESTA; ninguna aceptación aprobada ni aplicada.** Este documento reutiliza [SEC-02-subprocess.md](SEC-02-subprocess.md); no cambia Bandit, su validador, umbrales, exclusiones ni código. Las alertas restantes conservan el bloqueo de CI.

## Separación de decisiones

| Clasificación de SEC-02 | Tratamiento propuesto |
| --- | --- |
| Defecto concreto | Corregir y verificar. El import sin uso de `app/main.py` y el timeout/salida vacía de la consulta FFmpeg en `scripts/capture_runtime.py` pertenecen al coordinador; no se proponen para aceptación. Su corrección no elimina automáticamente B404/B603/B607. |
| Evidencia insuficiente | C01/C11/C12/C13 siguen bloqueados: falta acreditar confianza del ejecutable, permisos y confinamiento al procesar medios/artefactos. Una justificación documental no reemplaza esa evidencia. |
| Uso revisado que necesita decisión específica | Puede presentar una ficha por ubicación, con alcance y pruebas definidos. Debe aprobarse explícitamente después de comprobar los controles. La ficha candidata siguiente todavía no es elegible para aceptación. |

No se propone aceptar globalmente B404, B603, B607, directorios, imports o subprocess. Cada otra ubicación P de SEC-02 necesita su propia ficha; la decisión de una llamada no cubre sus imports ni otras alertas de la misma función.

## Contenido obligatorio de cada posible aceptación

- ID y regla, ruta y línea de la alerta; SHA256 del archivo completo y del span de código revisado, con algoritmo y límites reproducibles.
- Justificación concreta, entradas admitidas, ejecutable/argv y riesgos residuales; controles demostrados y evidencia enlazada, distinguiendo fixtures de ejecución real.
- Entorno autorizado e identidad/permisos, procedencia del binario, `PATH`, variables necesarias, red, montajes, datos y recursos temporales; sin extrapolar Linux CI a Windows operativo.
- Responsable técnico y aprobador **POR DESIGNAR**; no hay aprobación por existir una ficha o por autorizar su preparación.
- Revisión antes de decidir y al cambiar código, hashes, dependencias/binario, permisos o entorno. Fecha de aprobación y expiración UTC explícitas, ambas pendientes hasta su designación; se propone una vigencia máxima de 30 días desde la aprobación.
- Registro de aprobación explícita del usuario para esa ficha y sus límites. Cualquier cambio posterior que afecte esos límites invalida la decisión y requiere nueva revisión. El mecanismo técnico de una eventual aceptación requiere autorización posterior; esta propuesta no lo implementa.

## Ficha candidata SEC-03-C02 — PENDIENTE, NO ACEPTADA

| Campo | Propuesta concreta |
| --- | --- |
| Alerta | **Solo B603**, `app/audio_check.py:47–48`, llamada `subprocess.run()` de `make_test_mp4()`. El B404 de línea 12 y cualquier otra alerta quedan fuera. |
| Archivo SHA256 | `bb21ca8546683c0b9bf1dc86e8bac18ce0f3436c4f20d771beb5f7e08bbb4c3a` |
| Span revisado | Líneas **36–52** inclusive, función completa. SHA256 `e0a6d4a00ea49d87463434dd1d5f1733fdff2bd7cdceb2c41e7b1e9ae3e6d21e`. Codificación: texto de esas líneas unido con LF y un LF final, UTF-8 sin BOM. El hash del archivo usa sus bytes originales. Leídos el `2026-11-10T15:09:57Z`. |
| Justificación candidata | El flujo `check_audio_stack():88–98` crea `tone.wav` y `tone.mp4` bajo un `TemporaryDirectory` nuevo; genera negro lavfi y audio sintético de 1 s. Los argumentos son una lista y no activan shell. No acepta una cadena de comando del usuario en ese flujo. El hash del archivo también vincula este llamador. |
| Controles presentes en código | `-nostdin`, duración fija, un thread de video, timeout de 30 s; error ante returncode no cero o MP4 ausente/vacío. Destino temporal nuevo en el llamador revisado. Son observaciones estáticas, no pruebas nuevas. |
| Límite todavía abierto | `shutil.which("ffmpeg")` usa `PATH` y no acredita propiedad/permisos del ejecutable. La función admite rutas de otros llamadores y usa `-y`; la candidatura solo contempla el flujo de fixture indicado. Captura stdout/stderr en memoria, sin tope explícito de bytes; este riesgo residual debe revisarse. |
| Entorno candidato | Exclusivamente imagen CI Linux amd64 propia, contexto/manifiesto verificados, sin red externa, claves ni datos operativos, raíz read-only y temporal exclusivo. Falta comprobar identidad efectiva, permisos, procedencia y resolución de FFmpeg y variables heredadas. Ninguna aprobación cubre el servicio Windows activo. |
| Evidencia requerida antes de decidir | Verificar binario/directorios confiables y ausencia de búsqueda insegura; probar fixture real aislado y fallos por binario ausente, returncode no cero, timeout y output vacío. Comprobar separación de argv y destinos temporales; distinguir esos casos controlados de un intento real de explotación. No modificar datos ni ejecutar la captura operativa. |
| Responsable / aprobador | **POR DESIGNAR / POR DESIGNAR**. |
| Revisión / expiración | Revisión previa obligatoria; caduca ante cambio de hash, llamador, FFmpeg, entorno o permisos. Fecha UTC de expiración **POR DESIGNAR**, obligatoria antes de aprobar; propuesta de máximo 30 días de vigencia. |
| Aprobación explícita | **PENDIENTE**. No consta autorización del usuario para aceptar esta alerta o cambiar el gate. |

## Estado conservado

La ficha no levanta ninguna alerta, no añade `nosec` y no autoriza wrappers, aliases, baselines de supresión o exclusiones. Aunque llegara a aprobarse este uso, el resto de Bandit seguiría bloqueando hasta resolver cada hallazgo conforme a su clasificación.

El diagnóstico histórico de Trivy OS en [SEC-01](SEC-01.md) es independiente: una decisión SAST no corrige CVEs ni modifica ese bloqueo. No se consultaron CVEs ni se refrescaron scanners para esta propuesta. **GitHub Actions no se ha ejecutado en GitHub.**

En esta tarea solo se reutilizó la revisión previa y se leyeron/hasharon las líneas de la ficha. Simulaciones: ninguna. Nuevos tests, Bandit, pruebas del entorno y aceptación: pendientes. Único archivo añadido: este documento.
