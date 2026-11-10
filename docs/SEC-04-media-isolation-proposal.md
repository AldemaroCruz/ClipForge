# Propuesta separada: aislamiento de medios (no implementada)

SEC-04 verifica qué binario se ejecuta y cómo se separa argv. No demuestra qué
otros archivos podría leer el decoder al procesar un medio no confiable.
`-protocol_whitelist file,pipe` limita protocolos, no rutas de archivos. Las
ubicaciones C01/C11/C12/C13 de SEC-02 conservan ese límite de evidencia.
Esto no prueba explotación de un CVE ni autoriza una excepción de seguridad.

Decisión solicitada para otro incremento: autorizar primero un prototipo local
de worker por operación multimedia, separado del proceso API. No está aprobada
su incorporación al servicio ni se modifica el modelo de ejecución en SEC-04.

El contrato a evaluar sería:

- Entrada: un único archivo sintético validado por ID interno, montado RO; sin
  raíz del proyecto, datos de otros proyectos, credenciales, cache o respaldos.
- Salida: directorio exclusivo, publicado solo al completar y validar archivos
  regulares esperados; sin enlaces o lectura de rutas arbitrarias del host.
- Proceso: binarios/imagen identificados, UID sin privilegios, raíz RO, ninguna
  capacidad, no-new-privileges, red none y ningún socket Docker dentro del worker.
- Recursos: límites explícitos de CPU, memoria, temporales, tiempo de proceso,
  salida capturada y limpieza del grupo de procesos; valores a medir antes de
  fijarlos. La API no recibe autoridad sobre el daemon como atajo del prototipo.
- Evidencia: fixtures sintéticos que intenten leer un archivo señuelo vecino y
  salir del destino, más controles de error/timeout y los recorridos editoriales,
  render, descargas/Range y navegador actuales. Sin archivos del operador.

Falta elegir el mecanismo de orquestación y su responsable/aprobador. Debe
justificar el montaje de fuentes, fuentes tipográficas y bibliotecas necesarias,
sin ocultar componentes del inventario. Si requiere cambiar Compose, APIs,
renderer o permisos de despliegue, su alcance debe revisarse antes de programar.

La alternativa vigente es conservar el bloqueo. Aun si un sandbox demostrara
los límites de archivos, los HIGH/CRITICAL continuarían bloqueando bajo la
política actual. Su corrección o una decisión de riesgo explícita sería un
trabajo independiente; no se propone VEX ni aceptación automática.
