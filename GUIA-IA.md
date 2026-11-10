# ClipForge v0.4.1 — Selección editorial asistida (beta)

Esta versión analiza **transcripciones ya guardadas**, no videos ni sonidos. El
selector inicial de hasta cinco clips sigue siendo heurístico y no se cambió.
La IA es un paso separado: propuestas → revisión → borrador → variante → aprobación
→ entrega. No sustituye ni sobrescribe los clips existentes. No publica nada.


## Corrección de selección en v0.4.1

La versión 0.4.0 podía recibir JSON válido pero rechazar todos sus intervalos.
Además, el caso `AI_NO_VALID_CANDIDATES` perdía el detalle de cada descarte.
En 0.4.1 ClipForge construye localmente **todos los intervalos de segmentos completos**
que respetan el tramo y la duración elegidos. Envía el catálogo junto con la
transcripción. El modelo responde con `range_id` de un enum, título, motivo y
valoraciones; no inventa los extremos ni calcula la duración. La selección editorial
sigue siendo del modelo y debe revisarse: el catálogo no equivale a clips aprobados.

Máximo **500 intervalos elegibles por solicitud**, hasta 5 propuestas de salida.
Si el catálogo excede ese límite o el presupuesto de caracteres/contexto, la vista
previa lo rechaza antes de llamar al proveedor: reduce el tramo o estrecha las
duraciones. **No se muestrea, trunca ni divide silenciosamente la solicitud**.
El catálogo puede aumentar los tokens de entrada respecto a v0.4.0; se conserva
el límite previo de tamaño y se muestra la solicitud antes de consentir.
Si no existe ningún intervalo válido, tampoco se llama al modelo ni se reserva cuota.

La validación local conserva motivos individuales (ID desconocido, duración o
solapamiento) incluso si ninguna propuesta sirve. El panel distingue respuesta
JSON recibida de selección aceptada y permite leer un diagnóstico estructural.
No guarda cuerpos crudos del proveedor, claves ni entradas de error de Pydantic.
Los resultados aprobados sí conservan títulos/textos como antes.

Los análisis de **v0.4.0 permanecen intactos**. Si fallaron, no es posible reconstruir
la respuesta que esa versión no guardó. Abrir o actualizar su historial no envía
solicitudes. Después de actualizar prepara y autoriza un **análisis nuevo** con el
mismo proyecto; no hace falta subirlo ni transcribirlo otra vez. No hay retries ni
fallback de proveedor/heurística, y no se alteran clips, rangos, límites o modelo
para forzar un resultado. Un modelo puede devolver menos propuestas o ninguna.

### Actualizar una instalación que ya tiene IA habilitada

Conserva tu **`.env.ai` actual** y no pegues la API key en chats ni capturas. La
corrección no requiere cambiar modelo, clave ni límite de tokens.

```powershell
cd C:\Users\itres\Desktop\clipforge-mvp
# Detener solo cuando no haya un render o análisis en curso.
docker compose -f compose.yaml -f compose.ai.yaml down
# Copiar el contenido del ZIP encima del código. Conservar data/, cache/, .env y .env.ai.
docker compose -f compose.yaml -f compose.ai.yaml up --build -d --wait --wait-timeout 120
if ($LASTEXITCODE -ne 0) { throw "No se pudo construir o iniciar ClipForge" }
Invoke-RestMethod http://localhost:8080/health
Invoke-RestMethod http://localhost:8080/ai/config
```

Esperado: versión **0.4.1**, el mismo proveedor/modelo y configuración presente.
Estas consultas no realizan inferencia. Recarga con **Ctrl + F5**, abre tu proyecto
transcrito y prepara una nueva vista previa. Debe mostrar el número de intervalos
válidos antes de autorizar. Autoriza una sola vez, revisa propuestas y diagnóstico.
Un intento externo nuevo puede generar consumo; los fallos anteriores siguen
contando para la cuota local diaria (UTC).


## 1. Actualizar sin activar servicios externos

Detén la aplicación cuando no haya renders/análisis en curso, conserva `data/`,
`cache/`, `.env` y `.env.ai` si existen, y copia el contenido del ZIP sobre el proyecto.
No anides `clipforge-mvp/clipforge-mvp`. Los borradores, plantillas, aprobaciones y
entregas siguen en sus rutas actuales. Respalda primero cambios personales.

```powershell
cd C:\Users\itres\Desktop\clipforge-mvp
docker compose up --build -d --wait --wait-timeout 120
if ($LASTEXITCODE -ne 0) { throw "No se pudo construir o iniciar ClipForge" }
Invoke-RestMethod http://localhost:8080/health
```

Esperado: `0.4.1`. Recarga el navegador con Ctrl + F5. Esta ejecución **no carga
`.env.ai`**: la IA permanece desactivada. El build no llama a OpenAI ni a Ollama.

Abre un proyecto transcrito. Debajo de los resultados encontrarás **Propuestas
asistidas**. Puedes probar **Comparación heurística local · sin IA**, preparar la
vista previa, autorizarla y crear un borrador con uno de sus resultados. Esto no
mejora el criterio de selección: ejecuta el algoritmo original y permite probar
el nuevo recorrido sin proveedor, clave ni cargos de API. El brief no interviene
en ese modo. Un proyecto manual sin `transcript.json` no puede analizarse por texto.

## 2. Activar OpenAI, de manera explícita

Se requiere una API key y acceso al modelo elegido en tu proyecto de API.
La facturación de API se administra por separado de ChatGPT; una suscripción de
ChatGPT no debe interpretarse como crédito de API. Verifica tus límites y políticas
antes de autorizar una consulta. Esta entrega no incluye claves ni hace una prueba
pagada de conexión al arrancar.

En PowerShell:

```powershell
if (-not (Test-Path -LiteralPath .env.ai)) {
    Copy-Item .env.ai.example .env.ai
}
notepad .env.ai
```

Edita estas líneas **en el archivo local**, no en un chat, repositorio o captura:

```dotenv
CLIPFORGE_AI_PROVIDER=openai
CLIPFORGE_AI_MODEL=gpt-6-luna
OPENAI_API_KEY=TU_CLAVE_REAL
CLIPFORGE_AI_DAILY_LIMIT=10
CLIPFORGE_AI_MAX_INPUT_CHARS=60000
CLIPFORGE_AI_MAX_OUTPUT_TOKENS=4000
CLIPFORGE_AI_TIMEOUT_SECONDS=180
```

`gpt-6-luna` es el ejemplo documentado al preparar esta entrega; admite Responses y
salidas estructuradas. Es configurable, no un requisito ni una garantía de acceso
para tu cuenta. El adaptador fija esfuerzo `low` para ese modelo. Para otros modelos
no envía ajustes de razonamiento específicos; usa un modelo con Responses API y
JSON Schema estricto. No hay selección ni cambio automático de modelo si falla.

Guarda, cierra el editor y levanta con **los dos archivos Compose**:

```powershell
docker compose -f compose.yaml -f compose.ai.yaml up --build -d --wait --wait-timeout 120
if ($LASTEXITCODE -ne 0) { throw "No se pudo iniciar ClipForge con la configuracion IA" }
Invoke-RestMethod http://localhost:8080/ai/config
```

Ese GET devuelve configuración pública **sin la clave y sin llamar al proveedor**.
`configured: true` significa que hay configuración, no que la cuenta, el saldo,
la conectividad ni la inferencia hayan sido probados. El primer análisis autorizado
es la primera solicitud real. Sigue utilizando ambos `-f` cuando recrees el servicio
con IA; un `up` con solo el Compose base vuelve a la configuración base desactivada.

No compartas `.env.ai`, `docker inspect` ni un `docker compose config` que pudiera
resolver secretos. `.gitignore` y `.dockerignore` excluyen `.env*` (solo se versiona
el ejemplo sin clave). Variables de contenedor y archivos locales no son una bóveda
ni cifran tus secretos frente a administradores del equipo.

## 3. Ollama local (alternativa, no requisito)

El adaptador admite un **servidor Ollama ya instalado, iniciado y accesible desde
el contenedor**, con un modelo de instrucciones descargado localmente. ClipForge
no instala Ollama, no descarga modelos y no reserva GPU ni RAM para ese servicio.
No se validó inferencia real con Ollama en el entorno de esta entrega.

Ejemplo para un modelo instalado con `ollama pull qwen2.5:7b`:

```dotenv
CLIPFORGE_AI_PROVIDER=ollama
CLIPFORGE_AI_MODEL=qwen2.5:7b
OPENAI_API_KEY=
CLIPFORGE_OLLAMA_URL=http://host.docker.internal:11434
CLIPFORGE_OLLAMA_NUM_CTX=16384
CLIPFORGE_AI_MAX_OUTPUT_TOKENS=4000
CLIPFORGE_AI_TIMEOUT_SECONDS=180
```

Recrea con los dos Compose de la sección anterior. `localhost` dentro de ClipForge
es el propio contenedor, no Windows. El nombre `host.docker.internal` corresponde
al host en Docker Desktop; el servicio y el firewall deben permitir esa ruta.
No publiques un puerto de Ollama a Internet ni desactives tu firewall para probarlo.
También se admite `http://ollama:11434` cuando administras un servicio en la misma
red de Docker, sin publicar su puerto al host. Esta entrega no añade ese servicio.

Para mantener la inferencia local, desactiva cloud **en el proceso/servidor Ollama**
con `OLLAMA_NO_CLOUD=1` según su documentación y usa un tag descargado localmente.
Poner esa variable solo en ClipForge no cambia un Ollama externo. El adaptador
rechaza tags que contengan `cloud` y restringe hosts a localhost, loopback,
`host.docker.internal` y `ollama`, pero no puede auditar si el servidor configurado
se comporta como proxy. La propiedad de inferencia local depende también de ti.

El presupuesto de contexto usa un límite conservador basado en bytes UTF-8 de toda
la solicitud, salida y reserva. No es un conteo exacto de tokens. Puede rechazar un
texto que otro tokenizador sí admitiría. Para empezar, analiza un tramo de 1–2 minutos;
reduce el tramo ante `AI_CONTEXT_LIMIT`, o aumenta contexto solo si tu equipo lo admite.
CPU, RAM, modelo y carga concurrente influyen en el tiempo. Un timeout **no garantiza
que Ollama haya detenido la inferencia**.

## 4. Primera prueba editorial

Abre un video hablado propio o autorizado que ya tenga transcripción. Por ejemplo,
el proyecto `6de6f90a1f5544da8a3bf491c7bc3002` de la prueba inicial, si sigue en `data/`.
No vuelvas a subirlo para probar esta función.

1. En **Propuestas asistidas**, selecciona **IA configurada**.
2. Escribe un objetivo, por ejemplo: «Busca tres ideas útiles que se entiendan sin
   contexto, con una explicación y una conclusión. Evita presentaciones y despedidas».
3. Elige hasta 1–5 propuestas, duración de 20–60 s y un tramo del original. El modelo
   puede devolver menos propuestas o ninguna. No se prometen cinco resultados.
4. Pulsa **1. Revisar texto y destino**. Verás los segmentos completos que se usarán,
   sus IDs y tiempos, el objetivo y las instrucciones del sistema. Esta fase no
   contacta al proveedor ni crea un análisis persistente.
5. Comprueba texto y destino, marca la autorización y pulsa **2. Analizar una vez**.
   Cambiar el objetivo/tramo invalida la autorización y obliga a revisar otra vez.
6. Revisa títulos, razones, extracto y contexto anterior/posterior. Compara con el
   selector heurístico original. Gancho/claridad/cierre son juicios subjetivos de
   1 a 5, **no probabilidades de viralidad, hechos comprobados ni garantías**.
7. Pulsa **Crear / abrir borrador**. Se conserva un borrador real sin renderizar.
   Ajusta límites y subtítulos; el texto viene de la transcripción guardada, no de
   una paráfrasis del modelo. Después genera una variante y sigue el flujo normal
   de revisión y entrega.

Volver a aceptar la misma propuesta abre el mismo borrador y conserva los cambios
que ya guardaste. El título sugerido se convierte en nombre del borrador, no en un
rótulo incrustado ni en una aprobación para publicar. La procedencia queda en el
borrador y la exportación. Los clips automáticos originales permanecen separados.

## 5. Validación, privacidad y límites reales

El modelo solo puede devolver IDs de segmentos. El servidor calcula los tiempos,
valida duración/tramo/solapamientos y descarta propuestas inválidas. Rechaza JSON
incorrecto y no cambia a heurística en silencio para fingir que funcionó la IA.
Esto valida estructura y anclaje, **no fidelidad editorial**: revisa títulos, contexto,
audio y cortes. Los tiempos siguen siendo por segmento, no por palabra.

Se envía exclusivamente el texto seleccionado, sus tiempos/IDs y las instrucciones
editoriales al destino configurado. No se envía MP4, audio, borradores, notas de otros
proyectos ni claves dentro del prompt. El texto puede contener datos personales:
la vista previa no los anonimiza. Solo usa material autorizado.

El adaptador OpenAI usa `store:false`, no crea herramientas ni solicitudes en modo
background. Esto **no equivale a Zero Data Retention**, ni elimina por sí mismo las
políticas de monitoreo/retención del proveedor. Revisa su política y los controles
de tu organización. No se guardan cuerpos HTTP crudos, claves ni prompts completos
en los logs; el proyecto sí conserva el brief, extractos de propuestas y transcripción
original en archivos locales. Los respaldos contienen esos datos.

Máximos de esta versión:

- 1 solicitud por análisis; sin reintentos automáticos, sin fan-out ni cambios de modelo.
- 10 intentos IA por día UTC de forma predeterminada, compartidos entre proyectos y
  proveedores de esta instalación. Fallos, reservas e interrupciones también cuentan.
  Es un freno local conservador, no un límite de gasto de la cuenta del proveedor.
- 60 000 caracteres en toda la solicitud JSON por defecto; 2 000 segmentos por tramo.
  No hay truncación ni resumen silencioso: reduce el tramo cuando exceda el límite.
- 4 000 tokens de salida por defecto. Se muestra uso reportado cuando existe; `null`
  significa desconocido, no cero. No se calcula precio en USD ni se afirma un presupuesto.
- 100 análisis guardados por proyecto; la UI muestra los 10 recientes. Los anteriores
  siguen consultables por la API paginada. No hay eliminación desde la interfaz.
- Se comparte el bloqueo con transcripción/render. Un trabajo ocupado rechaza otro
  análisis; no hay cola duradera, cancelación remota ni ejecución multiusuario.

Repetir un POST con el mismo ID no realiza otra llamada; abrir/consultar análisis
es lectura. **Preparar un análisis nuevo con otro ID sí puede llamar y cobrar de nuevo.**
Si se pierde una respuesta de red, actualiza el historial antes de crear otro.
Tras reiniciar el servicio, los análisis en curso se marcan interrumpidos y no se
reanudan: la solicitud anterior pudo haber sido procesada/cobrada remotamente.
No permite que dos contenedores/procesos compartan el mismo `data/`.

## 6. Errores y diagnóstico seguro

- `AI_DISABLED` / `AI_KEY_REQUIRED`: revisa `.env.ai` y que utilizaste ambos Compose.
- `AI_ACCESS_DENIED` (HTTP 401/403): credencial, acceso o política del proyecto; no publiques
  la clave. Una configuración sintácticamente válida no verifica autorización.
- `AI_QUOTA_OR_RATE` (HTTP 429): cuota o rate limit remoto. No hay retry automático.
- `AI_INPUT_TOO_LARGE` / `AI_CONTEXT_LIMIT`: reduce el tramo antes de enviar.
- `AI_SCHEMA_INVALID` / `AI_NO_VALID_CANDIDATES`: el modelo produjo una respuesta no
  utilizable; no es un fallo de render. No inventamos una selección exitosa.
- `AI_TIMEOUT` / `AI_INCOMPLETE`: comprueba historial/consumo del proveedor. Puedes
  ajustar tramo, cantidad o salida, sabiendo que una nueva consulta puede tener cargo.
- HTTP 409 por fuente/configuración cambiada: genera una vista previa nueva.
- No hay transcripción: utiliza un proyecto previamente transcrito o el editor manual.

```powershell
Invoke-RestMethod http://localhost:8080/ai/config
docker compose logs --tail 80 clipforge
```

Para desactivar IA, cambia `CLIPFORGE_AI_PROVIDER=disabled` en `.env.ai` y recrea con
los dos archivos Compose; o recrea solo con el Compose base. No detengas una consulta
pagada esperando que ello cancele el procesamiento remoto. Conserva análisis ya guardados.

## 7. Referencias primarias revisadas el 22 de octubre de 2026

- OpenAI, Responses y salidas estructuradas:
  https://developers.openai.com/api/docs/guides/structured-outputs
  https://developers.openai.com/api/reference/resources/responses/methods/create
- Modelo de ejemplo (acceso real pendiente de prueba con tu cuenta):
  https://developers.openai.com/api/docs/models/gpt-6-luna
- OpenAI, datos y facturación independiente:
  https://developers.openai.com/api/docs/guides/your-data
  https://help.openai.com/en/articles/9039756-managing-billing-for-chatgpt-and-the-api-platform
- Ollama, API, JSON Schema y desactivar cloud:
  https://docs.ollama.com/api/chat
  https://docs.ollama.com/capabilities/structured-outputs
  https://docs.ollama.com/faq
  https://ollama.com/library/qwen2.5:7b
