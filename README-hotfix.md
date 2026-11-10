# ClipForge v0.4.2 - Parche PowerShell 1

Este paquete NO es una nueva version de la aplicacion. Se aplica al proyecto v0.4.2
que ya copiaste sobre la instalacion v0.4.1. No necesita reinstalar dependencias,
volver a copiar el proyecto completo ni cambiar la politica RemoteSigned.

## Correcciones

1. En el here-string del overlay Compose, `./$RelDir:/release:ro` pasa a
   `"./${RelDir}:/release:ro"`. La variable queda delimitada antes de los dos puntos.
2. En Prepare-Upgrade, las cinco referencias `$Home` pasan a `$HuggingFaceHome`.
   `$Home` y `$HOME` designan la misma variable automatica de PowerShell.
3. Se agrega Test-PowerShellScripts.ps1: analiza todos los .ps1 del directorio
   mediante Parser.ParseFile y rechaza asignaciones directas a ciertas variables
   automaticas. No ejecuta los scripts inspeccionados, Docker ni llamadas HTTP.

No se cambio ninguna otra operacion de Prepare-Upgrade. No se modifican los otros
siete scripts existentes. La aplicacion conserva version 0.4.2.

## Instalacion

No ejecutes docker compose down ni reconstruyas primero. El error ParserError
impidio que se ejecutara Prepare-Upgrade en ese intento.

Conserva una copia del script que reemplazaras (usa una extension diferente de
.ps1, por ejemplo Prepare-Upgrade.ps1.before-hotfix, para que el verificador no
intente analizar la copia antigua).

Copia los dos archivos de scripts/ de este ZIP dentro de la carpeta scripts/ de
C:\Users\itres\Desktop\clipforge-mvp, reemplazando Prepare-Upgrade.ps1.
No toques data/, cache/, .env.ai, release/ o backups/.

Despues de revisar los archivos descargados:

```powershell
cd C:\Users\itres\Desktop\clipforge-mvp
Unblock-File -LiteralPath .\scripts\Prepare-Upgrade.ps1 -ErrorAction Stop
Unblock-File -LiteralPath .\scripts\Test-PowerShellScripts.ps1 -ErrorAction Stop
.\scripts\Test-PowerShellScripts.ps1
```

Con los ocho scripts originales mas el nuevo, el resultado esperado es
`Validacion estatica OK: 9 scripts.` No es un resultado ya obtenido aqui.

Solo cuando termine sin errores:

```powershell
.\scripts\Prepare-Upgrade.ps1
```

Solo cuando indique `Preparacion completada`:

```powershell
.\scripts\Start-Release.ps1
```

Si Start-Release termina correctamente:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
```

La version esperada sigue siendo 0.4.2. Si cualquier etapa falla, detente y
conserva el primer error; no ejecutes la siguiente etapa.

## Validacion y limites

Se inspeccionaron los ocho archivos PowerShell del ZIP v0.4.2 real. Se verifico
con Python que el cambio al script existente se limita a los dos defectos
anteriores y se revisaron patrones de interpolacion ambigua y asignaciones a
HOME/HOST/PID/PSHOME. El diff y el informe estan en evidence/.

Este entorno NO tiene PowerShell ni Docker. Un intento de obtener PowerShell
fallo por DNS. No se ejecuto aqui el parser nativo, el nuevo verificador ni una
actualizacion Docker/Windows. La comprobacion nativa se debe ejecutar en el equipo
del usuario; un resultado verde de sintaxis tampoco prueba los montajes, backup,
captura del modelo o inicio de la imagen.

Fuentes oficiales:
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_quoting_rules
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_case-sensitivity
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables
- https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.parser.parsefile
