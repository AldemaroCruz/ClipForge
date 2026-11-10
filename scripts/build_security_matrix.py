"""Build the complete SEC-01 baseline ledger from immutable CI evidence, offline.

Official responses must be fetched separately and cached with their URL/time and
HTTP status. Missing scanner fields remain missing; Debian fixes are restricted
to the requested release and are never applied to PyPI wheels.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re


RAW_FIELDS = ("SeveritySource", "SrcName", "FixedVersion", "Status", "DataSource")
REGRESSIONS = {
    "OS": "Verificar candidato/paquete fuente/versión con APT y dpkg de la misma suite; rebuild por digest; pip check, imports nativos, suite completa sin omisiones, SBOM y reescaneo de la misma imagen.",
    "MEDIA": "Además de OS: checks reales media/presentation/branding; FFmpeg/ffprobe, audio AAC/WAV/VAD, MP4/subtítulos/plantillas, entrega ZIP y recuperación con fixtures sintéticos.",
    "API": "Resolver FastAPI/Starlette/multipart sin forzar incompatibilidades; pip check; API/editorial/entregas, carga multipart, FileResponse/Range y suite completa; reescaneo del mismo artefacto.",
}
PYTHON_TESTS = {
    "CVE-2026-24486": "Filenames absolutos/traversal con configuración de upload no predeterminada en directorio temporal; ninguna escritura fuera del destino; conservar upload normal.",
    "CVE-2026-42561": "Part headers excesivos/repetidos y header individual sobredimensionado; rechazo acotado y uploads válidos preservados, sin ejecutar cargas contra el servicio activo.",
    "CVE-2026-53539": "Querystring con separadores ';' y '&', semántica del parser parcheado y límites; una prueba funcional no acredita complejidad temporal ni resistencia DoS.",
    "CVE-2025-62727": "FileResponse/Range prefix/suffix/open, múltiples rangos/solapamiento, If-Range y 416; verificar el cambio del parser sin presentar esos casos como benchmark DoS.",
    "CVE-2026-48818": "StaticFiles rechaza UNC/rutas absolutas antes de resolver rutas remotas; validar Windows mediante fixture aislado sin red/SMB. El finding no se elimina por usar Linux.",
    "CVE-2026-54283": "Request.form urlencoded con max_fields=2 y tercer campo ->400; max_part_size cuenta nombre+valor raw: límite4 acepta a=123 y rechaza a=1234; multipart normal preservado.",
}


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def raw_field(record: dict, name: str) -> dict:
    return {"present": name in record, "value": record.get(name)}


def visible(field: dict) -> str:
    if not field["present"]:
        return "ausente"
    if field["value"] is None:
        return "null (presente)"
    if isinstance(field["value"], dict):
        value = field["value"]
        return " / ".join(str(value[key]) for key in ("ID", "Name", "URL") if key in value)
    return str(field["value"])


def source_version(package: dict) -> str | None:
    version = package.get("SrcVersion")
    if not version:
        return None
    if package.get("SrcRelease"):
        version += "-" + package["SrcRelease"]
    if package.get("SrcEpoch"):
        version = str(package["SrcEpoch"]) + ":" + version
    return version


def dpkg_inventory(path: Path) -> dict:
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 8:
            raise ValueError("Unexpected baseline dpkg inventory columns (expected 8, no header).")
        name, version, src, src_version, depends, predepends, essential, priority = parts
        key = name.split(":", 1)[0]
        if key in result:
            raise ValueError("Ambiguous binary package in baseline dpkg inventory.")
        result[key] = dict(binary_name=name, version=version, source_name=src,
                           source_version=src_version, depends=depends, predepends=predepends,
                           essential=essential, priority=priority)
    return result


def shortest_path(packages: list[dict], target: str) -> list[str]:
    nodes = {item["ID"]: item for item in packages if item.get("ID")}
    queue = deque(([item["ID"]] for item in packages
                   if item.get("Name") in {"ffmpeg", "fonts-dejavu-core"} and item.get("ID")))
    seen = set()
    while queue:
        path = queue.popleft()
        current = path[-1]
        if current == target:
            return path
        if current in seen:
            continue
        seen.add(current)
        for dependency in nodes.get(current, {}).get("DependsOn", []):
            if dependency not in seen:
                queue.append([*path, dependency])
    return []


def verified_response(record: dict) -> None:
    if record.get("http_status") != 200 or not record.get("url", "").startswith("https://") or not record.get("retrieved_at_utc"):
        raise ValueError("Official evidence lacks a successful HTTPS retrieval record.")


def official_debian(cache: dict, source: str | None, cve: str, release: str) -> dict:
    verified_response(cache)
    entry = cache["data"].get(source, {}).get(cve)
    if entry is None:
        raise ValueError(f"Missing official Debian record for {source}/{cve}.")
    status = entry.get("releases", {}).get(release)
    if status is None:
        raise ValueError(f"Missing official {release} release status for {source}/{cve}.")
    fixed = status.get("fixed_version")
    if status.get("status") == "resolved" and fixed not in (None, "0"):
        remediation = f"Candidato de backport {release}: {source} {fixed}; verificar binario exacto en APT del snapshot aprobado e instalar solo los paquetes necesarios. No ejecutado."
        decision = "candidate_same_release"
    elif status.get("status") == "open":
        remediation = f"Bloqueado: Debian {release} mantiene {source}/{cve} abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot."
        decision = "blocked_no_same_release_fix"
    else:
        remediation = f"Revisión pendiente: estado oficial {status.get('status')}, fixed_version={fixed!r}; no inferir una versión corregida ni crear VEX/allowlist."
        decision = "review_required"
    return {"kind": "debian-source-release", "url": f"https://security-tracker.debian.org/tracker/{cve}",
            "source_package_url": f"https://security-tracker.debian.org/tracker/source-package/{source}",
            "cache_url": cache["url"], "retrieved_at_utc": cache["retrieved_at_utc"],
            "release": release, "status": status.get("status"),
            "fixed_version": raw_field(status, "fixed_version"), "release_record": status,
            "other_releases": {name: value for name, value in entry.get("releases", {}).items() if name != release},
            "decision": decision, "minimum_correction": remediation}


def official_python(cache: dict, package: str, cve: str) -> dict:
    record = cache[cve]
    verified_response(record)
    advisory = record["data"]
    if advisory.get("cve_id") != cve:
        raise ValueError("Advisory CVE identity mismatch.")
    entries = [item for item in advisory.get("vulnerabilities", [])
               if item.get("package", {}).get("ecosystem") == "pip"
               and item["package"].get("name", "").lower() == package.lower()]
    if len(entries) != 1:
        raise ValueError("Expected one matching official PyPI advisory range.")
    finding = entries[0]
    fixed = finding.get("first_patched_version")
    if not fixed:
        raise ValueError("Official Python advisory does not publish a patched version.")
    return {"kind": "project-ghsa-pypi", "url": record["project_url"], "api_url": record["url"],
            "retrieved_at_utc": record["retrieved_at_utc"], "ghsa_id": advisory["ghsa_id"],
            "status": "patched_release_published", "fixed_version": {"present": True, "value": fixed},
            "vulnerable_range": finding["vulnerable_version_range"], "severity_official": advisory.get("severity"),
            "withdrawn_at": advisory.get("withdrawn_at"), "decision": "candidate_pypi_bundle",
            "minimum_correction": f"PyPI {package}>={fixed} para este CVE. Para cerrar los tres del paquete se requiere "
                + ("python-multipart>=0.0.30." if package == "python-multipart" else "Starlette>=1.3.1 y FastAPI compatible; 0.115.12 exige Starlette<0.47.")
                + " Resolver y fijar el bundle deliberadamente, sin --no-deps/override incompatible; aún no ejecutado."}


def build(args) -> dict:
    report, sbom, debian, advisories, pypi = map(read_json, (args.report, args.sbom, args.debian, args.advisories, args.pypi))
    dpkg = dpkg_inventory(args.dpkg)
    components = {item.get("purl"): item for item in sbom.get("components", []) if item.get("purl")}
    rows = []
    for result in report.get("Results", []):
        packages = result.get("Packages", [])
        by_id = {package["ID"]: package for package in packages if package.get("ID")}
        for finding in result.get("Vulnerabilities", []):
            name, version, cve = finding["PkgName"], finding["InstalledVersion"], finding["VulnerabilityID"]
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                raise ValueError("Unexpected vulnerability identifier.")
            purl = finding.get("PkgIdentifier", {}).get("PURL")
            package = by_id.get(finding.get("PkgID"), {})
            component = components.get(purl, {})
            props = {prop["name"]: prop["value"] for prop in component.get("properties", [])}
            raw = {field: raw_field(finding, field) for field in RAW_FIELDS}
            if result.get("Class") == "os-pkgs":
                runtime = dpkg[name]
                if runtime["version"] != version:
                    raise ValueError("dpkg binary version differs from the immutable scanner baseline.")
                source, src_version = runtime["source_name"], runtime["source_version"]
                for observed in (package.get("SrcName"), props.get("aquasecurity:trivy:SrcName")):
                    if observed and observed != source:
                        raise ValueError("Debian source-package evidence conflicts.")
                trivy_src_version = source_version(package)
                if trivy_src_version and trivy_src_version != src_version:
                    raise ValueError("Debian source-version evidence conflicts.")
                dependency_path = shortest_path(packages, finding.get("PkgID", ""))
                if dependency_path:
                    intro = "APT CI explícito: " + " → ".join(item.split("@", 1)[0] for item in dependency_path)
                    intro_evidence = "DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci"
                else:
                    ffmpeg_layer = next((item.get("Layer", {}).get("DiffID") for item in packages if item.get("Name") == "ffmpeg"), None)
                    if finding.get("Layer", {}).get("DiffID") == ffmpeg_layer:
                        intro = "Capa APT CI; introductor concreto no resuelto desde las raíces explícitas"
                    else:
                        intro = "Base Python/Debian (inferencia por capa); introductor concreto no identificado"
                    intro_evidence = "DiffID observado, sin inventar una arista de dependencia"
                official = official_debian(debian, source, cve, args.release)
                regressions = ["OS", "MEDIA"] if dependency_path or source == "ffmpeg" else ["OS"]
                scope, origin = "sistema", f"Debian 13.7/{args.release}; dpkg de imagen CI"
                resolved_source = {"name": source, "version": src_version, "evidence": "baseline-dpkg.tsv + Results.Packages/SBOM",
                                   "package_metadata_src_name": raw_field(package, "SrcName"), "dpkg": runtime}
            else:
                package = next((item for item in packages if item.get("Name") == name and item.get("Version") == version), {})
                source, src_version = name, version
                scope, origin, regressions = "app", "Wheel PyPI en imagen CI; no paquete Debian", ["API"]
                dependency_path = []
                if name == "python-multipart":
                    intro, intro_evidence = "requirements.txt → python-multipart==0.0.20 (directa)", "Pin directo en el baseline de fuentes"
                elif name == "starlette":
                    metadata = pypi["fastapi/0.115.12"]
                    verified_response(metadata)
                    constraint = next(item for item in metadata["info"]["requires_dist"] if item.startswith("starlette"))
                    intro = f"requirements.txt → FastAPI 0.115.12 → {constraint} → Starlette 0.46.2"
                    intro_evidence = metadata["url"] + " Requires-Dist; el SBOM no conserva esta arista Python"
                else:
                    raise ValueError("Unexpected affected PyPI package; explicit introductory evidence required.")
                official = official_python(advisories, name, cve)
                resolved_source = {"name": name, "version": version, "evidence": "PyPI distribution/PURL; SrcName de distro no aplicable"}
            rows.append({"target": result["Target"], "class": result.get("Class"), "type": result.get("Type"),
                         "cve": cve, "package": name, "installed_version": version, "purl": purl,
                         "pkg_id": finding.get("PkgID"), "scope": scope, "origin": origin,
                         "severity": finding["Severity"], "raw_fields": raw, "resolved_source": resolved_source,
                         "introduced_by": intro, "intro_evidence": intro_evidence, "dependency_path": dependency_path,
                         "layer": finding.get("Layer"), "fingerprint": finding.get("Fingerprint"),
                         "vendor_severity": finding.get("VendorSeverity"), "cvss": finding.get("CVSS"),
                         "official": official, "regression_codes": regressions,
                         "specific_regression": PYTHON_TESTS.get(cve), "remediation_executed": False})
    rows.sort(key=lambda item: (item["cve"], item["package"], item["installed_version"], item["target"]))
    for index, row in enumerate(rows, 1):
        row["finding_id"] = f"F{index:03d}"
    groups = defaultdict(list)
    for row in rows:
        groups[row["cve"]].append(row["finding_id"])
    if len(rows) != args.expected_findings or len(groups) != args.expected_cves:
        raise ValueError("Baseline counts differ; refusing an incomplete or silently filtered matrix.")
    keys = {(row["target"], row["cve"], row["package"], row["installed_version"], row["pkg_id"]) for row in rows}
    if len(keys) != len(rows):
        raise ValueError("Duplicate findings need explicit handling rather than deduplication.")
    return {"schema": "clipforge-sec01-matrix-1", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "client_date": "2026-11-09", "baseline_artifact_id": report.get("ArtifactID"),
            "os": report.get("Metadata", {}).get("OS"), "release": args.release,
            "counts": {"findings": len(rows), "unique_cves": len(groups), "by_scope": dict(Counter(row["scope"] for row in rows)),
                       "by_severity": dict(Counter(row["severity"] for row in rows)),
                       "missing_scanner_fields": {field: sum(not row["raw_fields"][field]["present"] for row in rows) for field in RAW_FIELDS}},
            "inputs": {name: {"filename": path.name, "sha256": checksum(path)} for name, path in
                       (("report", args.report), ("sbom", args.sbom), ("dpkg", args.dpkg), ("debian", args.debian), ("advisories", args.advisories), ("pypi", args.pypi))},
            "regression_definitions": REGRESSIONS, "groups_by_cve": dict(sorted(groups.items())), "findings": rows}


def cell(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def render(matrix: dict) -> str:
    counts = matrix["counts"]
    lines = ["# SEC-01 — Matriz inicial completa de vulnerabilidades", "",
             "Fecha de contexto: 2026-11-09. Diagnóstico ANTES de cambios de versiones. No acredita remediación, despliegue ni GitHub Actions ejecutado.", "",
             f"Imagen CI baseline: `{matrix['baseline_artifact_id']}`; Debian 13.7/trixie. **{counts['findings']} hallazgos, {counts['unique_cves']} CVEs únicos**; "
             f"{counts['by_scope'].get('sistema', 0)} sistema y {counts['by_scope'].get('app', 0)} app. No son 234 CVEs distintos.", "",
             "La línea base `.ci-local/ci01-ba2ee8bc/trivy-high-critical.json` y su SBOM no se modifican. Esta matriz conserva cada hallazgo, agrupa por CVE y separa campos crudos del scanner de información resuelta con dpkg/SBOM o fuentes oficiales.", "",
             "**Ausente** significa que la clave no existe en el registro de vulnerabilidad original; no se rellena `SeveritySource` con `DataSource`. `SrcName` resuelto desde otro inventario se muestra aparte. `FixedVersion` crudo ausente no se sustituye por un fix de otra suite ni por una versión upstream.", "",
             "| Campo original | Registros donde está ausente |", "|---|---:|"]
    lines.extend(f"| {field} | {number} |" for field, number in counts["missing_scanner_fields"].items())
    lines.extend(["", "## Fuentes y reproducción", "",
                  "Las respuestas oficiales se descargaron por HTTPS con HTTP 200 y fecha UTC, y se filtró la API de Debian a los 60 IDs de esta línea base. El JSON de la matriz conserva esas referencias y los datos por release. Los metadatos PyPI fijan la dependencia introductora y los GHSA del proyecto fijan rangos corregidos; los backports Debian no se aplican a wheels PyPI.", "",
                  "| Entrada | SHA-256 |", "|---|---|"])
    lines.extend(f"| {name}: {item['filename']} | `{item['sha256']}` |" for name, item in matrix["inputs"].items())
    lines.extend(["", "Artefactos detallados: `.ci-local/sec01-06e7d342/diagnosis/matrix/security-matrix.json` y `security-matrix.csv`; caches oficiales `debian-tracker-filtered.json`, `python-advisories.json`, `python-pypi-metadata.json`. No contienen datos editoriales ni credenciales.", "",
                  "```powershell", "py -3.11 -B scripts/build_security_matrix.py `",
                  "  --report .ci-local/ci01-ba2ee8bc/trivy-high-critical.json `",
                  "  --sbom .ci-local/ci01-ba2ee8bc/sbom.cdx.json `",
                  "  --dpkg .ci-local/sec01-06e7d342/baseline-dpkg.tsv `",
                  "  --debian .ci-local/sec01-06e7d342/diagnosis/debian-tracker-filtered.json `",
                  "  --advisories .ci-local/sec01-06e7d342/diagnosis/python-advisories.json `",
                  "  --pypi .ci-local/sec01-06e7d342/diagnosis/python-pypi-metadata.json `",
                  "  --output-dir <directorio-nuevo> --markdown <archivo-nuevo.md>", "```", "",
                  "El generador es stdlib/offline, exige exactamente 234 filas y 60 CVEs para esta línea base y rechaza sobreescribir salidas existentes. La API pública se consulta por separado; no hay consultas pagadas ni uso de la instalación activa.", "",
                  "## Decisiones mínimas antes de implementar", "",
                  "- **Libxml2 bloqueante:** ocho CVEs siguen abiertos en trixie; instalada y disponible `2.12.7+dfsg+really2.9.14-2.1+deb13u3`. La cadena observada es `ffmpeg → libavformat61 → libxml2`. Los fixes de forky/sid no corrigen automáticamente Debian 13. No se propone sustituir librerías de otra distribución.",
                  "- **OS:** de los 54 CVEs del sistema, 52 permanecen abiertos en trixie. Solo los dos de zlib publican aquí una versión corregida para la misma suite: `1:1.3.dfsg+really1.3.1-1+deb13u1`; requiere confirmar APT del snapshot y probar un parche dirigido. No implica cerrar los otros 226 hallazgos OS.",
                  "- **PyPI:** para cerrar los seis hallazgos del conjunto, mínimos publicados `python-multipart>=0.0.30` y `Starlette>=1.3.1`. FastAPI 0.115.12 exige `starlette>=0.40.0,<0.47.0`: no cabe forzar Starlette nueva bajo ese pin. El coordinador debe resolver y justificar un FastAPI compatible conservando transitivas no afectadas cuando sea posible.",
                  "- No se declara ningún falso positivo, VEX, allowlist o excepción por alcance Linux. Una condición de explotación específica se documenta y se prueba; no borra el finding ni abre el gate.", "",
                  "## Selección posterior de candidato: no cambia el baseline", "",
                  "El mínimo `python-multipart>=0.0.30` de los tres CVEs anteriores no equivale a recomendar instalar exactamente 0.0.30. La revisión posterior encontró [GHSA-v9pg-7xvm-68hf / CVE-2026-53540](https://github.com/Kludex/python-multipart/security/advisories/GHSA-v9pg-7xvm-68hf): la página del proyecto lo clasifica LOW (CVSS 3.7), declara afectados `<0.0.31` y corregido `0.0.31`. No se añade a los 234 hallazgos/60 CVEs de la captura HIGH/CRITICAL ni se afirma que solo se introdujo en 0.0.30.", "",
                  "El candidato deliberado pasa a `python-multipart==0.0.31` ([release y wheel oficial](https://pypi.org/project/python-multipart/0.0.31/), SHA-256 `8408153d68a9773291fc1da39a8b85a50044bddbabd2dd72e9229776b7b15e28`), sujeto a resolución y regresiones. Como regresión adicional, una llamada aislada a parse_form con Content-Length negativo debe rechazar antes de leer el stream; no se ejecuta contra el servicio activo. No se declara un VEX por las condiciones de explotación.", "",
                  "El coordinador verificó la frontera de compatibilidad FastAPI 0.132.1 (`starlette<1.0.0`) → [0.133.0](https://pypi.org/pypi/fastapi/0.133.0/json) (`starlette>=0.40.0`), que permite el candidato Starlette 1.3.1. Esa comprobación de frontera no es una auditoría exhaustiva de todas las releases históricas. El conjunto propuesto se valida con constraints de las transitivas no afectadas; no se sustituye por las últimas versiones sin necesidad.", "",
                  "## Regresiones exigidas", ""])
    lines.extend(f"- **{name}:** {description}" for name, description in REGRESSIONS.items())
    lines.extend(["", "Las pruebas de esta matriz son análisis de evidencia y contrastes oficiales. Los tests nuevos de remediación, el nuevo build/SBOM/scan y el navegador permanecen pendientes de ejecución del candidato. Las respuestas ASR/IA de la suite siguen siendo fixtures identificados.", "",
                  "## SAST y herramientas CI", "",
                  "Al iniciar SEC-01 no se encontró SAST de Python en las fuentes inspeccionadas: Gitleaks detecta secretos y Trivy dependencias, no sustituyen un analizador del código. Se propone Bandit **1.9.4**, wheel SHA-256 `f89ffa663767f5a0585ea075f01020207e966a9c0f2b9ef56a57c7963a3f6f8e`, publicado mediante Trusted Publishing en [PyPI](https://pypi.org/project/bandit/1.9.4/) y [release PyCQA](https://github.com/PyCQA/bandit/releases/tag/1.9.4).", "",
                  "Ejecutar en un stage/entorno de herramientas separado, hash-lock transitivo propio, inventario/SBOM/scan propios, snapshot fuente readonly y `--network none`. No instalar Bandit en el runtime app ni ocultar sus paquetes de los scans de herramientas. CLI [oficial](https://bandit.readthedocs.io/en/latest/man/bandit.html):", "",
                  "```text", "python -m bandit -r /source/app /source/scripts --severity-level all --confidence-level all --ignore-nosec --format json --output /reports/bandit.json", "```", "",
                  "Sin skips, baseline de supresión, exclusiones generales ni `--exit-zero`; inicialmente todos los hallazgos bloquean. Los hallazgos legacy exigen revisión y, si requieren cambios de lógica, una propuesta separada. La instalación/ejecución e integración del SAST corresponden al coordinador y no se presentan como ejecutadas por esta matriz.", "",
                  "## Resumen de los 60 CVEs", "", "| CVE | Hallazgos | Source package/distribución | Estado oficial | Fixed oficial aplicable |",
                  "|---|---:|---|---|---|"])
    grouped = defaultdict(list)
    for row in matrix["findings"]:
        grouped[row["cve"]].append(row)
    for cve, rows in grouped.items():
        row, official = rows[0], rows[0]["official"]
        source = row["resolved_source"]["name"] + (" / trixie" if row["scope"] == "sistema" else " / PyPI")
        lines.append(f"| [{cve}]({official['url']}) | {len(rows)} | {cell(source)} | {cell(official['status'])} | {cell(visible(official['fixed_version']))} |")
    lines.extend(["", "## Detalle íntegro por CVE y hallazgo", "",
                  "En cada tabla, `SrcName crudo` conserva el campo del finding; la columna source/versión procede del inventario CI separado. `DataSource` incluye ID, nombre y URL completos en JSON; su ID se muestra aquí y no equivale a `SeveritySource`. Todas las filas conservan target, PURL, capa, evidencia introductora, CVSS/VendorSeverity observados y remediación pendiente en JSON.", ""])
    for cve, rows in grouped.items():
        first, official = rows[0], rows[0]["official"]
        lines.extend([f"### {cve} — {first['resolved_source']['name']} ({len(rows)} hallazgos)", "",
                      f"Fuente verificada: [{official.get('ghsa_id', 'Debian Security Tracker')}]({official['url']}); consulta `{official['retrieved_at_utc']}`. "
                      f"Estado: **{official['status']}**; fixed aplicable: **{visible(official['fixed_version'])}**.", "",
                      "Corrección mínima: " + official["minimum_correction"], ""])
        if official["kind"] == "debian-source-release":
            lines.extend(["Repositorios de trixie observados: " + cell(json.dumps(official["release_record"].get("repositories", {}), ensure_ascii=False)) + ".", ""])
        else:
            lines.extend(["Rango oficial afectado: `" + official["vulnerable_range"] + "`. Distribución instalada: PyPI; no usar las versiones corregidas de paquetes Debian.", ""])
        lines.extend(["| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |",
                      "|---|---|---|---|---|---|---|---|"])
        for row in rows:
            raw = row["raw_fields"]
            data_source = raw["DataSource"]["value"]
            datasource_id = data_source.get("ID", "ausente") if isinstance(data_source, dict) else visible(raw["DataSource"])
            source = row["resolved_source"]
            values = (row["finding_id"], f"{row['package']} @ {row['installed_version']}", f"{source['name']} @ {source['version']}",
                      visible(raw["SrcName"]), f"{row['severity']} / {visible(raw['SeveritySource'])}",
                      f"{visible(raw['Status'])} / {datasource_id}", visible(raw["FixedVersion"]), row["scope"])
            lines.append("| " + " | ".join(cell(value) for value in values) + " |")
        lines.extend(["", "Introductor y origen por fila:", ""])
        for row in rows:
            lines.append(f"- **{row['finding_id']}:** {row['introduced_by']}. Origen: {row['origin']}. Evidencia: {row['intro_evidence']}. Regresiones: {', '.join(row['regression_codes'])}.")
        if first["specific_regression"]:
            lines.extend(["", "Regresión específica: " + first["specific_regression"]])
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("report", "sbom", "dpkg", "debian", "advisories", "pypi", "output-dir", "markdown"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--release", default="trixie")
    parser.add_argument("--expected-findings", type=int, default=234)
    parser.add_argument("--expected-cves", type=int, default=60)
    args = parser.parse_args(argv)
    if args.output_dir.exists() or args.markdown.exists():
        raise FileExistsError("Generated output directory and Markdown file must both be new.")
    matrix = build(args)
    text = render(matrix)
    args.output_dir.mkdir(parents=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "security-matrix.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(matrix, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    with (args.output_dir / "security-matrix.csv").open("x", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("FindingID", "CVE", "Scope", "Package", "InstalledVersion", "SourcePackage", "SourceVersion", "Origin", "Severity",
                         "SeveritySource_RAW", "SrcName_RAW", "FixedVersion_RAW", "Status_RAW", "DataSource_RAW", "IntroducedBy", "OfficialURL",
                         "OfficialStatus", "OfficialFixedVersion", "MinimumCorrection", "Regressions", "SpecificRegression"))
        for row in matrix["findings"]:
            writer.writerow((row["finding_id"], row["cve"], row["scope"], row["package"], row["installed_version"], row["resolved_source"]["name"],
                             row["resolved_source"]["version"], row["origin"], row["severity"],
                             *(visible(row["raw_fields"][name]) for name in RAW_FIELDS), row["introduced_by"], row["official"]["url"],
                             row["official"]["status"], visible(row["official"]["fixed_version"]), row["official"]["minimum_correction"],
                             ",".join(row["regression_codes"]), row["specific_regression"]))
    with args.markdown.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    print(json.dumps(matrix["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
