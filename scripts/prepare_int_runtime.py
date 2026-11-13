"""Prepare a source/model-only INT context outside the installation.

Weights are copied only from the explicit, public revision/hash manifest. No
operator data, Git credentials, state, CI tools or browser enter this context.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.request

try:
    from scripts import prepare_ci_context as context
except ModuleNotFoundError:
    import prepare_ci_context as context

ROOT_FILES = ("Dockerfile.int", "Dockerfile.int.dockerignore", "requirements-int.lock")
MODEL_LOCK = "config/whisper-int.json"
SOURCE_DIRS = {"app": {".py"}, "app/cloud": {".py"}, "app/static": {".html", ".js", ".css"}}


def _records(source, weights):
    records = {name: source / name for name in (*ROOT_FILES, MODEL_LOCK)}
    for directory, suffixes in SOURCE_DIRS.items():
        folder = source / directory
        context._check_components(folder)
        for entry in folder.iterdir():
            # No traversal of unknown/private folders, including development data.
            if entry.suffix.lower() in suffixes and not context._private(entry.name):
                records[f"{directory}/{entry.name}"] = entry
    context._check_components(source / MODEL_LOCK)
    lock = json.loads((source / MODEL_LOCK).read_text(encoding="utf-8"))
    if (lock.get("schema") != 1 or lock.get("model") != "tiny"
            or lock.get("repo_id") != "Systran/faster-whisper-tiny"
            or not re.fullmatch(r"[a-f0-9]{40}", lock.get("revision", ""))):
        raise context.ContextError("Unrecognized public Whisper model manifest")
    snapshot = "hub/models--Systran--faster-whisper-tiny/snapshots/" + lock["revision"]
    if {f.get("name") for f in lock["files"]} != {"model.bin", "config.json", "tokenizer.json", "vocabulary.txt"}:
        raise context.ContextError("Unexpected model inventory")
    for item in lock["files"]:
        if not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")) or type(item.get("bytes")) is not int:
            raise context.ContextError("Invalid model hash/size")
        filename = weights / snapshot / item["name"]
        record = context._stream_record(filename)
        if record != {"bytes": item["bytes"], "sha256": item["sha256"]}:
            raise context.ContextError("Public model differs from pinned bytes")
        records[f"weights/{snapshot}/{item['name']}"] = filename
    return records


def _permitted_name(name):
    if name in (*ROOT_FILES, MODEL_LOCK):
        return True
    p = Path(name)
    if any(context._private(part) for part in p.parts):
        return False
    if p.parent.as_posix() in SOURCE_DIRS:
        return p.suffix.lower() in SOURCE_DIRS[p.parent.as_posix()]
    return re.fullmatch(r"weights/hub/models--Systran--faster-whisper-tiny/snapshots/[a-f0-9]{40}/(?:model.bin|config.json|tokenizer.json|vocabulary.txt)", name) is not None


def prepare(source, weights, destination, manifest):
    source, weights, destination, manifest = map(context._absolute, (source, weights, destination, manifest))
    context._separate(source, weights, destination, manifest)
    for path in (source, weights, destination.parent, manifest.parent):
        context._check_components(path)
    records = _records(source, weights)
    before = {name: context._stream_record(path) for name, path in records.items()}
    destination.mkdir()
    for name, path in records.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if context._stream_record(path, target) != before[name]:
            raise context.ContextError("Runtime source drift")
    if _records(source, weights) != records or any(context._stream_record(p) != before[n] for n, p in records.items()):
        raise context.ContextError("Runtime source drift")
    value = {"schema": "clipforge-int-context-1", "files": [{"path": n, **v} for n, v in sorted(before.items())]}
    with manifest.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2); output.write("\n")
    return verify(destination, manifest)


def verify(destination, manifest):
    destination, manifest = map(context._absolute, (destination, manifest))
    context._separate(destination, manifest)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    if value.get("schema") != "clipforge-int-context-1":
        raise context.ContextError("Unknown runtime context manifest")
    expected = {}
    for item in value["files"]:
        name = item["path"]
        p = Path(name)
        if p.is_absolute() or ".." in p.parts or "\\" in name or name in expected or not _permitted_name(name):
            raise context.ContextError("Invalid runtime context manifest path")
        expected[name] = {"bytes": item["bytes"], "sha256": item["sha256"]}
    folders = {p.parent.as_posix() for name in expected for p in (Path(name), *Path(name).parents) if p.parent.as_posix() != "."}
    actual = {}
    def walk(folder):
        with os.scandir(folder) as entries:
            for entry in entries:
                path = Path(entry.path)
                name = path.relative_to(destination).as_posix()
                metadata = context._checked_stat(path)
                if stat.S_ISDIR(metadata.st_mode):
                    if name not in folders:
                        raise context.ContextError("Unexpected runtime context directory")
                    walk(path)
                else:
                    if name not in expected:
                        raise context.ContextError("Unexpected runtime context file")
                    actual[name] = context._stream_record(path)
    context._check_components(destination)
    walk(destination)
    if actual != expected:
        raise context.ContextError("Runtime context inventory/hash mismatch")
    return {"status": "ok", "files": len(expected), "bytes": sum(x["bytes"] for x in expected.values())}


def fetch(source, weights):
    """Explicit public-only preparation; never import application configuration."""
    source, weights = map(context._absolute, (source, weights))
    context._separate(source, weights)
    context._check_components(source / MODEL_LOCK)
    context._check_components(weights.parent)
    lock = json.loads((source / MODEL_LOCK).read_text(encoding="utf-8"))
    if (lock.get("schema") != 1 or lock.get("repo_id") != "Systran/faster-whisper-tiny"
            or lock.get("model") != "tiny" or not re.fullmatch(r"[a-f0-9]{40}", lock.get("revision", ""))
            or {f.get("name") for f in lock["files"]} != {"model.bin", "config.json", "tokenizer.json", "vocabulary.txt"}):
        raise context.ContextError("Unrecognized public model manifest")
    weights.mkdir()
    snapshot = weights / "hub" / "models--Systran--faster-whisper-tiny" / "snapshots" / lock["revision"]
    snapshot.mkdir(parents=True)
    for item in lock["files"]:
        if not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")) or type(item.get("bytes")) is not int:
            raise context.ContextError("Invalid model hash/size")
        url = "https://huggingface.co/Systran/faster-whisper-tiny/resolve/" + lock["revision"] + "/" + item["name"]
        digest, size = hashlib.sha256(), 0
        with urllib.request.urlopen(url, timeout=60) as response, (snapshot / item["name"]).open("xb") as output:
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > item["bytes"]:
                    raise context.ContextError("Public model exceeds pinned size")
                digest.update(block); output.write(block)
        if size != item["bytes"] or digest.hexdigest() != item["sha256"]:
            raise context.ContextError("Public model differs from pinned bytes")
    return {"status": "ok", "model_revision": lock["revision"], "files": len(lock["files"])}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["prepare", "verify", "fetch"])
    p.add_argument("--source", type=Path)
    p.add_argument("--weights", type=Path)
    p.add_argument("--context", type=Path)
    p.add_argument("--manifest", type=Path)
    args = p.parse_args(argv)
    try:
        if args.action == "fetch":
            if not args.source or not args.weights:
                p.error("fetch requires --source and --weights")
            result = fetch(args.source, args.weights)
        elif not args.context or not args.manifest:
            p.error("prepare/verify requires --context and --manifest")
        elif args.action == "prepare":
            if not args.source or not args.weights:
                p.error("prepare requires --source and --weights")
            result = prepare(args.source, args.weights, args.context, args.manifest)
        else:
            result = verify(args.context, args.manifest)
        print(json.dumps(result)); return 0
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}), file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
