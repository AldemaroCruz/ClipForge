"""Runtime packaging refuses credentials, substituted models and context drift."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from scripts import prepare_int_runtime as runtime


class RuntimeContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clipforge-int-context-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.weights = self.root / "source", self.root / "weights"
        self.source.mkdir(); self.weights.mkdir()
        for name in (*runtime.ROOT_FILES, "app/main.py", "app/cloud/__init__.py", "app/static/index.html"):
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("synthetic fixture")
        revision = "b" * 40
        snapshot = self.weights / "hub" / "models--Systran--faster-whisper-tiny" / "snapshots" / revision
        snapshot.mkdir(parents=True)
        files = []
        for name in ("model.bin", "config.json", "tokenizer.json", "vocabulary.txt"):
            data = ("synthetic " + name).encode(); (snapshot / name).write_bytes(data)
            files.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        lock = {"schema": 1, "model": "tiny", "repo_id": "Systran/faster-whisper-tiny", "revision": revision, "files": files}
        path = self.source / runtime.MODEL_LOCK; path.parent.mkdir(); path.write_text(json.dumps(lock))
        self.destination, self.manifest = self.root / "context", self.root / "manifest.json"

    def prepare(self):
        return runtime.prepare(self.source, self.weights, self.destination, self.manifest)

    def test_round_trip_excludes_unrelated_private_sources(self):
        (self.source / "app" / "credentials.json").write_text("private synthetic")
        (self.source / ".env").write_text("private synthetic")
        self.assertEqual(self.prepare()["status"], "ok")
        self.assertFalse((self.destination / ".env").exists())
        self.assertFalse((self.destination / "app/credentials.json").exists())

    def test_model_substitution_rejected_before_context_creation(self):
        next(self.weights.rglob("model.bin")).write_bytes(b"changed")
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.destination.exists())

    def test_drift_and_injected_private_tree_rejected(self):
        self.prepare()
        (self.destination / "app/main.py").write_text("changed")
        with self.assertRaises(ValueError): runtime.verify(self.destination, self.manifest)
        (self.destination / "credentials").mkdir()
        with self.assertRaises(ValueError): runtime.verify(self.destination, self.manifest)

    def test_private_path_even_in_forged_manifest_rejected(self):
        self.prepare()
        value = json.loads(self.manifest.read_text()); value["files"].append({"path": ".env", "bytes": 1, "sha256": "a" * 64})
        self.manifest.write_text(json.dumps(value))
        with self.assertRaises(ValueError): runtime.verify(self.destination, self.manifest)


if __name__ == "__main__": unittest.main()
