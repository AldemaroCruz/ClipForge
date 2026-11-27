"""Verify the exact accepted INT baseline before running focused C04 acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import re


BASE = "80c17a6b8f210e24a34f1098ad9968d1f9c72519"
RUN = "46055318253"
ATTEMPT = "2"
ARTIFACT = "15234780121"
SCHEMA = "clipforge-int-c04-baseline-1"
REPORTS = {
    "after-rollout.json": "4e6a7d66f1ddbfce9790cbd7a833c433c83b32aae0613136f9806ea3b65d09f6",
    "browser-verify.json": "a4b8b059dac90a9bddcde073ef9d683d49cdd2f8b5dd37657d1e9f2df6c0792f",
    "browser-capacity-load.json": "31cda99d3bbf7357f3056daeae18545215e43df13ab41b601c67dd129e8f073f",
    "browser-capacity-cuts.json": "ecb20b1c5db47e9d4bbb2c0f34f3f7f3e4f0762c07520f20a2212635ebf2c9a3",
    "browser-capacity.json": "3f9ccc43a534ef36992b6d77b8aa130ecbbbcd7c28acfefb3a0bec50ea7e664d",
}


def native_report(root, name):
    path = root / name
    if root.is_symlink() or path.is_symlink():
        raise ValueError("Símbolo de archivo en el recibo de aceptación")
    with path.open("rb") as source:
        raw = source.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != REPORTS[name]:
        raise ValueError(f"Hash incorrecto para {name}")
    return json.loads(raw)


def verify(root, commit, model):
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or commit == BASE:
        raise ValueError("La candidata C04 debe tener su propio commit")
    rollout, preview, load, cuts, editorial = (native_report(root, name) for name in REPORTS)
    revisions = {"frontend": rollout["frontend_revision"], "api": rollout["api_revision"]}
    if rollout["commit"] != BASE or rollout["editorial"]["model"] != model:
        raise ValueError("Base editorial distinta de la aprobada")
    for receipt in (preview, load, cuts, editorial):
        if receipt["commit"] != BASE or receipt["status"] != "passed" or receipt["revisions"] != revisions:
            raise ValueError("El recibo no corresponde a la versión aceptada")
    for receipt in (load, cuts, editorial):
        if (receipt["run_id"], receipt["run_attempt"]) != (RUN, ATTEMPT):
            raise ValueError("La corrida de capacidad no coincide")
    return {
        "schema": SCHEMA, "status": "passed", "target_commit": commit, "baseline": rollout,
        "evidence": {"run_id": RUN, "attempt": ATTEMPT, "artifact_id": ARTIFACT, "sha256": REPORTS},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    receipt = verify(args.source, args.commit, args.model)
    with args.receipt.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2, ensure_ascii=False)
        output.write("\n")


if __name__ == "__main__":
    main()
