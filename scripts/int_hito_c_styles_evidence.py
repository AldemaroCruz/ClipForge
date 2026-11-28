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


def native_report(root, name, expected):
    path = root / name
    if root.is_symlink() or path.is_symlink():
        raise ValueError("Símbolo de archivo en el recibo de aceptación")
    with path.open("rb") as source:
        raw = source.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"Hash incorrecto para {name}")
    return json.loads(raw)


def verify(root, commit, model):
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or commit == BASE:
        raise ValueError("La candidata C04 debe tener su propio commit")
    rollout, preview, load, cuts, editorial = (native_report(root, name, digest) for name, digest in REPORTS.items())
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


def verify_product_release(root, commit, model, phase, accepted_commit, run, artifact, rollout_digest, browser_digest):
    if (not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(r"[a-f0-9]{40}", accepted_commit)
            or commit == accepted_commit):
        raise ValueError("La candidata debe descender del incremento aceptado")
    if phase == "styles":
        increment = "c05"
        required = {
            "normal_creator_style_persisted_after_relogin",
            "normal_other_creator_cannot_list_same_style_or_read_mutate_it",
            "confirmed_project_style_applied_to_all_preserving_each_cue",
            "style_in_export_and_caption_sidecars",
            "default_style_snapshotted_on_new_work_and_render",
            "template_update_and_delete_preserve_applied_values_and_export_bytes",
        }
    else:
        increment = "c06"
        required = {
            "normal_creator_framing_preview_and_two_approved_renders_match",
            "reopen_preserves_crop_styles_text_times_and_previous_mp4",
        }
    expected = {"after-rollout.json": rollout_digest, f"browser-{phase}.json": browser_digest}
    rollout, browser = (native_report(root, name, digest) for name, digest in expected.items())
    revisions = {"frontend": rollout["frontend_revision"], "api": rollout["api_revision"]}
    passed = {entry["name"] for entry in browser["checks"] if entry["status"] == "passed"}
    if (rollout["commit"] != accepted_commit or rollout["editorial"]["model"] != model
            or rollout["editorial"]["daily_limit"] != 100 or browser["commit"] != accepted_commit
            or browser["revisions"] != revisions or browser["status"] != "passed"
            or browser["phase"] != phase or not required <= passed):
        raise ValueError("La evidencia no corresponde al incremento aceptado")
    return {
        "schema": f"clipforge-int-{increment}-baseline-1", "status": "passed", "target_commit": commit,
        "baseline": rollout, "evidence": {"run_id": run, "artifact_id": artifact, "sha256": expected},
    }


def verify_logos_baseline(root, profile, commit, model):
    accepted = "cbfb913190f5893df371e8ba156ebc7976a2058a"
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or commit == accepted:
        raise ValueError("La candidata de logos debe tener su propio commit")
    hashes = {
        "after-rollout.json": "4e86068cc6b39723457471c8361a0ddd879d954e2eaa23fedfb34e38bcf3880b",
        "browser-zip.json": "fbb048ba2f36b986e217d6703a3bba996c941542bd7a27bc840f7bb7caee747c",
        "worker-profile-adopted.json": "cb11601d2f7bf2297afe6a82330ae2fdd56517131f89a004674f7f3ef3f5a861",
    }
    rollout = native_report(root, "after-rollout.json", hashes["after-rollout.json"])
    browser = native_report(root, "browser-zip.json", hashes["browser-zip.json"])
    adoption = native_report(profile, "worker-profile-adopted.json", hashes["worker-profile-adopted.json"])
    pinned_public = adoption["public"]
    worker = adoption["adopted_worker"]
    revisions = {"frontend": rollout["frontend_revision"], "api": rollout["api_revision"]}
    checks = {entry["name"] for entry in browser["checks"] if entry["status"] == "passed"}
    if (rollout["commit"] != accepted or browser["commit"] != accepted or browser["revisions"] != revisions
            or browser["phase"] != "zip" or browser["status"] != "passed"
            or "zip_stream_over_32_mib_matches_individual_files" not in checks
            or any(pinned_public[key] != rollout[key] for key in pinned_public)
            or adoption["status"] != "passed" or worker["generation"] != worker["observed_generation"]
            or worker["cpu"] != "4" or worker["memory"] != "4Gi"
            or rollout["editorial"]["model"] != model or rollout["editorial"]["daily_limit"] != 100):
        raise ValueError("La base no coincide con el portal y worker aceptados")
    return {
        "schema": "clipforge-int-logos-baseline-1", "status": "passed", "target_commit": commit,
        "baseline": {**rollout, "worker_image": worker["image"], "worker_source": worker["source"],
                     "worker_cpu": worker["cpu"], "worker_memory": worker["memory"]},
        "evidence": {"c06_run": "46088385849", "c06_artifact": "15241015222",
                     "profile_run": "46092661387", "profile_artifact": "15241319365", "sha256": hashes},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    group = parser.add_mutually_exclusive_group()
    for phase in ("styles", "framing"):
        group.add_argument("--accepted-" + phase, nargs=5,
                           metavar=("SHA", "RUN", "ARTIFACT", "ROLLOUT_HASH", "BROWSER_HASH"))
    group.add_argument("--accepted-logo-profile", type=Path, metavar="PROFILE_RECEIPT_DIR")
    args = parser.parse_args()
    if args.accepted_styles:
        receipt = verify_product_release(args.source, args.commit, args.model, "styles", *args.accepted_styles)
    elif args.accepted_framing:
        receipt = verify_product_release(args.source, args.commit, args.model, "framing", *args.accepted_framing)
    elif args.accepted_logo_profile:
        receipt = verify_logos_baseline(args.source, args.accepted_logo_profile, args.commit, args.model)
    else:
        receipt = verify(args.source, args.commit, args.model)
    with args.receipt.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2, ensure_ascii=False)
        output.write("\n")


if __name__ == "__main__":
    main()
