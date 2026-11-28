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


def verify_caption_color_baseline(root, commit, model):
    accepted = "fb83fd49e077dc95f4720ad9f4922cd9c5340bc9"
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or commit == accepted:
        raise ValueError("Se requiere una candidata distinta de la base de color")
    hashes = {
        "after-rollout.json": "6151e4bab57b3e125ff3294b010bbd5b55e53786ac24c010e8448c6bb5ca95e7",
        "browser-logos.json": "49e8c41e7fa2ddc53d2545258ef3fd3bf4671d936599c47a658064fac54cf2ce",
    }
    rollout, browser = (native_report(root, name, digest) for name, digest in hashes.items())
    worker = rollout["worker_configuration"]
    revisions = {"frontend": rollout["frontend_revision"], "api": rollout["api_revision"]}
    approved = {entry["name"] for entry in browser["checks"] if entry["status"] == "passed"}
    required = {"automatic_logo_preview_export_and_zip_use_the_same_variant_and_sidecars",
                "range_word_style_logo_crop_preview_and_edited_download",
                "retired_logo_and_deleted_template_preserve_drafts_and_mp4_after_relogin"}
    if (rollout["commit"] != accepted or browser["commit"] != accepted or browser["revisions"] != revisions
            or browser["phase"] != "logos" or browser["status"] != "passed" or not required <= approved
            or rollout["editorial"]["model"] != model or rollout["editorial"]["daily_limit"] != 100
            or worker["cpu"] != "4" or worker["memory"] != "4Gi"):
        raise ValueError("La base no coincide con la entrega aceptada de logos")
    return {
        "schema": "clipforge-int-caption-color-baseline-1", "status": "passed", "target_commit": commit,
        "baseline": {**rollout, "worker_source": accepted, "worker_cpu": worker["cpu"],
                     "worker_memory": worker["memory"]},
        "evidence": {"run_id": "46098994059", "artifact_id": "15245332058", "sha256": hashes},
    }


def verify_mixed_zip_baseline(root, commit, model, accepted, run, artifact, rollout_digest, browser_digest):
    if (not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(r"[a-f0-9]{40}", accepted)
            or commit == accepted):
        raise ValueError("La ampliación del ZIP requiere una revisión distinta de la corrección aceptada")
    hashes = {"after-rollout.json": rollout_digest, "browser-caption-color.json": browser_digest}
    rollout, browser = (native_report(root, name, digest) for name, digest in hashes.items())
    worker = rollout["worker_configuration"]
    revisions = {"frontend": rollout["frontend_revision"], "api": rollout["api_revision"]}
    approved = {entry["name"] for entry in browser["checks"] if entry["status"] == "passed"}
    required = {"template_recovered_and_applied_to_another_clip_with_cues_unchanged",
                "two_downloaded_mp4s_show_distinct_caption_colors_with_identical_sidecars"}
    if (rollout["commit"] != accepted or browser["commit"] != accepted or browser["revisions"] != revisions
            or browser["phase"] != "caption-color" or browser["status"] != "passed" or not required <= approved
            or rollout["editorial"]["model"] != model or rollout["editorial"]["daily_limit"] != 100
            or worker["cpu"] != "4" or worker["memory"] != "4Gi"):
        raise ValueError("La ampliación requiere la aceptación nativa de la corrección de color")
    return {
        "schema": "clipforge-int-mixed-zip-baseline-1", "status": "passed", "target_commit": commit,
        "baseline": {**rollout, "worker_source": accepted, "worker_cpu": worker["cpu"],
                     "worker_memory": worker["memory"]},
        "evidence": {"run_id": run, "artifact_id": artifact, "sha256": hashes},
    }


def verify_d01_baseline(root, commit, model):
    accepted = "86ab0a9f4dd5de69fd14b766320db16a570f0b1e"
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or commit == accepted:
        raise ValueError("D01 requiere una candidata distinta de la versión aceptada")
    hashes = {
        "after-rollout.json": "4d1b67b582b9d0b1c6fede0f67c1f36c7a436aaf64e10456bf0ebffdac3acf80",
        "browser-mixed-zip.json": "3a6528a29118f8dc5aa8b1275ffccc48ebe80de58a0e9940941444281aab356a",
    }
    rollout, browser = (native_report(root, name, digest) for name, digest in hashes.items())
    worker = rollout["worker_configuration"]
    revisions = {"frontend": rollout["frontend_revision"], "api": rollout["api_revision"]}
    approved = {entry["name"] for entry in browser["checks"] if entry["status"] == "passed"}
    if (rollout["commit"] != accepted or browser["commit"] != accepted or browser["revisions"] != revisions
            or browser["phase"] != "mixed-zip" or browser["status"] != "passed"
            or "automatic_manual_editorial_zip_matches_individual_downloads_byte_for_byte" not in approved
            or rollout["editorial"]["model"] != model or rollout["editorial"]["daily_limit"] != 100
            or worker["cpu"] != "4" or worker["memory"] != "4Gi"):
        raise ValueError("La evidencia no corresponde a la base editorial y de ZIP de INT")
    return {
        "schema": "clipforge-int-d01-baseline-1", "status": "passed", "target_commit": commit,
        "baseline": {**rollout, "worker_source": accepted, "worker_cpu": worker["cpu"], "worker_memory": worker["memory"]},
        "evidence": {"run_id": "46111969891", "artifact_id": "15251015617", "sha256": hashes},
    }


def verify_d01_provider(root, commit, model):
    original = "0e7738b9107451ee34e2783d2646aabfdce2f027"
    run_id, artifact_id = "46116426162", "15252033378"
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or commit == original:
        raise ValueError("La continuación de D01 requiere una corrección descendiente")
    hashes = {
        "after-rollout.json": "0db413342f548ae642286ddd8d3c99966b272ef3ec7c40d0f835bbfc804fef90",
        "browser-d01-prepare.json": "9036dd6d02425afa3a5cb05f011fa41a020ffc98d338399d279f8c916940a792",
        "browser-d01.json": "286890cb1761e29502e90b5efc3a6346447d1a0386e253e83e45e785e0abff13",
    }
    rollout, prepared, browser = (native_report(root, name, digest) for name, digest in hashes.items())
    approved = {entry["name"] for entry in browser["checks"] if entry["status"] == "passed"}
    required = {"d01_three_explicit_searches_and_idempotent_replays",
                "d01_relogin_restores_queries_and_private_results_desktop_and_narrow"}
    expected_usage = {"reservations": 3, "calls": 3, "responses": 3}
    revisions = {"frontend": rollout["frontend_revision"], "api": rollout["api_revision"]}
    if (rollout["commit"] != original or browser["commit"] != original or browser["revisions"] != revisions
            or prepared["status"] != "passed" or prepared["phase"] != "d01-prepare"
            or prepared["fixture"]["duration_seconds"] != 1200 or prepared["fixture"]["content"] != "synthetic_spoken_topics"
            or browser["phase"] != "d01" or browser["status"] != "failed"
            or browser["failure"] != "d01_draft_export_and_exact_zip" or not required <= approved
            or rollout["editorial"]["model"] != model or rollout["editorial"]["daily_limit"] != 100
            or browser["daily_limit_utc"] != 100 or browser["usage"] != expected_usage):
        raise ValueError("La evidencia real de D01 no corresponde al tramo aceptado")
    searches = browser["searches"]
    if (len(searches) != 3 or len({item["transcript_sha256"] for item in searches}) != 1
            or [item["outcome"] for item in searches] != ["matches", "matches", "no_matches"]
            or searches[2]["proposals"]
            or any(item["status"] != "completed" or item["provider"] != "openai" or item["model"] != model
                   or item["models_received"] != [model] or len(item["provider_call_intervals"]) != 1
                   or item["last_transcript_end"] != 1181 or item["windows"] != [
                       {"start": 0, "end": 1200, "segments": 9, "eligible_ranges": 9}]
                   or any(item[key] != 1 for key in expected_usage) for item in searches)):
        raise ValueError("Las búsquedas D01 no acreditan tres llamadas reales sobre la misma transcripción")
    late = searches[1]
    proposal, = late["proposals"]
    if (late["topic"] != "reparar el freno de una bicicleta"
            or (proposal["start"], proposal["end"], proposal["range_id"]) != (1142, 1181, "r6_9")
            or proposal["evidence"]["segment_id"] != 6):
        raise ValueError("La propuesta tardía no coincide con el intervalo comprobado")
    replay = {"source_commit": original, "run_id": run_id, "search_id": late["id"],
              "report_sha256": hashes["browser-d01.json"], "video_sha256": prepared["fixture"]["sha256"],
              "transcript_sha256": late["transcript_sha256"], "model": model,
              "range_id": proposal["range_id"], "evidence_segment": proposal["evidence"]["segment_id"]}
    return {"schema": "clipforge-int-d01-provider-continuation-1", "status": "passed",
            "target_commit": commit, "original_usage": expected_usage, "replay": replay,
            "evidence": {"run_id": run_id, "artifact_id": artifact_id, "sha256": hashes}}


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
    group.add_argument("--accepted-caption-color-base", action="store_true")
    group.add_argument("--accepted-mixed-zip-base", nargs=5,
                       metavar=("SHA", "RUN", "ARTIFACT", "ROLLOUT_HASH", "BROWSER_HASH"))
    group.add_argument("--accepted-d01-base", action="store_true")
    group.add_argument("--accepted-d01-provider-base", action="store_true")
    args = parser.parse_args()
    if args.accepted_styles:
        receipt = verify_product_release(args.source, args.commit, args.model, "styles", *args.accepted_styles)
    elif args.accepted_framing:
        receipt = verify_product_release(args.source, args.commit, args.model, "framing", *args.accepted_framing)
    elif args.accepted_logo_profile:
        receipt = verify_logos_baseline(args.source, args.accepted_logo_profile, args.commit, args.model)
    elif args.accepted_caption_color_base:
        receipt = verify_caption_color_baseline(args.source, args.commit, args.model)
    elif args.accepted_mixed_zip_base:
        receipt = verify_mixed_zip_baseline(args.source, args.commit, args.model, *args.accepted_mixed_zip_base)
    elif args.accepted_d01_base:
        receipt = verify_d01_baseline(args.source, args.commit, args.model)
    elif args.accepted_d01_provider_base:
        receipt = verify_d01_provider(args.source, args.commit, args.model)
    else:
        receipt = verify(args.source, args.commit, args.model)
    with args.receipt.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2, ensure_ascii=False)
        output.write("\n")


if __name__ == "__main__":
    main()
