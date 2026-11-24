"""Prepare the exact review-only capsule and integrate an admitted Deploy stdin channel."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import re
from pathlib import Path

from scripts import int_noble_personal_sql_guest as guest


ROOT = Path(__file__).resolve().parent
SQL_PINS = {
    "views": ("20-personal-inspection.sql", "cfa78a0aca0d2ab5fc35e3cbc1fe1902049b167e815a367e074f1ae88ffd1030"),
    "acl": ("29-verify-personal-acl.sql", "c1c977154251ce9fd3c36282f72a7b22738ccad2de49be13de7ef5b9b9bc81b5"),
    "revoke": ("90-revoke-personal.sql", "c5c5170f1a3ffcb0d648f44caf167045152e44dc8996faac263aa81b94a3431c"),
}
AUTHORITY = "clipforge-int-noble-personal-activation-owner-1"
PREFIX = "projects/clipforgebeta2/locations/us-central1/jobs/"
JOBS = {"migrate": "clipforge-int-db01-noble-migration", "app": "clipforge-int-db01-noble-acceptance",
        "admin": "clipforge-int-bootstrap"}
JOB_EFFECTS = {"migrate": "locked_idempotent_migrations", "app": "tls_and_dml_without_data_changes",
               "admin": "one_time_first_administrator"}
INPUTS = {"bootstrap", "tls", "apply", *JOBS}
REVISIONS = ["auth01_0001", "auth02_0002", "cloud01_0001"]
MUTATIONS = {"activate", "revoke"}
STATE = "terraform/int/tf-int-01/default.tfstate"
PRIVATE_ROOT = "private-deploy/int/demo-a/v1/"
RESULT = "clipforge-int-noble-personal-sql-workflow-result-1"
RECOVERED = "activation_reconciled_for_revocation"
ABSENT = "original_key_absent_verified"
REMOVED = {"own_key_removed", "key_already_absent"}
PARTIAL = {"guest_outcome_unknown_reconcile", "guest_cleanup_pending_reconcile"}
RECONCILIATION = {"activation_intent", "activation_partial", "activation_observation"}
MAX_RECEIPT = 512 * 1024
require = guest.require


def digest(value):
    return sha256(value).hexdigest()


def public_file(path, expected, maximum):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= maximum,
            "reviewed_source_is_regular")
    value = path.read_bytes()
    require(digest(value) == expected, "reviewed_source_digest")
    return value


def payload(sql_dir=ROOT / "personal_sql", guest_source=ROOT / "int_noble_personal_sql_guest.py"):
    assets = {key: public_file(sql_dir / name, expected, 16384)
              for key, (name, expected) in SQL_PINS.items()}
    compiled = b"SQL_ASSETS = " + repr(assets).encode("ascii") + b"\n" + guest_source.read_bytes()
    require(len(compiled) <= 48 * 1024, "personal_payload_bound")
    return compiled


def predecessor_names(action, names):
    extras = names - INPUTS
    intent = {"activation_intent"}
    recovery = intent | {"activation_observation"}
    require(INPUTS <= names and extras in {
        "activate": (set(),),
        "observe": (set(), intent, intent | {"activation_partial"}),
        "revoke": ({"activation"}, recovery, RECONCILIATION),
    }[action], "personal_predecessor_set")
    return names


def key_identity(key):
    names = {"public_key_sha256", "fingerprint_sha256", "profile_name_sha256", "created_us", "expiration_us"}
    require(isinstance(key, dict) and set(key) == names and all(
        isinstance(key[name], str) and guest.HASH.fullmatch(key[name]) for name in names if name.endswith("_sha256"))
        and type(key["created_us"]) is type(key["expiration_us"]) is int and key["created_us"] > 0
        and 0 < key["expiration_us"] - key["created_us"] <= 900 * 1_000_000, "personal_original_key_identity")
    return key


def activation_origin(origin):
    require(isinstance(origin, dict) and set(origin) == {"run", "attempt", "decision_sha256", "key"}
            and isinstance(origin["run"], str) and re.fullmatch(r"[1-9][0-9]*", origin["run"])
            and origin["attempt"] == "1" and isinstance(origin["decision_sha256"], str)
            and guest.HASH.fullmatch(origin["decision_sha256"]), "personal_original_attempt_identity")
    key_identity(origin["key"])
    return origin


def receipt_name(commit, run):
    return f"{PRIVATE_ROOT}{commit}/{run}-1/personal-sql-result.json"


def verified_mutation_receipt(old, action, scope, prior_evidence):
    public_fields = guest.COMMON_FIELDS - {"schema"}
    require(isinstance(old, dict) and set(old) == public_fields | {"schema", "status", "observation"}
            and old["schema"] == guest.RESULT and old["action"] == action
            and old["status"] == {"activate": "activated_verified", "observe": "observed"}[action]
            and all(old[key] == scope[key] for key in {*guest.TARGET, "boot_id", "state_generation", "public_ca_sha256"})
            and old["prior_evidence_sha256"] == prior_evidence, "personal_reconciled_guest_receipt")
    guest.check_observation("activate", old["observation"])
    return old["observation"]["activation_marker"]


def verified_recovery(values, pinned, references, scope, now, operation_id):
    reference = references["activation_intent"]
    intent = values["activation_intent"]
    require(isinstance(intent, dict) and set(intent) == guest.COMMON_FIELDS | {"status", "origin"}
            and intent["schema"] == guest.SCHEMA and intent["action"] == "activate" and intent["status"] == "intended_once"
            and all(intent[k] == scope[k] for k in {*guest.TARGET, "boot_id", "state_generation", "public_ca_sha256"})
            and intent["prior_evidence_sha256"] == digest(guest.canonical({key: pinned[key] for key in INPUTS}))
            and re.fullmatch(r"[a-f0-9]{40}", intent["controls_commit"])
            and re.fullmatch(r"[a-f0-9]{32}", intent["operation_id"]) and intent["operation_id"] != operation_id
            and all(guest.HASH.fullmatch(intent[field]) for field in ("authority_sha256", "payload_sha256"))
            and reference["name"] == (f"{PRIVATE_ROOT}{intent['controls_commit']}/decisions/{intent['operation_id']}"
                                      "/personal-sql-intent.json"), "personal_original_activation_intent")
    origin = activation_origin(intent["origin"])
    marker = guest.activation_marker(intent)
    original_result = receipt_name(intent["controls_commit"], origin["run"])
    request_sha = digest(guest.canonical({key: intent[key] for key in guest.COMMON_FIELDS}))
    partial_ref = references.get("activation_partial")
    if partial_ref is not None:
        partial = values["activation_partial"]
        expected = {"schema": RESULT, "action": "activate", "operation_id": intent["operation_id"],
                    "run": origin["run"], "control_commit": intent["controls_commit"],
                    "decision_sha256": origin["decision_sha256"], "request_sha256": request_sha,
                    "intent": reference, "sql_started": True, "retry_authorized": False}
        require(partial_ref["name"] == original_result and isinstance(partial, dict) and partial.get("status") in PARTIAL
                and all(partial.get(key) == value for key, value in expected.items()), "personal_partial_activation_result")
        if "outcome" in partial:
            require(partial["outcome"]["intent"] == reference and verified_mutation_receipt(
                partial["outcome"]["guest"], "activate", scope, intent["prior_evidence_sha256"]) == marker,
                "personal_partial_activation_marker")
    recovery = {"intent": reference, "partial": partial_ref, "origin": origin, "original_result_name": original_result,
                "operation_id": intent["operation_id"], "marker": marker}
    if "activation_observation" in values:
        terminal = values["activation_observation"]
        # Reconcile attributes without recasting the observation as the successful result of activation.
        expected = {"schema": RESULT, "status": RECOVERED, "action": "observe", "retry_authorized": False}
        require(isinstance(terminal, dict) and all(terminal.get(key) == value for key, value in expected.items())
                and terminal.get("cleanup") in REMOVED and terminal.get("recovery") == recovery
                and terminal.get("original_key_withdrawal") == {**origin["key"], "status": ABSENT}
                and terminal.get("intent") is None and terminal.get("operation_id") not in {intent["operation_id"], operation_id}
                and guest.HASH.fullmatch(terminal.get("decision_sha256", ""))
                and terminal.get("run") != origin["run"] and guest.HASH.fullmatch(terminal.get("post_backend_sha256", ""))
                and references["activation_observation"]["name"] == receipt_name(terminal["control_commit"], terminal["run"]),
                "personal_reconciled_activation_receipt")
        observed_at = datetime.fromisoformat(terminal["observed_utc"])
        require(observed_at.utcoffset() == timedelta(0) and observed_at <= now
                and origin["key"]["created_us"] <= int(observed_at.timestamp() * 1_000_000),
                "personal_current_reconciliation_observation")
        observation_hash = digest(guest.canonical({key: value for key, value in pinned.items() if key != "activation_observation"}))
        observed = terminal["guest"]
        require(verified_mutation_receipt(observed, "observe", scope, observation_hash) == marker
                and observed["controls_commit"] == terminal["control_commit"]
                and observed["operation_id"] == terminal["operation_id"]
                and terminal["request_sha256"] == digest(guest.canonical({**{key: observed[key]
                    for key in guest.COMMON_FIELDS - {"schema"}}, "schema": guest.SCHEMA})),
                "personal_reconciled_activation_marker")
    return recovery


def verified_inputs(artifacts, pinned, action, references, now, operation_id):
    names = predecessor_names(action, set(pinned))
    require(set(artifacts) == names, "personal_predecessor_set")
    for name, raw in artifacts.items():
        require(0 < len(raw) <= MAX_RECEIPT and digest(raw) == pinned[name], "personal_predecessor_digest")
    values = {key: guest.decode(raw) for key, raw in artifacts.items()}
    bootstrap, tls, applied = (values[name] for name in ("bootstrap", "tls", "apply"))
    ca = bootstrap.get("ca_certificate_sha256", "")
    boot_id = bootstrap["guest_receipt"]["guest_boot_id"]
    require(bootstrap["status"] == "configured_guest_verified_external_acceptance_pending"
            and bootstrap["guest_receipt"]["disk_id"] == guest.TARGET["data_disk_id"]
            and bootstrap["guest_receipt"]["checks"]["roles_verified"] is True
            and bootstrap["cleanup"]["status"] in {"own_key_removed", "key_already_absent"}
            and guest.UUID.fullmatch(boot_id) and guest.HASH.fullmatch(ca), "personal_verified_bootstrap")
    require(tls.get("status") == "verified" and tls.get("mode") == "verify-full" and tls.get("host") == "10.80.1.3"
            and tls.get("public_ca_sha256") == ca and tls.get("bootstrap_receipt_sha256") == pinned["bootstrap"],
            "personal_tls_provenance")
    state = applied["state_after"]
    require(applied["status"] == "applied_verified" and applied["deployment_phase"] == "human_access"
            and applied["managed_count"] == 59 and applied["iap_verified"] is True and applied["firewall_verified"] is True
            and applied["bootstrap_receipt_sha256"] == pinned["bootstrap"] and state["name"] == STATE
            and state["current_lock_absent"] is True and re.fullmatch(r"[1-9][0-9]{0,30}", state["generation"])
            and type(state["size"]) is int and state["size"] > 0, "personal_phase_two_reconciliation")
    for phase, job in JOBS.items():
        row = values[phase]
        require(row["schema"] == "clipforge-int-noble-job-result-1" and row["action"] == "run"
                and row["phase"] == phase and row["status"] == "execution_verified" and row["job"] == PREFIX + job
                and row["effect"] == JOB_EFFECTS[phase] and row["execution"].startswith(PREFIX + job + "/executions/")
                and all(row["receipts"][key] == pinned[key] for key in ("bootstrap", "tls", "apply"))
                and row["backend_observation"]["state"] == {key: state[key] for key in ("name", "generation", "size")}
                and row["backend_observation_sha256"] == digest(guest.canonical(row["backend_observation"]).rstrip(b"\n")),
                "personal_noble_job_predecessor")
    require(values["migrate"]["database_revisions"] == REVISIONS
            and values["app"]["receipts"]["migration"] == values["admin"]["receipts"]["migration"] == pinned["migrate"]
            and values["admin"]["receipts"]["acceptance"] == pinned["app"], "personal_job_sequence")
    scope = {**guest.TARGET, "boot_id": boot_id, "state_generation": state["generation"],
             "public_ca_sha256": ca, "prior_evidence_sha256": digest(guest.canonical(pinned))}
    if "activation_intent" in values:
        scope["recovery"] = verified_recovery(values, pinned, references, scope, now, operation_id)
        if action == "revoke":
            scope["activation_marker"] = scope["recovery"]["marker"]
    elif action == "revoke":
        terminal = values["activation"]
        require(terminal.get("status") == "completed_verified"
                and terminal.get("cleanup") in REMOVED, "personal_confirmed_activation_cleanup")
        old = terminal["guest"]
        marker = verified_mutation_receipt(old, "activate", scope, digest(guest.canonical({key: pinned[key] for key in INPUTS})))
        require(marker == guest.activation_marker(old), "personal_confirmed_activation_marker")
        scope["activation_marker"] = marker
    return scope


def check_authority(raw, expected_sha, executable, controls_commit, clock):
    require(0 < len(raw) <= 65536 and digest(raw) == expected_sha, "personal_independently_pinned_authority")
    value = guest.decode(raw)
    fields = {"schema", "operation_id", "action", "approved_commit", "valid_from", "expires",
              "evidence", "snapshot_sha256", "payload_sha256", "owner", "owner_approval_ref", *guest.TARGET}
    require(raw == guest.canonical(value) and set(value) == fields and value["schema"] == AUTHORITY
            and value["action"] in guest.MODES and re.fullmatch(r"[a-f0-9]{32}", value["operation_id"])
            and re.fullmatch(r"[a-f0-9]{40}", value["approved_commit"]) and value["approved_commit"] == controls_commit
            and value["owner"] == "admin@ixbalam.studio"
            and re.fullmatch(r"[A-Za-z0-9_.:/-]{8,160}", value["owner_approval_ref"])
            and value["payload_sha256"] == digest(executable)
            and all(value[key] == want for key, want in guest.TARGET.items()), "personal_closed_authority")
    start, expiry = (datetime.fromisoformat(value[key]) for key in ("valid_from", "expires"))
    require(start.utcoffset() == expiry.utcoffset() == timedelta(0)
            and clock.tzinfo is not None and start <= clock.astimezone(timezone.utc) < expiry - timedelta(seconds=150)
            and expiry - start <= timedelta(hours=24), "personal_technical_authority_validity")
    return value


def request_bytes(value, expected_sha, scope):
    selected = ("boot_id", "prior_evidence_sha256", "state_generation", "public_ca_sha256")
    if value["action"] == "revoke":
        require(guest.MARKER.fullmatch(scope["activation_marker"]), "personal_requested_activation_marker")
        selected += ("activation_marker",)
    return guest.canonical({"schema": guest.SCHEMA, **{key: value[key] for key in ("action", "operation_id", "payload_sha256", *guest.TARGET)},
                            "authority_sha256": expected_sha, "controls_commit": value["approved_commit"],
                            **{key: scope[key] for key in selected}})


def admission(raw, expected_sha, executable, artifacts, snapshot, live_backend, controls_commit, clock, *, references=None):
    return admission_details(raw, expected_sha, executable, artifacts, snapshot, live_backend, controls_commit,
                             clock, references=references)[0]


def admission_details(raw, expected_sha, executable, artifacts, snapshot, live_backend, controls_commit, clock, *, references=None):
    value = check_authority(raw, expected_sha, executable, controls_commit, clock)
    scope = verified_inputs(artifacts, value["evidence"], value["action"], references or {}, clock, value["operation_id"])
    require(digest(guest.canonical(snapshot)) == value["snapshot_sha256"]
            and snapshot["instance_id"] == scope["instance_id"] and snapshot["boot_disk_id"] == scope["boot_disk_id"]
            and snapshot["data_disk_id"] == scope["data_disk_id"] and snapshot["guest_boot_id"] == scope["boot_id"]
            and live_backend == {"name": STATE, "generation": scope["state_generation"], "current_lock_absent": True},
            "personal_fresh_target_and_lock")
    return request_bytes(value, expected_sha, scope), scope.get("recovery")


def protected_invocation(processes, port, executable, public_request, record_intent, password=None, *,
                         render_verifier=None, origin=None):
    """Call only from the admitted continuation. Keep SCRAM inside memory and stdin."""
    value = guest.decode(public_request)
    if value["action"] == "activate":
        require(isinstance(password, str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", password), "personal_password_format")
        if render_verifier is None:
            from scripts.int_bootstrap_vm import scram as render_verifier
        packet = guest.canonical({**value, "verifier": render_verifier(password)})
    else:
        require(password is None, "unexpected_personal_password")
        packet = public_request
    payload_sha = digest(executable)
    guest.request(packet, payload_sha)
    intent = None
    if value["action"] in MUTATIONS:
        # The caller binds this callback to one exact create-only bucket object, reconciled before another effect.
        intent_name = f"{PRIVATE_ROOT}{value['controls_commit']}/decisions/{value['operation_id']}/personal-sql-intent.json"
        provenance = {"origin": activation_origin(origin)} if value["action"] == "activate" else {}
        intent_bytes = guest.canonical({**value, **provenance, "status": "intended_once"})
        intent = record_intent(intent_name, intent_bytes)
        require(isinstance(intent, dict) and set(intent) == {"name", "generation", "size", "sha256"}
                and intent["name"] == intent_name and intent["sha256"] == digest(intent_bytes)
                and intent["size"] == len(intent_bytes) and re.fullmatch(r"[1-9][0-9]*", intent["generation"]),
                "personal_intent_create_readback")
    code, stdout, _ = processes.invoke(port, executable, payload_sha, packet)
    require(code == 0 and 0 < len(stdout) <= guest.MAX_OUTPUT, "personal_guest_outcome_requires_reconciliation")
    receipt = guest.decode(stdout)
    require(stdout == guest.canonical(receipt) and receipt.get("schema") == guest.RESULT
            and receipt.get("status") == {"activate": "activated_verified", "revoke": "revoked_verified", "observe": "observed"}[value["action"]]
            and set(receipt) == (set(value) - {"schema"}) | {"schema", "status", "observation"}
            and all(receipt[key] == data for key, data in value.items() if key != "schema"),
            "personal_native_scope_or_status")
    guest.check_observation(value["action"], receipt["observation"])
    if value["action"] == "activate":
        require(receipt["observation"]["activation_marker"] == guest.activation_marker(value), "personal_native_activation_marker")
    return {"guest": receipt, "intent": intent}


def verified_terminal(outcome, before, after, backend, cleanup):
    """Finalize only after independent readbacks and own Deploy key withdrawal."""
    receipt = outcome["guest"]
    require(before == after and all(after[key] == receipt[key] for key in guest.TARGET)
            and after["guest_boot_id"] == receipt["boot_id"]
            and backend == {"name": STATE, "generation": receipt["state_generation"], "current_lock_absent": True},
            "personal_post_scope_requires_reconciliation")
    require(cleanup.get("status") in {"own_key_removed", "key_already_absent"}, "personal_deploy_key_cleanup_pending")
    return {**outcome, "status": "completed_verified", "cleanup": cleanup["status"]}
