"""Prepared single-stop containment, never initialization or automatic recovery.

The future protected caller supplies the original approved decision/proposal and
the exact failed operation's private journal digest. This file has no cloud API,
SQL, secret payload, configuration-write or restart implementation. The sole
additional write is a root-private, exclusive, permanent stop-intent receipt.
"""
from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import zlib

if "_clipforge_db01_guest" in sys.modules:
    guest = sys.modules["_clipforge_db01_guest"]
else:
    from scripts import int_bootstrap_vm as guest

UNIT = "postgresql@17-main.service"
STOP = ["/usr/bin/systemctl", "stop", UNIT]
JOURNAL = Path("/var/lib/clipforge-postgres/db01/operation.json")
INTENT = Path("/var/lib/clipforge-postgres/db01/containment-intent.json")
CONFIG = Path("/etc/postgresql/17/main")
PGDATA = Path("/var/lib/clipforge-postgres/data/pgdata")
UNIT_FRAGMENT = Path("/usr/lib/systemd/system/postgresql@.service")
# postgresql-common278, authenticated Debian archive package; never change unit.
UNIT_FRAGMENT_SHA256 = "4c44931bba34e0754b7c0762852a5c1b615a1e307df9c458d231232d55e4c907"
EXEC_STOP = ["/usr/bin/pg_ctlcluster", "--skip-systemctl-redirect", "-m", "fast", "17-main", "stop"]
UNIT_PROPERTIES = "ActiveState,SubState,LoadState,MainPID,FragmentPath,DropInPaths,NeedDaemonReload,ExecStop"
PUBLIC_FILES = (Path("/etc/fstab"), CONFIG / "postgresql.conf", CONFIG / "pg_hba.conf", CONFIG / "start.conf")
TOTAL_SECONDS = 90
require = guest.require


def containment_policy(own_sha, bootstrap_sha, *, authorized=False):
    require(type(authorized) is bool, "containment_policy_boolean")
    return {"schema": "clipforge-db01-containment-policy-2", "authorized": authorized,
            "action": "single_stop_created_17_main_preserve", "argv": list(STOP), "automatic_retry": False,
            "source_sha256": own_sha, "bootstrap_source_sha256": bootstrap_sha,
            "journal_path": JOURNAL.as_posix(), "intent_path": INTENT.as_posix(),
            "intent_creation_authorized": authorized, "maximum_seconds": TOTAL_SECONDS}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def instant(value):
    require(isinstance(value, str), "containment_timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.utcoffset() is not None, "containment_timestamp")
    return result


def authorize(payload, own_sha, bootstrap_sha, *, now=None):
    require(isinstance(payload, dict) and set(payload) == {"schema", "owner_decision_json", "owner_decision_sha256", "proposal_json", "journal_sha256"}
            and payload["schema"] == "clipforge-db01-containment-input-1", "closed_containment_input")
    decision_raw = payload["owner_decision_json"].encode("ascii")
    proposal_raw = payload["proposal_json"].encode("ascii")
    require(sha(decision_raw) == payload["owner_decision_sha256"], "containment_owner_decision_digest")
    decision, proposal = guest.decode(decision_raw), guest.decode(proposal_raw)
    require(set(decision) == {"schema", "status", "owner", "repository", "branch", "approved_commit", "operation_id", "proposal_sha256", "host_evidence_sha256", "baseline_evidence_sha256", "baseline_run_id", "baseline_artifact_id", "issued_utc", "expires_utc", "confirmation"}
            and decision.get("schema") == "clipforge-db01-activation-decision-1"
            and decision.get("status") == "authorized_single_guest_initialization"
            and decision.get("owner") == "admin@ixbalam.studio"
            and decision.get("repository") == "AldemaroCruz/ClipForge"
            and decision.get("branch") == "ci/bootstrap-sec03"
            and decision.get("proposal_sha256") == sha(proposal_raw), "containment_requires_original_bootstrap_authority")
    require(proposal.get("status") == "authorized_single_guest_initialization"
            and proposal.get("execution_authorized") is True and proposal.get("cloud_writes_authorized") is True
            and proposal.get("VM_operations_authorized") is True
            and proposal.get("SQL_on_INT_authorized") is True, "containment_preparation_is_not_authority")
    require(proposal.get("target", {}).get("instance_id") == "1670495097211408131"
            and proposal.get("target", {}).get("disk_id") == "6427691858848206684"
            and proposal.get("target", {}).get("project_id") == "clipforgebeta2"
            and proposal.get("target", {}).get("project_number") == "816643438938"
            and proposal.get("target", {}).get("zone") == "us-central1-a"
            and decision.get("confirmation") == "INITIALIZE_NEW_DISK_6427691858848206684", "containment_target")
    policy = proposal.get("containment")
    require(isinstance(policy, dict) and policy.get("authorized") is True and policy.get("automatic_retry") is False
            and policy.get("intent_creation_authorized") is True
            and policy == containment_policy(own_sha, bootstrap_sha, authorized=True), "exact_containment_policy_required")
    require(re.fullmatch(r"[a-f0-9]{32}", decision.get("operation_id", ""))
            and re.fullmatch(r"[a-f0-9]{40}", decision.get("approved_commit", ""))
            and re.fullmatch(r"[a-f0-9]{64}", payload["journal_sha256"]), "containment_identity")
    at = datetime.now(timezone.utc) if now is None else now
    issued, expires = instant(decision["issued_utc"]), instant(decision["expires_utc"])
    require(0 < (expires - issued).total_seconds() <= 3600 and issued <= at
            and (expires - at).total_seconds() >= 120, "containment_authority_expired_or_insufficient_time")
    return decision, proposal


def public_payload(bootstrap_source, containment_source, bootstrap_sha, containment_sha):
    """Public bytes only, for the existing pinned GUEST SSH loader; no transport."""
    require(sha(bootstrap_source) == bootstrap_sha and sha(containment_source) == containment_sha
            and all(re.fullmatch(r"[a-f0-9]{64}", x) for x in (bootstrap_sha, containment_sha)), "containment_source_binding")
    first = base64.b64encode(zlib.compress(bootstrap_source, 9)).decode('ascii')
    second = base64.b64encode(zlib.compress(containment_source, 9)).decode('ascii')
    raw = ("import base64,hashlib,sys,types,zlib\n"
        "m=types.ModuleType('_clipforge_db01_guest');sys.modules[m.__name__]=m\n"
        "s=zlib.decompress(base64.b64decode('" + first + "'))\nif hashlib.sha256(s).hexdigest()!='" + bootstrap_sha + "':raise ValueError('bootstrap_source_digest')\n"
        "exec(compile(s,'<reviewed-bootstrap>','exec'),m.__dict__)\n"
        "CONTAINMENT_BOOTSTRAP_SOURCE_SHA256='" + bootstrap_sha + "'\n"
        "CONTAINMENT_SOURCE_SHA256='" + containment_sha + "'\n"
        "s=zlib.decompress(base64.b64decode('" + second + "'))\nif hashlib.sha256(s).hexdigest()!='" + containment_sha + "':raise ValueError('containment_source_digest')\n"
        "exec(compile(s,'<reviewed-containment>','exec'),globals())\n").encode('ascii')
    # The existing SSH loader base64-encodes this public bundle once more.
    require(len(raw) <= 65536, "containment_public_payload_limit")
    return raw


def owned_journal(raw, decision, expected, bootstrap_sha, *, guest_boot_id, now=None):
    require(sha(raw) == expected, "containment_journal_changed")
    journal = guest.decode(raw)
    require(journal.get("status") == "partial_preserved" and type(journal.get("exit_code")) is int
            and journal["exit_code"] == 3 and journal.get("error_code") is not None
            and isinstance(journal.get("started_utc"), str) and isinstance(journal.get("finished_utc"), str)
            and isinstance(guest_boot_id, str) and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", guest_boot_id)
            and journal.get("guest_boot_id") == guest_boot_id, "containment_requires_finished_failed_same_boot")
    # The persisted journal omits its own hash. Validate the original receipt
    # shape without changing any of its bytes or accepting an unfinished run.
    require(journal.get("journal_path") == JOURNAL.as_posix(), "containment_journal_path")
    # The bootstrap validator compares its local Path spelling; the wire value
    # above is always the fixed Linux path, including Windows authored tests.
    guest.validate_receipt({**journal, "journal_sha256": expected,
                            "journal_path": str(guest.JOURNAL_DIR / "operation.json")})
    at = datetime.now(timezone.utc) if now is None else now
    require(instant(decision["issued_utc"]) <= instant(journal["started_utc"])
            <= instant(journal["finished_utc"]) <= at < instant(decision["expires_utc"]), "containment_requires_finished_failed_same_boot")
    require(journal.get("journal_path") == JOURNAL.as_posix()
            and journal.get("operation_id") == decision["operation_id"]
            and journal.get("approved_commit") == decision["approved_commit"]
            and journal.get("proposal_sha256") == decision["proposal_sha256"]
            and journal.get("operator_sha256") == bootstrap_sha
            and journal.get("disk_id") == "6427691858848206684", "containment_foreign_operation")
    require(isinstance(journal.get("filesystem_uuid"), str)
            and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", journal["filesystem_uuid"])
            and journal.get("checks", {}).get("mount_verified") is True
            and re.fullmatch(r"[a-f0-9]{64}", journal.get("effective_config_sha256", "")), "containment_created_cluster_proof")
    starts = [row for row in journal.get("native_operations", []) if row.get("operation") == "start"]
    require(len(starts) == 1, "containment_single_start_intent_required")
    return journal


def unit_state(raw):
    pairs = [row.split("=", 1) for row in raw.decode("ascii").splitlines() if row]
    require(len(pairs) == 8 and len({k for k, _ in pairs}) == 8, "containment_unit_metadata")
    value = dict(pairs)
    require(set(value) == set(UNIT_PROPERTIES.split(","))
            and value["LoadState"] == "loaded"
            and value["FragmentPath"] in {"/usr/lib/systemd/system/postgresql@.service", "/lib/systemd/system/postgresql@.service"}
            and value["MainPID"].isdigit() and value["DropInPaths"] == ""
            and value["NeedDaemonReload"] == "no", "containment_unit_identity")
    serialized = value["ExecStop"]
    require(serialized.startswith("{ ") and serialized.endswith(" }"), "containment_effective_ExecStop")
    pairs = [item.split("=", 1) for item in serialized[2:-2].split(" ; ")]
    require(all(len(pair) == 2 for pair in pairs) and len({p[0] for p in pairs}) == len(pairs), "containment_effective_ExecStop")
    stop = dict(pairs)
    require(set(stop) == {"path", "argv[]", "ignore_errors", "start_time", "stop_time", "pid", "code", "status"}
            and stop["path"] == EXEC_STOP[0] and stop["argv[]"] == " ".join(EXEC_STOP)
            and stop["ignore_errors"] == "no", "containment_effective_ExecStop")
    value["ExecStop"] = list(EXEC_STOP)  # Exclude volatile execution timestamps.
    return value


def postmaster_metadata(pid, postgres_uid):
    path = PGDATA / "postmaster.pid"
    guest._parents(path, owners=(0, postgres_uid))
    before = guest._regular(path, owners=(postgres_uid,), maximum=4096)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "containment_pidfile_changed")
        first, second = stream.readline(64), stream.readline(512)
    require(first == str(pid).encode("ascii") + b"\n" and second == PGDATA.as_posix().encode("ascii") + b"\n",
            "containment_foreign_PGDATA")


def created_postmaster(pid, *, reader=guest.read_bytes):
    require(type(pid) is int and 1 < pid < 2147483648, "containment_postmaster_pid")
    path = Path("/proc") / str(pid)
    uid = guest.postgres_account().pw_uid
    require(path.stat().st_uid == uid and os.readlink(path / "exe") == "/usr/lib/postgresql/17/bin/postgres"
            and os.readlink(path / "cwd") == PGDATA.as_posix(), "containment_postmaster_identity")
    postmaster_metadata(pid, uid)
    raw = reader(path / "stat", limit=4096, owners=(0, uid)).decode("ascii")
    prefix, separator, rest = raw.rpartition(") ")
    fields = rest.split()
    require(separator and prefix.startswith(str(pid) + " (") and len(fields) >= 20
            and re.fullmatch(r"[1-9][0-9]*", fields[19]), "containment_process_start_ticks")
    return {"pid": pid, "start_ticks": fields[19], "uid": uid, "PGDATA": PGDATA.as_posix()}


def claim_stop_intent(value):
    """No replacement, deletion or replay, including after a partial write."""
    guest._parents(INTENT)
    raw = guest.canonical(value) + b"\n"
    require(len(raw) <= 4096, "containment_intent_limit")
    descriptor = os.open(INTENT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        info = os.fstat(stream.fileno())
        require(info.st_uid == 0 and stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "containment_intent_owner")
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    guest._fsync_dir(INTENT.parent)
    require(guest.read_bytes(INTENT, limit=4096) == raw, "containment_intent_readback")
    return sha(raw)


class Containment:
    def __init__(self, payload, *, own_sha, bootstrap_sha, runner=guest.native, read=guest.read_bytes,
                 identity=guest.metadata_identity, clock=time.monotonic, intent_writer=claim_stop_intent):
        self.payload, self.own_sha, self.bootstrap_sha = payload, own_sha, bootstrap_sha
        self.runner, self.read, self.identity, self.clock = runner, read, identity, clock
        self.intent_writer = intent_writer
        self.deadline = clock() + TOTAL_SECONDS
        self.result = {"schema": "clipforge-db01-containment-receipt-1", "status": "blocked_before_stop",
            "stop_attempted": False, "native_operations": [], "data_reinitialized": False,
            "configuration_restored": False, "restart_attempted": False, "IAM_or_state_written": False,
            "configuration_and_journal_preserved": False, "intent_creation_attempted": False,
            "intent_created": False, "intent_path": INTENT.as_posix(), "intent_sha256": None}

    def call(self, operation, argv):
        remaining = self.deadline - self.clock()
        require(remaining > 0, "containment_total_timeout")
        try:
            raw, row = self.runner(operation, argv, None, min(20, remaining))
        except guest.NativeInterruption as error:
            self.result["native_operations"].append(error.native_receipt)
            raise
        self.result["native_operations"].append(row)
        require(row["status"] == "ok" and row["exit_code"] == 0, "containment_native_operation_failed")
        return raw

    def snapshot(self, journal):
        postgres = guest.postgres_account()
        public = {str(path): self.read(path, owners=(0, postgres.pw_uid)) for path in PUBLIC_FILES}
        effective = sha(guest.canonical({"postgresql_conf": sha(public[str(CONFIG / "postgresql.conf")]),
                                        "pg_hba_conf": sha(public[str(CONFIG / "pg_hba.conf")])}))
        require(effective == journal["effective_config_sha256"]
                and sha(public[str(PUBLIC_FILES[0])]) == journal.get("fstab_after_sha256"), "containment_foreign_configuration")
        mounted = json.loads(self.call("mounted", ["/usr/bin/findmnt", "--json", "--target", str(guest.MOUNT),
                    "--output", "UUID,SOURCE,TARGET,FSTYPE,OPTIONS,MAJ:MIN"]))
        rows = mounted.get("filesystems", [])
        require(len(rows) == 1, "containment_mount_identity")
        row = rows[0];device = Path(guest.DEVICE).stat()
        require(stat.S_ISBLK(device.st_mode) and device.st_rdev != Path("/").stat().st_dev
                and row.get("uuid") == journal["filesystem_uuid"] and row.get("target") == str(guest.MOUNT)
                and row.get("fstype") == "ext4" and row.get("maj:min") == f"{os.major(device.st_rdev)}:{os.minor(device.st_rdev)}"
                and Path(row.get("source", "")).stat().st_rdev == device.st_rdev
                and {"rw", "nodev", "nosuid", "noexec"} <= set(row.get("options", "").split(",")), "containment_mount_identity")
        clusters = self.call("clusters", ["/usr/bin/pg_lsclusters", "--no-header"]).decode("ascii").splitlines()
        require(len(clusters) == 1 and clusters[0].split()[:3] == ["17", "main", "5432"]
                and clusters[0].split()[4:6] == ["postgres", str(guest.MOUNT / "pgdata")], "containment_cluster_identity")
        return {"public_file_sha256": {path: sha(raw) for path, raw in public.items()},
                "uuid": row["uuid"], "major_minor": row["maj:min"], "cluster": clusters[0].split()[:6]}

    def run(self):
        try:
            decision, proposal = authorize(self.payload, self.own_sha, self.bootstrap_sha)
            require(sys.platform == "linux" and os.geteuid() == 0, "containment_linux_root_required")
            require(self.identity() == {"instance_id": "1670495097211408131", "project_id": "clipforgebeta2",
                    "project_number": "816643438938", "zone": "us-central1-a"}, "containment_VM_identity")
            raw = self.read(JOURNAL)
            boot_id = self.read(Path("/proc/sys/kernel/random/boot_id"), limit=64).decode("ascii").strip()
            journal = owned_journal(raw, decision, self.payload["journal_sha256"], self.bootstrap_sha, guest_boot_id=boot_id)
            before = self.snapshot(journal)
            require(sha(self.read(UNIT_FRAGMENT, limit=16384)) == UNIT_FRAGMENT_SHA256, "containment_unit_fragment_changed")
            state = unit_state(self.call("unit_state", ["/usr/bin/systemctl", "show", UNIT, "--no-pager",
                "--property=" + UNIT_PROPERTIES]))
            require(state["ActiveState"] in {"active", "activating"} and int(state["MainPID"]) > 1
                    and before["cluster"][3] == "online", "containment_not_running_created_cluster")
            process = created_postmaster(int(state["MainPID"]), reader=self.read)
            require(self.snapshot(journal) == before, "containment_configuration_changed_before_stop")
            current = unit_state(self.call("unit_state", ["/usr/bin/systemctl", "show", UNIT, "--no-pager", "--property=" + UNIT_PROPERTIES]))
            require(current == state and created_postmaster(int(current["MainPID"]), reader=self.read) == process,
                    "containment_process_changed_before_stop")
            require(self.read(JOURNAL) == raw, "containment_journal_changed_before_stop")
            require(self.read(Path("/proc/sys/kernel/random/boot_id"), limit=64).decode("ascii").strip() == boot_id,
                    "containment_boot_changed_before_stop")
            authorize(self.payload, self.own_sha, self.bootstrap_sha)
            # Bind partial receipts before the first durable side effect, even
            # when intent fsync or the subsequent PID comparison fails.
            self.result.update(operation_id=decision["operation_id"], approved_commit=decision["approved_commit"],
                owner_decision_sha256=self.payload["owner_decision_sha256"], journal_sha256=sha(raw))
            self.result["intent_creation_attempted"] = True
            self.result["intent_sha256"] = self.intent_writer({"schema": "clipforge-db01-single-stop-intent-1",
                "operation_id": decision["operation_id"], "approved_commit": decision["approved_commit"],
                "proposal_sha256": decision["proposal_sha256"], "owner_decision_sha256": self.payload["owner_decision_sha256"],
                "bootstrap_source_sha256": self.bootstrap_sha, "containment_source_sha256": self.own_sha,
                "original_journal_sha256": sha(raw), "guest_boot_id": boot_id, "process": process,
                "filesystem_uuid": journal["filesystem_uuid"], "argv": STOP, "created_utc": datetime.now(timezone.utc).isoformat()})
            self.result["intent_created"] = True
            require(created_postmaster(int(state["MainPID"]), reader=self.read) == process, "containment_process_changed_after_intent")
            self.result.update(operation_id=decision["operation_id"], approved_commit=decision["approved_commit"],
                owner_decision_sha256=self.payload["owner_decision_sha256"], journal_sha256=sha(raw),
                status="stop_sent_outcome_unknown", stop_attempted=True)
            self.call("containment_stop", STOP)
            state = unit_state(self.call("unit_state", ["/usr/bin/systemctl", "show", UNIT, "--no-pager",
                "--property=" + UNIT_PROPERTIES]))
            require(state["ActiveState"] in {"inactive", "failed"} and state["MainPID"] == "0", "containment_stop_not_verified")
            require(not self.call("tcp", ["/usr/bin/ss", "-H", "-ltn", "sport = :5432"]).strip(), "containment_listener_remains")
            require(not self.call("unix", ["/usr/bin/ss", "-H", "-lx", "src = /var/run/postgresql/.s.PGSQL.5432"]).strip(), "containment_unix_listener_remains")
            after = self.snapshot(journal)
            require(after["public_file_sha256"] == before["public_file_sha256"]
                    and after["uuid"] == before["uuid"] and after["major_minor"] == before["major_minor"]
                    and after["cluster"][3] == "down" and self.read(JOURNAL) == raw, "containment_preservation_unconfirmed")
            self.result.update(status="created_cluster_stopped_preserved", configuration_and_journal_preserved=True,
                               filesystem_uuid=after["uuid"], mount_preserved=True)
        except Exception as error:
            self.result["error_code"] = str(error) if isinstance(error, guest.Blocked) else "containment_details_withheld"
            if self.result["stop_attempted"]: self.result["status"] = "stop_outcome_unknown_preserve_and_review"
        return self.result


def main():
    require(len(sys.argv) == 1, "containment_no_command_line_inputs")
    def interrupted(_signum, _frame):
        raise guest.Blocked("containment_interrupted")
    for number in (signal.SIGTERM, signal.SIGINT):signal.signal(number, interrupted)
    signal.signal(signal.SIGALRM, interrupted);signal.alarm(TOTAL_SECONDS)
    raw = sys.stdin.buffer.read(65537)
    require(len(raw) <= 65536, "containment_input_limit")
    source = globals().get("CONTAINMENT_SOURCE_SHA256", "")
    bootstrap = globals().get("CONTAINMENT_BOOTSTRAP_SOURCE_SHA256", "")
    require(re.fullmatch(r"[a-f0-9]{64}", source) and re.fullmatch(r"[a-f0-9]{64}", bootstrap), "reviewed_containment_loader_required")
    result = Containment(guest.decode(raw), own_sha=source, bootstrap_sha=bootstrap).run()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "created_cluster_stopped_preserved" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"schema": "clipforge-db01-containment-receipt-1", "status": "blocked_before_stop",
            "error_code": str(error) if isinstance(error, guest.Blocked) else "containment_details_withheld",
            "stop_attempted": False}))
        raise SystemExit(1)
