"""DB-01 disposable PostgreSQL 17.12 compatibility, never the INT database.

Host lifecycle reuses CI ownership/cleanup. Its TLS keys and passwords are newly
generated synthetic material. The existing suite uses the migrator for its own
schema fixtures; a separate public-schema contract checks the restricted app.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import ci_postgres as ci

PG_IMAGE = "docker.io/library/postgres:17.12-trixie@sha256:9d4105e2fcb1308961d4ee01f0ebc14fdd0497b11243982a4a0935fdb1a8f8dc"
SERVER_VERSION_NUM = 170012
CERT_SCRIPT = """set -eu
umask 077
cd /qa
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=DB01-Own-Test-CA -keyout ca.key -out ca.crt
openssl req -newkey rsa:2048 -nodes -subj /CN=postgres -keyout server.key -out server.csr
printf 'subjectAltName=DNS:postgres\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile server.ext -out server.crt
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=DB01-Other-Test-CA -keyout other-ca.key -out other-ca.crt
chmod 0644 ca.crt server.crt other-ca.crt
"""
BOOTSTRAP = """set -eu
umask 077
mkdir -p /var/lib/postgresql/certs
cp /run/db01/server.crt /var/lib/postgresql/certs/server.crt
cp /run/db01/server.key /var/lib/postgresql/certs/server.key
chmod 0600 /var/lib/postgresql/certs/server.key
exec /usr/local/bin/docker-entrypoint.sh postgres -c ssl=on -c ssl_min_protocol_version=TLSv1.2 -c ssl_cert_file=/var/lib/postgresql/certs/server.crt -c ssl_key_file=/var/lib/postgresql/certs/server.key -c hba_file=/run/db01/pg_hba.conf -c password_encryption=scram-sha-256
"""
HBA = """local all postgres peer
hostnossl all all 0.0.0.0/0 reject
hostssl clipforge clipforge_migrator 0.0.0.0/0 scram-sha-256
hostssl clipforge clipforge_app 0.0.0.0/0 scram-sha-256
"""


def require(value, message):
    if not value:
        raise ValueError(message)


def initial_sql(migrator, app):
    require(all(re.fullmatch(r"[A-Za-z0-9_-]{32,128}", item) for item in (migrator, app)) and migrator != app,
            "Separate generated passwords required")
    return ("SET log_statement='none';\nSET log_min_error_statement='panic';\n"
            "CREATE ROLE clipforge_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '" + migrator + "';\n"
            "CREATE ROLE clipforge_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '" + app + "';\n"
            "CREATE DATABASE clipforge OWNER clipforge_migrator;\n"
            "REVOKE ALL ON DATABASE clipforge FROM PUBLIC;\n"
            "GRANT CONNECT ON DATABASE clipforge TO clipforge_migrator,clipforge_app;\n"
            "\\connect clipforge\nREVOKE ALL ON SCHEMA public FROM PUBLIC;\n"
            "ALTER SCHEMA public OWNER TO clipforge_migrator;\nGRANT USAGE ON SCHEMA public TO clipforge_app;\n"
            "ALTER DEFAULT PRIVILEGES FOR ROLE clipforge_migrator IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO clipforge_app;\n"
            "ALTER DEFAULT PRIVILEGES FOR ROLE clipforge_migrator IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO clipforge_app;\n")


def require_all_app_dml(connection):
    for table in ("auth_users", "cloud_documents", "cloud_tasks", "cloud_outbox", "cloud_requests"):
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            require(connection.execute("SELECT has_table_privilege(current_user,%s,%s)", (table, privilege)).fetchone()[0], "Missing app DML grant")


def contract(report_path):
    """Actual TLS, migrations and SQL privilege checks inside the isolated client."""
    import psycopg
    from sqlalchemy import text
    from app import auth_db
    from app.cloud.migrate import upgrade
    report = {"schema": "clipforge-db01-contract-1", "status": "failed", "checks": [],
              "fixtures": "new disposable Docker database; synthetic data only",
              "vm_package_or_sca_equivalence_claimed": False,
              "differences_from_INT": ["Docker official PGDG package 17.12-1.pgdg13+1 versus VM Debian 17.12-0+deb13u1",
                                       "Docker DNS postgres/SAN postgres and exclusive internal subnet versus INT private IP/SAN and /26 HBA",
                                       "Synthetic CA and separate generated passwords; no owner data or cloud access"]}
    def record(name, **details):
        report["checks"].append({"name": name, "status": "passed", **details})
    password = Path("/run/secrets/app-password").read_text().strip()
    options = dict(host="postgres", port=5432, dbname="clipforge", user="clipforge_app", password=password,
                   sslmode="verify-full", sslrootcert="/run/db01/ca.crt", connect_timeout=3)
    try:
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
        require(not any(row.split()[1] == "00000000" for row in routes if row.split()), "Unexpected default network route")
        for endpoint in (("1.1.1.1", 443), ("8.8.8.8", 53)):
            try:
                with socket.create_connection(endpoint, timeout=1):
                    pass
            except OSError:
                continue
            raise ValueError("Unexpected external connectivity")
        record("internal_network_no_egress", default_ipv4_route=False, external_tcp="blocked")
        os.environ.update(CLIPFORGE_STORAGE_BACKEND="gcs", CLIPFORGE_ENVIRONMENT="INT",
                          CLIPFORGE_DATABASE_SCHEMA="public", CLIPFORGE_DATABASE_POOL_SIZE="2", CLIPFORGE_DATABASE_POOL_OVERFLOW="1")
        auth_db.reset_engine()
        first, second = upgrade(), upgrade()
        require(first["status"] == "applied" and second["status"] == "current", "Migration or idempotence failed")
        with auth_db.get_engine().connect() as connection:
            auth = connection.execute(text("SELECT revision FROM auth_schema_migrations ORDER BY revision")).scalars().all()
            cloud = connection.execute(text("SELECT revision FROM cloud_schema_migrations ORDER BY revision")).scalars().all()
            require(auth == ["auth01_0001", "auth02_0002"] and cloud == ["cloud01_0001"], "Unexpected revisions")
        record("migrator_public_schema_migrations", auth=auth, cloud=cloud, repeated="current")
        with psycopg.connect(**options) as connection:
            version = int(connection.execute("SHOW server_version_num").fetchone()[0])
            require(version == SERVER_VERSION_NUM, "Wrong server version")
            tls = connection.execute("SELECT ssl,version FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()
            require(tls[0] is True and tls[1] in {"TLSv1.2", "TLSv1.3"}, "Verified TLS required")
            encryption = connection.execute("SHOW password_encryption").fetchone()[0]
            require(encryption == "scram-sha-256", "SCRAM required")
            roles = connection.execute("SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolreplication FROM pg_roles WHERE rolname IN ('clipforge_app','clipforge_migrator') ORDER BY rolname").fetchall()
            require(roles == [("clipforge_app", False, False, False, False), ("clipforge_migrator", False, False, False, False)], "Unexpected role privilege")
            require(connection.execute("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()").fetchone()[0] == "clipforge_migrator", "Unexpected database owner")
        record("server_and_roles", server_version_num=version, sslmode="verify-full", protocol=tls[1], password_encryption=encryption, database_owner="clipforge_migrator")
        with auth_db.get_engine().begin() as connection:
            connection.execute(text("CREATE TABLE db01_compatibility_probe(id BIGSERIAL PRIMARY KEY, value TEXT NOT NULL)"))
        with psycopg.connect(**options) as connection:
            row = connection.execute("INSERT INTO db01_compatibility_probe(value) VALUES ('synthetic') RETURNING id").fetchone()[0]
            connection.execute("UPDATE db01_compatibility_probe SET value='updated' WHERE id=%s", (row,))
            require(connection.execute("SELECT value FROM db01_compatibility_probe WHERE id=%s", (row,)).fetchone() == ("updated",), "App DML failed")
            connection.execute("DELETE FROM db01_compatibility_probe WHERE id=%s", (row,))
            require_all_app_dml(connection)
        record("app_table_sequence_dml", operations=["INSERT", "SELECT", "UPDATE", "DELETE", "sequence_nextval"])
        for name, sql in (("create_table", "CREATE TABLE public.db01_forbidden(id INTEGER)"),
                          ("create_schema", "CREATE SCHEMA db01_forbidden"), ("create_role", "CREATE ROLE db01_forbidden"),
                          ("create_database", "CREATE DATABASE db01_forbidden"),
                          ("alter_auth_table", "ALTER TABLE auth_users ADD COLUMN db01_forbidden INTEGER"),
                          ("drop_auth_table", "DROP TABLE auth_users")):
            try:
                with psycopg.connect(**options, autocommit=True) as connection:
                    connection.execute(sql)
            except psycopg.errors.InsufficientPrivilege:
                record("app_denied_" + name, sqlstate="42501")
            else:
                raise ValueError("Unexpected app DDL permission")
        wrong_host = {**options, "host": "unreviewed.invalid", "hostaddr": socket.gethostbyname("postgres")}
        for name, bad in (("bad_ca", {**options, "sslrootcert": "/run/db01/other-ca.crt"}),
                          ("wrong_hostname", wrong_host), ("plaintext", {**options, "sslmode": "disable"}),
                          ("wrong_password", {**options, "password": secrets.token_urlsafe(48)})):
            try:
                with psycopg.connect(**bad):
                    pass
            except psycopg.OperationalError:
                record("connection_denied_" + name)
            else:
                raise ValueError("Unexpected connection accepted")
        with auth_db.get_engine().begin() as connection:
            connection.execute(text("DROP TABLE db01_compatibility_probe"))
        report["status"] = "passed"
    except Exception as error:
        report["error_type"] = type(error).__name__
    finally:
        auth_db.reset_engine()
        with Path(report_path).open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2); output.write("\n")
    return report


def pg_suite(report_path):
    """Discover the real suite, then execute every module using AUTH SQL fixtures."""
    from scripts import run_ci_tests
    root = Path(__file__).resolve().parents[1]
    selected_modules = ["test_auth", "test_auth_recovery"]
    discovered = run_ci_tests.discover_suite(root)
    full_inventory = run_ci_tests.test_inventory(discovered)
    selected = []
    def visit(node):
        if isinstance(node, unittest.TestCase):
            if node.id().split(".", 1)[0] in selected_modules:
                selected.append(node)
        else:
            for child in node:
                visit(child)
    visit(discovered)
    suite = unittest.TestSuite(selected)
    inventory = run_ci_tests.test_inventory(suite)
    result = run_ci_tests.execute_suite(suite, sys.stderr)
    counts = run_ci_tests.test_counts(result)
    report = {"schema": "clipforge-db01-pg-suite-1", "status": "passed" if run_ci_tests.suite_passed(counts) else "failed",
        "tests": counts, "test_inventory": inventory, "full_discovery_count": full_inventory["discovered"],
        "selection": {"rule": "all actually discovered IDs in the two AUTH PostgreSQL integration modules; no skips or test substitutions", "modules": selected_modules},
        "fixture_role": "clipforge_migrator; per-test schemas only, distinct from public runtime app privilege contract",
        "failures": [{"id": case.id(), "kind": kind, "last_exception_line": trace.strip().splitlines()[-1][:300]}
                     for kind, rows in (("failure", result.failures), ("error", result.errors)) for case, trace in rows]}
    with Path(report_path).open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2); output.write("\n")
    return report


class Compatibility(ci.Lifecycle):
    def prepare(self):
        self.config.state_root.mkdir(mode=0o700)
        (self.config.state_root / "docker-config").mkdir(mode=0o700)
        nonce = __import__("uuid").uuid4().hex
        value = {"schema": ci.SCHEMA, "run_key": self.config.run_key, "nonce": nonce,
            "prefix": "clipforge-ci-auth-" + hashlib.sha256(self.config.run_key.encode()).hexdigest()[:12] + "-" + nonce[:12],
            "scratch": str(self.config.scratch), "reports": str(self.config.reports), "user": self.config.user}
        ci.save_new(self.config.state_root / "state.json", value)
        directory = self.attempt("prepare-db01")
        _, identity = self.call(directory, "postgres-identity", ["image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", PG_IMAGE])
        parts = identity.strip().split("|")
        ci.require(len(parts) == 3 and ci.IMAGE_ID.fullmatch(parts[0]) and parts[1:] == ["linux", "amd64"], "Unexpected PG image")
        ci.save_new(self.config.state_root / "prepared.json", {"image": PG_IMAGE, "image_id": parts[0]})
        self.config.private.mkdir(mode=0o700)
        for name in ("postgres-password", "database-password", "app-password"):
            ci.private_write(self.config.private / name, secrets.token_urlsafe(48))
        ci.private_write(self.config.private / "initialize.sql", initial_sql((self.config.private / "database-password").read_text(), (self.config.private / "app-password").read_text()))
        for name, content in (("bootstrap.sh", BOOTSTRAP), ("pg_hba.conf", HBA)):
            ci.private_write(self.config.private / name, content)
        self.call(directory, "synthetic-tls", ["run", "--rm", "--pull", "never", "--name", value["prefix"] + "-certgen", *self.labels(value),
            "--network", "none", "--user", "999:999", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,uid=999,gid=999,mode=0700,size=16m",
            "--mount", f"type=bind,src={self.config.private},dst=/qa", "--entrypoint", "/bin/sh", PG_IMAGE, "-c", CERT_SCRIPT])
        _, identity = self.call(directory, "postgres-os-identity", ["run", "--rm", "--pull", "never", "--name", value["prefix"] + "-pgid", *self.labels(value),
            "--network", "none", "--user", "999:999", "--tmpfs", "/var/lib/postgresql/data:uid=999,gid=999,mode=0700,size=16m",
            "--entrypoint", "/usr/bin/id", PG_IMAGE, "postgres"])
        ci.require("uid=999(postgres)" in identity and "gid=999(postgres)" in identity, "Postgres peer identity differs")
        return value

    def start_arguments(self, value):
        arguments = super().start_arguments(value)
        arguments[-1] = PG_IMAGE
        arguments[arguments.index("--user") + 1] = "999:999"
        arguments = [x.replace("uid=" + self.config.user.split(":")[0] + ",gid=" + self.config.user.split(":")[1], "uid=999,gid=999") for x in arguments]
        arguments[-1:-1] = ["--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,uid=999,gid=999,mode=0700,size=1g",
            "--mount", f"type=bind,src={self.config.private},dst=/run/db01,readonly", "--entrypoint", "/bin/sh"]
        return arguments + ["/run/db01/bootstrap.sh"]

    def start(self):
        value = self.state(); directory = self.attempt("start-db01")
        _, network = self.call(directory, "network-create", ["network", "create", "--internal", *self.labels(value), self.network_name(value)])
        ci.save_new(self.config.state_root / "network.json", {"id": network.strip(), "name": self.network_name(value)})
        _, container = self.call(directory, "postgres-start", self.start_arguments(value))
        ci.save_new(self.config.state_root / "postgres.json", {"id": container.strip(), "name": value["prefix"] + "-postgres"})
        for number in range(60):
            _, health = self.call(directory, "health-" + str(number), ["inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}", value["prefix"] + "-postgres"])
            if health.strip() == "running|healthy":
                return
            if not health.strip().startswith("running|") or "unhealthy" in health:
                self.call(directory, "postgres-early-diagnostic", ["logs", value["prefix"] + "-postgres"], allowed=(0, 1))
                raise ValueError("PG failed health; private native diagnostic retained")
            time.sleep(1)
        raise ValueError("PG health timeout")

    def runner_arguments(self, value, role, reports, *, browser=False):
        args = super().runner_arguments(value, role, reports, browser=browser)
        replacements = {"CLIPFORGE_DATABASE_NAME": "clipforge", "CLIPFORGE_DATABASE_USER": "clipforge_migrator"}
        for index, item in enumerate(args):
            if item.split("=", 1)[0] in replacements:
                args[index] = item.split("=", 1)[0] + "=" + replacements[item.split("=", 1)[0]]
        return args + ["--mount", f"type=bind,src={self.source},dst=/app,readonly",
            "--mount", f"type=bind,src={self.config.private / 'ca.crt'},dst=/run/db01/ca.crt,readonly",
            "--mount", f"type=bind,src={self.config.private / 'other-ca.crt'},dst=/run/db01/other-ca.crt,readonly",
            "--mount", f"type=bind,src={self.config.private / 'app-password'},dst=/run/secrets/app-password,readonly",
            "--env", "CLIPFORGE_DATABASE_SSL_MODE=verify-full", "--env", "CLIPFORGE_DATABASE_SSL_ROOT_CERT_FILE=/run/db01/ca.crt",
            "--env", "CLIPFORGE_DATABASE_POOL_SIZE=2", "--env", "CLIPFORGE_DATABASE_POOL_OVERFLOW=1"]

    def execute(self, source):
        self.source = Path(source)
        value = None
        result = {"schema": "clipforge-db01-compatibility-1", "status": "failed", "postgres_image": PG_IMAGE,
                  "candidate_image": self.config.image_id, "candidate_kind": "existing exclusively owned CI image with current verified curated sources mounted read-only",
                  "fixture_role": "clipforge_migrator; existing tests create/drop only their own schemas", "runtime_app_role": "clipforge_app; no DDL grants"}
        try:
            value = self.prepare()
            self.start()
            directory = self.attempt("check-db01")
            self.candidate(directory)
            _, network = self.call(directory, "internal-network", ["network", "inspect", "--format", '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Labels}},"internal":{{json .Internal}},"ipv6":{{json .EnableIPv6}}}', self.network_name(value)])
            network = json.loads(network); self.owned(value, network, "network")
            ci.require(network["internal"] is True and network["ipv6"] is False, "Network isolation changed")
            _, postgres = self.call(directory, "postgres-ports", ["inspect", "--format", '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"ports":{{json .HostConfig.PortBindings}}}', value["prefix"] + "-postgres"])
            postgres = json.loads(postgres); self.owned(value, postgres, "container"); ci.require(not postgres["ports"], "Published PG port")
            ci.save_new(self.config.state_root / "checked.json", {"status": "passed", "network": network, "published_ports": False})
            arguments = self.runner_arguments(value, "db01-contract", self.config.reports)
            code, _ = self.call(directory, "int-contract", arguments + [self.config.image_id, "python", "scripts/db01_compatibility.py", "contract", "--report", "/ci-results/db01-contract.json"], timeout=180, allowed=tuple(range(256)))
            ci.require(code == 0, "INT-equivalent contract failed; no suite substituted")
            ci.save_new(self.config.state_root / "migrated.json", {"status": "passed", "migration": "AUTH and cloud real public schema"})
            tests = self.run("pg-tests", ["python", "scripts/db01_compatibility.py", "pg-suite", "--report", "/ci-results/pg-test-summary.json"], timeout=1800)
            result["suite"] = tests
            result["status"] = "passed" if tests["exit_code"] == 0 else "failed"
        except Exception as error:
            result["error_type"] = type(error).__name__
        finally:
            result["cleanup"] = self.cleanup()
            for name in ("app-password", "ca.key", "server.key", "other-ca.key"):
                item = self.config.private / name
                if item.exists():
                    ci.context._check_components(item)
                    ci.require(item.is_file() and not item.is_symlink(), "Unsafe private cleanup target")
                    item.unlink()
            ci.save_new(self.config.reports / "db01-compatibility.json", result)
        return result

    def optional_resource_call(self, directory, label, arguments, identifier):
        if arguments[:2] == ["rm", "-f"]:
            arguments = [*arguments[:2], "-v", *arguments[2:]]
        return super().optional_resource_call(directory, label, arguments, identifier)

    def execute_browsers(self, source, manifest_hash):
        """Separate new database; only the two existing PostgreSQL browser gates."""
        self.source = Path(source)
        result = {"schema": "clipforge-db01-browser-compatibility-1", "status": "failed", "scenarios": {},
            "postgres_image": PG_IMAGE, "browser_image": self.config.image_id,
            "fixture_role": "clipforge_migrator for isolated browser schemas; runtime app DDL remains forbidden",
            "unit_or_INT_contract_rerun": False}
        try:
            value = self.prepare(); self.start()
            directory = self.attempt("browser-isolation")
            self.candidate(directory)
            _, raw = self.call(directory, "network", ["network", "inspect", "--format", '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Labels}},"internal":{{json .Internal}},"ipv6":{{json .EnableIPv6}}}', self.network_name(value)])
            network = json.loads(raw); self.owned(value, network, "network")
            ci.require(network["internal"] is True and network["ipv6"] is False, "Browser network isolation changed")
            _, raw = self.call(directory, "postgres", ["inspect", "--format", '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"ports":{{json .HostConfig.PortBindings}}}', value["prefix"] + "-postgres"])
            postgres = json.loads(raw); self.owned(value, postgres, "container")
            ci.require(not postgres["ports"], "Browser PostgreSQL published ports")
            ci.save_new(self.config.state_root / "checked.json", {"status": "passed", "network": network, "published_ports": False})
            # Existing migration and browser fixtures create their own AUTH schemas.
            self.migrate()
            postgres_id = json.loads((self.config.state_root / "prepared.json").read_text())["image_id"]
            for scenario, filename in (("auth", "browser-auth-summary.json"), ("recovery", "browser-auth-recovery-summary.json")):
                role = "browser-auth" if scenario == "auth" else "browser-auth-recovery"
                outcome = self.run(role, ["python", "scripts/run_ci_auth_browser.py", "--report", "/ci-results/" + filename,
                    "--image-id", self.config.image_id, "--postgres-image-id", postgres_id,
                    "--context-manifest-sha256", manifest_hash, "--scenario", scenario],
                    reports_subdir=role, browser=True, timeout=1200)
                result["scenarios"][scenario] = outcome
                ci.require(outcome["exit_code"] == 0, "Browser gate failed; no retry")
            result["status"] = "passed"
        except Exception as error:
            result["error_type"] = type(error).__name__
        finally:
            result["cleanup"] = self.cleanup()
            for name in ("app-password", "ca.key", "server.key", "other-ca.key"):
                item = self.config.private / name
                if item.exists():
                    ci.context._check_components(item)
                    ci.require(item.is_file() and not item.is_symlink(), "Unsafe browser private cleanup target")
                    item.unlink()
            ci.save_new(self.config.reports / "db01-browser-compatibility.json", result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    probe = sub.add_parser("contract"); probe.add_argument("--report", type=Path, required=True)
    suite = sub.add_parser("pg-suite"); suite.add_argument("--report", type=Path, required=True)
    for action in ("run", "browser-run"):
        run = sub.add_parser(action); run.add_argument("--scratch", type=Path, required=True); run.add_argument("--source", type=Path, required=True); run.add_argument("--manifest", type=Path, required=True); run.add_argument("--ci-image", required=True)
    args = parser.parse_args()
    if args.action == "contract":
        return 0 if contract(args.report)["status"] == "passed" else 1
    if args.action == "pg-suite":
        return 0 if pg_suite(args.report)["status"] == "passed" else 1
    require(os.name == "nt", "Host lifecycle is verified only for Docker Desktop on Windows; guest contracts run on Linux")
    ci.context.verify_context(args.source, args.manifest)
    reports = args.scratch / "reports"
    reports.mkdir(exist_ok=True)
    config = ci.Configuration.from_environment({"CI_SCRATCH": str(args.scratch.resolve()), "CI_REPORTS": str(reports.resolve()),
        "CI_CONTAINER_USER": "10001:10001", "CI_RUN_KEY": "db01-" + args.scratch.name, "CI_IMAGE_ID": args.ci_image})
    lifecycle = Compatibility(config)
    result = (lifecycle.execute_browsers(args.source, hashlib.sha256(args.manifest.read_bytes()).hexdigest())
              if args.action == "browser-run" else lifecycle.execute(args.source))
    print(json.dumps({"status": result["status"], "cleanup": result["cleanup"]["status"]}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
