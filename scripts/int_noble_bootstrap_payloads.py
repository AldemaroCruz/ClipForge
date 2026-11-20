"""Derive the reviewed Noble bootstrap and containment from the frozen DB-01 payloads."""
from hashlib import sha256
from pathlib import Path
from types import ModuleType

from scripts import int_noble_guest_observation as noble


HERE = Path(__file__).resolve().parent
INSTANCE = "7365414160255801909"
BOOT = "8897353356069952044"
DATA = "7382984635240536620"
GUEST_SOURCE = "861de13ce61943a0a9f62118633adab24f413cb4234566cac34cf441eea4a023"
CONTAINMENT_SOURCE = "7fbc88fae2e4b6aa6e980820df7c0b5ce2183c14b6c6d205a6372cf739ebeff4"
GUEST_SHA = "6a4c718a24e9c4c635017e606fa848808e5807b709544794b6d31984e8a2d08f"
CONTAINMENT_SHA = "3ce527474daf7467791621c9e2bdc2d3257e232f0fdcf23bc546f26f3b1e56bf"


def render(name, source_sha, expected_sha, changes):
    raw = (HERE / name).read_bytes()
    noble.require(sha256(raw).hexdigest() == source_sha, "NOBLE_BOOTSTRAP_HISTORICAL_SOURCE")
    for original, replacement, count in changes:
        raw = noble.replace_exact(raw, original.encode("ascii"), replacement.encode("ascii"), count)
    noble.require(sha256(raw).hexdigest() == expected_sha, "NOBLE_BOOTSTRAP_RENDERED_PAYLOAD")
    return raw


def operator_bytes():
    return render("int_bootstrap_vm.py", GUEST_SOURCE, GUEST_SHA, (
        ("6427691858848206684", DATA, 1),
        ("1670495097211408131", INSTANCE, 1),
        ("clipforge-int-base-postgres-data", noble.DATA_DISK, 1),
        ("clipforge-pg-data", noble.DEVICE_NAME, 2),
        ("17.12-0+deb13u1", "17.12-1.pgdg24.04+1", 2),
        ("10.80.1.2", noble.PRIVATE_IP, 5),
        ("listen_addresses='10.80.1.3'", "listen_addresses='10.80.1.3,127.0.0.1'", 1),
        ('clipforge_migrator 10.80.0.0/26 scram-sha-256\\n").encode()',
         'clipforge_migrator 10.80.0.0/26 scram-sha-256\\n"\n'
         '               "hostssl clipforge aldemaro_int 127.0.0.1/32 scram-sha-256\\n").encode()', 1),
        ('ON SEQUENCES TO clipforge_app; COMMIT;")', 'ON SEQUENCES TO clipforge_app; "\n'
         '                 "CREATE ROLE aldemaro_int NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; COMMIT;")', 1),
        ('"listen": "10.80.1.3"', '"listen": "10.80.1.3,127.0.0.1"', 1),
        ('                "\'app_temp\',',
         '                "\'personal_pending\',EXISTS(SELECT 1 FROM pg_authid WHERE rolname=\'aldemaro_int\' AND NOT rolcanlogin AND NOT rolinherit "\n'
         '                "AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolpassword IS NULL "\n'
         '                "AND NOT has_database_privilege(rolname,\'clipforge\',\'CONNECT\')),"\n'
         '                "\'app_temp\',', 1),
        ('"migrator_schema_create": True, "memberships": 0,', '"migrator_schema_create": True, "memberships": 0, "personal_pending": True,', 1),
    ))


def containment_bytes():
    return render("int_bootstrap_containment.py", CONTAINMENT_SOURCE, CONTAINMENT_SHA, (
        ("6427691858848206684", DATA, 3),
        ("1670495097211408131", INSTANCE, 2),
        ("4c44931bba34e0754b7c0762852a5c1b615a1e307df9c458d231232d55e4c907",
         "ac9bf71c90ca096a55e73b6c4a7ea08c6c8159eee10db60642a9058d67d6668e", 1),
        ("postgresql-common278, authenticated Debian archive package", "postgresql-common 297, authenticated PGDG archive package", 1),
    ))


def operator_contract(raw):
    """Execute only the validated public source for its receipt/input validators."""
    noble.require(sha256(raw).hexdigest() == GUEST_SHA, "NOBLE_BOOTSTRAP_OPERATOR_DIGEST")
    module = ModuleType("_clipforge_db01_noble_guest")
    exec(compile(raw, "<reviewed-noble-bootstrap>", "exec"), module.__dict__)
    return module
