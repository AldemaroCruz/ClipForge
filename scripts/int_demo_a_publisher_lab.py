"""Rehearse the exact publisher and two reviewed OCI archives without cloud credentials."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import subprocess
from tempfile import TemporaryDirectory, TemporaryFile
import time

from scripts import int_demo_a_docker as identity
from scripts import int_demo_a_docker_prepare as preparation
from scripts import int_demo_a_publish as publish
from scripts import int_guest_inventory as transport


SCHEMA = "clipforge-int-demo-a-publisher-rehearsal-1"
REGISTRY = "registry@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
PYTHON = "python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df"
BOUND = 65536
REPO = Path(__file__).resolve().parents[1]
require = transport.require


def credential_free(env):
    require(not any(env.get(name) for name in ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                "GCP_ACCESS_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_AUTH_ACCESS_TOKEN",
                "GOOGLE_OAUTH_ACCESS_TOKEN", "DOCKER_AUTH_CONFIG")), "publisher_rehearsal_requires_credential_free_runner")


class LabFailure(ValueError):
    def __init__(self, phase, exit_code, raw):
        super().__init__(phase)
        self.evidence = {"stage": phase, "native_exit": exit_code, "output_bytes": len(raw),
                         "output_sha256": sha256(raw).hexdigest(), "diagnostic": raw[-1200:].decode("utf-8", "replace")}


def bounded(args, env, label, *, timeout=25, check=True):
    import resource

    def output_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (BOUND, BOUND))

    with TemporaryFile() as result:
        try:
            code = subprocess.run(args, env=env, stdout=result, stderr=subprocess.STDOUT, timeout=timeout,
                                  check=False, preexec_fn=output_limit).returncode
        except subprocess.TimeoutExpired:
            code = None
        result.seek(0)
        output = result.read(BOUND + 1)
    if code is None or len(output) >= BOUND or check and code:
        raise LabFailure(label, code, output)
    return code, output


def comparison_proof(eligible, preparation_raw, engine_raw, tool):
    profile = transport.decode(preparation_raw)
    obs = eligible["observation"]
    require(profile["schema"] == preparation.SCHEMA and profile["profile"] == "evaluate"
            and profile["status"] == "prepared_verified" and profile["cloud_credentials_used"] is False
            and profile["oidc_job_capability"] is False and profile["after"]["toolchain"] == eligible
            and profile["run"] == obs["run"] and profile["attempt"] == obs["attempt"] and profile["commit"] == obs["source_commit"],
            "publisher_rehearsal_requires_same_credential_free_preparation")
    return {"schema": SCHEMA, "status": "tls_copy_pending", **{key: obs[key] for key in ("source_commit", "run", "attempt", "job", "boot_id")},
            "source_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "docker_toolchain_sha256": sha256(engine_raw).hexdigest(), "docker_projection_sha256": identity.projection_sha256(eligible),
            "preparation_sha256": sha256(preparation_raw).hexdigest(), "publisher_manifest": tool["manifest"],
            "publisher_config": tool["config"], "images": {key: list(value) for key, value in publish.TARGETS.items()},
            "registry_image": REGISTRY, "cloud_credentials_used": False}


def trust(work, env):
    ca = work / "ca.pem"
    ca_key = work / "ca.key"
    server = work / "server.pem"
    server_key = work / "server.key"
    csr = work / "server.csr"
    extension = work / "tls.cnf"
    extension.write_text("subjectAltName=DNS:registry\nextendedKeyUsage=serverAuth\n", encoding="ascii")
    openssl = "/usr/bin/openssl"
    bounded([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=ClipForge Lab CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", ca_key, "-out", ca], env, "rehearsal_ca")
    bounded([openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=registry", "-keyout", server_key,
             "-out", csr], env, "rehearsal_server_key")
    bounded([openssl, "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial", "-days", "1",
             "-extfile", extension, "-out", server], env, "rehearsal_server_certificate")
    return ca, server, server_key


def mount(path, target):
    return f"--mount=type=bind,source={path},target={target},readonly"


def verify_server(docker, network, ca, work, report, expected):
    statement = ("import json; from pathlib import Path; from scripts.int_demo_a_publish import verify_registry; "
                 "targets=json.loads(Path('/lab/expected.json').read_bytes()); "
                 "[verify_registry('registry:5000/lab/'+name+'@'+row['manifest'],row,ca='/tls/ca.pem') for name,row in targets.items()]")
    scope = work / "expected.json"
    scope.write_bytes(transport.canonical(expected))
    docker("rehearsal_verify_oci", "run", "--rm", "--pull=never", "--network", network, "--read-only", "--cap-drop=ALL",
           "--security-opt=no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}", "--workdir=/source",
           mount(REPO / "scripts", "/source/scripts"), mount(scope, "/lab/expected.json"), mount(ca, "/tls/ca.pem"),
           PYTHON, "python", "-B", "-c", statement, timeout=240)
    report["manifest_config_layers_verified"] = True


def rehearse(bundle, engine_raw, preparation_raw, report, work):
    engine_proof = transport.decode(engine_raw)
    identity.verify_same_host(engine_proof, identity.verify(engine_proof))
    tool = publish.verify_tool(bundle, transport.decode(transport._local_bytes(bundle / "publisher-proof.json", BOUND)))
    report.update(comparison_proof(engine_proof, preparation_raw, engine_raw, tool))
    expected = {name: publish.archive_inventory(bundle / f"{name}.oci.tar", approved) for name, approved in publish.TARGETS.items()}
    config = work / "docker-config"
    config.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(work), "LC_ALL": "C"}
    engine = identity.endpoint(config)

    def docker(label, *args, timeout=25, check=True):
        return bounded([*engine, *args], env, label, timeout=timeout, check=check)

    ca, server, server_key = trust(work, env)
    auth = work / "auth.json"
    auth.write_bytes(b'{"auths":{}}')
    prefix = "clipforge-publisher-lab-" + secrets.token_hex(10)
    network = prefix + "-net"
    registry = prefix + "-registry"
    containers = [registry]
    created_network = False
    primary = None
    try:
        for image in (REGISTRY, PYTHON):
            docker("rehearsal_pull_pinned_fixture", "pull", "--platform=linux/amd64", image, timeout=150)
        docker("rehearsal_load_publisher", "load", "--input", bundle / "publisher.oci.tar", timeout=180)
        _, inspected = docker("rehearsal_publisher_id", "image", "inspect", "--format={{.Id}}", tool["config"])
        require(inspected.decode().strip() == tool["config"], "rehearsal_loaded_publisher_config_changed")
        docker("rehearsal_create_network", "network", "create", "--internal", network)
        created_network = True
        _, value = docker("rehearsal_network_internal", "network", "inspect", "--format={{.Internal}}", network)
        require(value.strip() == b"true", "rehearsal_network_not_internal")
        docker("rehearsal_start_registry", "run", "-d", "--name", registry, "--pull=never", "--network", network,
               "--network-alias", "registry", "--network-alias", "wrong", "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges", "--tmpfs=/var/lib/registry:rw,nosuid,nodev,size=512m",
               mount(server, "/tls/server.pem"), mount(server_key, "/tls/server.key"),
               "--env=REGISTRY_HTTP_TLS_CERTIFICATE=/tls/server.pem", "--env=REGISTRY_HTTP_TLS_KEY=/tls/server.key", REGISTRY)
        _, value = docker("rehearsal_no_published_ports", "inspect", "--format={{json .HostConfig.PortBindings}}", registry)
        require(transport.decode(value) in (None, {}), "rehearsal_registry_ports_exposed")
        report["isolated_network"] = True
        time.sleep(2)

        def copy(name, archive, label, host, trusted):
            destination = f"{host}:5000/lab/{name}@{expected[name]['manifest']}"
            args = publish.copy_args(tool["config"], archive, auth, destination, network=network, trust=trusted, engine=engine)
            container = prefix + "-" + label
            containers.append(container)
            args[len(engine) + 1:len(engine) + 1] = ["--name", container]
            return bounded(args, env, label, timeout=240, check=False)

        staged = {}
        for name, scope in expected.items():
            staged[name] = work / f"{name}.oci.tar"
            publish.verified_staging_archive(bundle / f"{name}.oci.tar", staged[name], scope, os.getuid(), os.getgid())
        client = "db01-noble-client"
        code, output = copy(client, staged[client], "bad-ca", "registry", None)
        if code == 0 or b"certificate signed by unknown authority" not in output:
            raise LabFailure("rehearsal_unknown_authority_unverified", code, output)
        report["unknown_ca_rejected"] = True
        code, output = copy(client, staged[client], "bad-host", "wrong", ca)
        if code == 0 or b"x509:" not in output or b"registry, not wrong" not in output:
            raise LabFailure("rehearsal_invalid_hostname_unverified", code, output)
        report["wrong_hostname_rejected"] = True
        for name in expected:
            code, output = copy(name, staged[name], name, "registry", ca)
            if code:
                raise LabFailure("rehearsal_copy_" + name, code, output)
            require(publish.digest_file(bundle / f"{name}.oci.tar") == expected[name]["archive_sha256"], "rehearsal_source_changed")
        report["source_unchanged"] = True
        verify_server(docker, network, ca, work, report, expected)
        identity.verify_same_host(engine_proof, identity.verify(engine_proof))
    except (OSError, ValueError, KeyError) as error:
        primary = error
        raise
    finally:
        try:
            for container in reversed(containers):
                code, output = docker("rehearsal_remove_owned_container", "rm", "-f", container, check=False)
                if code and b"No such container" not in output:
                    raise LabFailure("rehearsal_remove_owned_container", code, output)
            if created_network:
                docker("rehearsal_remove_owned_network", "network", "rm", network)
            report["owned_resources_removed"] = True
        except (OSError, ValueError) as error:
            report["cleanup_failed"] = str(error) if isinstance(error, LabFailure) else type(error).__name__
            if primary is None:
                raise
    report["status"] = "tls_copy_verified"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--toolchain", required=True, type=Path)
    parser.add_argument("--preparation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    credential_free(os.environ)
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(args.output.parent.resolve() == runner and args.output.name == "publisher-rehearsal.json", "rehearsal_report_path")
    os.umask(0o077)
    report = {"schema": SCHEMA, "status": "blocked", "cloud_credentials_used": False}
    try:
        engine = transport._local_bytes(args.toolchain, BOUND)
        prepare_raw = transport._local_bytes(args.preparation, preparation.MAX_RECEIPT)
        with TemporaryDirectory(prefix="clipforge-publisher-lab-", dir=runner) as work:
            rehearse(args.bundle, engine, prepare_raw, report, Path(work))
    except (OSError, KeyError, ValueError) as error:
        report["status"] = "blocked"
        report["failure"] = error.evidence if isinstance(error, LabFailure) else {"error": type(error).__name__}
    with args.output.open("xb") as output:
        output.write(transport.canonical(report))
    print(json.dumps({"status": report["status"], "cloud_credentials_used": False}))
    return int(report["status"] != "tls_copy_verified")


if __name__ == "__main__":
    raise SystemExit(main())
