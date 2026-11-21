"""Generation-pinned custody for the scoped INT A operations."""

import json
import re
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener

from scripts import int_guest_inventory as transport
from scripts import int_release as custody


LIMIT = 1024 * 1024
PREFIX = "private-deploy/int/demo-a/v1/"
GCS = "https://storage.googleapis.com/"
BUCKET = "clipforgebeta2-tfstate-int"
SHA = r"[a-f0-9]{64}"
RUN = r"[1-9][0-9]*"
PRODUCERS = {
    "publish": (("publication-runtime.json", "publication-db01-noble-client.json"),
                ("publication-runtime-intent.json", "publication-db01-noble-client-intent.json")),
    "secrets": (("noble-bootstrap.json", "secret-versions.json"),
                ("secret-app_password-intent.json", "secret-migrator_password-intent.json",
                 "secret-postgres_ca-intent.json", "secret-bootstrap_admin-intent.json")),
    "guest_intervention": (("noble-intervention-result.json",), ("noble-intervention-intent.json",)),
}
JOB_OPERATIONS = {"migrate": {"create", "run"}, "app": {"create", "run"}, "admin": {"run"}}
KIND = ("intent", "result")
FILES = "|".join(re.escape(leaf) for terminal, _ in PRODUCERS.values() for leaf in terminal)
INTENTS = "|".join(re.escape(leaf) for _, intents in PRODUCERS.values() for leaf in intents)
NAME = re.compile(re.escape(PREFIX) + r"(?:[a-f0-9]{40}/(?:" + RUN + r"-1/(?:" + FILES
                  + r")|decisions/[a-f0-9]{32}/(?:" + INTENTS + r"))"
                  + r"|jobs/(?:(?:migrate|app)/(?:create|run)|admin/run)/(?:intent|result)\.json)")
require = transport.require


class Custody:
    def __init__(self, token, *, names=None):
        require(re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", token), "demo_a_custody_token_format")
        self.token = token
        self.names = None if names is None else frozenset(names)
        require(self.names is None or bool(self.names) and all(NAME.fullmatch(name) for name in self.names),
                "demo_a_custody_exact_names")

    def request(self, method, name, *, generation=None, payload=None):
        require(isinstance(name, str) and NAME.fullmatch(name), "demo_a_custody_scope")
        require((self.names is None and method == "GET") or (self.names is not None and name in self.names),
                "demo_a_custody_not_in_operation")
        headers = {"Authorization": "Bearer " + self.token}
        if method == "POST":
            require(isinstance(payload, bytes) and len(payload) <= LIMIT and generation is None, "demo_a_custody_create_shape")
            query = {"uploadType": "media", "name": name, "ifGenerationMatch": "0", "fields": "name,generation,size"}
            url = f"{GCS}upload/storage/v1/b/{BUCKET}/o?" + urlencode(query)
            headers["Content-Type"] = "application/octet-stream"
        else:
            require(method == "GET" and payload is None and isinstance(generation, str) and re.fullmatch(RUN, generation),
                    "demo_a_custody_get_shape")
            query = {"alt": "media", "generation": generation, "ifGenerationMatch": generation}
            url = f"{GCS}storage/v1/b/{BUCKET}/o/{quote(name, safe='')}?" + urlencode(query)
        try:
            with build_opener(ProxyHandler({}), transport.NoRedirect()).open(
                Request(url, headers=headers, method=method, data=payload), timeout=45
            ) as response:
                raw = response.read(LIMIT + 1)
            require(len(raw) <= LIMIT, "demo_a_custody_response_bound")
            return raw
        except HTTPError as error:
            status = error.code
            error.close()
            raise transport.Failure("demo_a_custody_request_failed", {"method": method, "object": name, "http_status": status}) from None

    def fetch(self, reference):
        require(isinstance(reference, dict) and set(reference) == {"name", "generation", "sha256", "size"}
                and isinstance(reference["sha256"], str) and re.fullmatch(SHA, reference["sha256"])
                and type(reference["size"]) is int and 0 < reference["size"] <= LIMIT, "demo_a_custody_reference")
        raw = self.request("GET", reference["name"], generation=reference["generation"])
        require(len(raw) == reference["size"] and custody.sha256(raw) == reference["sha256"], "demo_a_custody_verified_bytes")
        return raw

    def create(self, name, document):
        return self.create_bytes(name, custody.canonical(document))

    def create_bytes(self, name, raw):
        require(isinstance(transport.decode(raw), dict), "demo_a_custody_json_object")
        result = json.loads(self.request("POST", name, payload=raw))
        generation = result.get("generation")
        require(result.get("name") == name and str(result.get("size")) == str(len(raw))
                and isinstance(generation, str) and re.fullmatch(RUN, generation), "demo_a_custody_create_receipt")
        reference = {"name": name, "generation": generation, "sha256": custody.sha256(raw), "size": len(raw)}
        self.fetch(reference)
        return reference


def producer_names(env, operation, decision_id):
    commit, run = env.get("GITHUB_SHA", ""), env.get("GITHUB_RUN_ID", "")
    require(operation in PRODUCERS and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and re.fullmatch(r"[a-f0-9]{40}", commit) and re.fullmatch(RUN, run)
            and re.fullmatch(r"[a-f0-9]{32}", decision_id), "demo_a_custody_producer_scope")
    terminal, intents = PRODUCERS[operation]
    return {**{leaf: f"{PREFIX}{commit}/{run}-1/{leaf}" for leaf in terminal},
            **{leaf: f"{PREFIX}{commit}/decisions/{decision_id}/{leaf}" for leaf in intents}}


def job_names(phase, action):
    require(action in JOB_OPERATIONS.get(phase, ()), "demo_a_custody_job_scope")
    return {kind: f"{PREFIX}jobs/{phase}/{action}/{kind}.json" for kind in KIND}
