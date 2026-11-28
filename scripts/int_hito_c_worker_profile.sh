#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit
umask 077

[[ "$GITHUB_WORKFLOW_REF" == 'AldemaroCruz/ClipForge/.github/workflows/int-hito-b.yml@refs/heads/ci/bootstrap-sec03' ]]
[[ "$GITHUB_SHA" =~ ^[a-f0-9]{40}$ && "$GITHUB_SHA" == "$APPROVED_COMMIT" ]]
[[ "$DELIVERY_DIR" == "$RUNNER_TEMP"/clipforge-beta-deploy.* && -d "$DELIVERY_DIR" ]]
[[ "${INT_ADOPT_WORKER_PROFILE:-}" == true && -z "${INT_WORKER_BENCHMARK_BASE:-}" ]]

reports="$DELIVERY_DIR/reports"
verified="$reports/worker-profile-verified.json"
project=clipforgebeta2
region=us-central1
frontend=clipforge-int-beta
api=clipforge-int-beta-api
migrator=clipforge-int-beta-migrate
public=https://clipforge-int-beta-816643438938.us-central1.run.app

[[ -f "$verified" && ! -L "$verified" ]]
jq -e '.schema == "clipforge-int-worker-profile-verified-1" and .status == "passed"' "$verified" >/dev/null
trial="$(jq -er '.comparison.commit | select(test("^[a-f0-9]{40}$"))' "$verified")"
INT_WORKER_BENCHMARK_BASE="$(jq -er '.public.commit | select(test("^[a-f0-9]{40}$"))' "$verified")"
TF_VAR_worker_image="$(jq -er '.tested_worker.image' "$verified")"
selected="$(jq -er '.worker_cpu | select(. == 2 or . == 4)' "$verified")"
[[ "$trial" != "$GITHUB_SHA" && "$trial" != "$INT_WORKER_BENCHMARK_BASE" ]]
[[ "$TF_VAR_worker_image" =~ ^us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/beta-worker@sha256:[a-f0-9]{64}$ ]]
[[ "$(jq -er '.worker_cpu' config/int-worker-profile.json)" == "$selected" ]]

run() { gcloud run "$@" --project "$project" --region "$region" --quiet; }

# shellcheck source=scripts/int_hito_c_worker_benchmark.sh
source scripts/int_hito_c_worker_benchmark.sh
benchmark_baseline="$reports/worker-profile-baseline.json"

case "${1:-}" in
    prepare)
        [[ ! -e "$benchmark_baseline" ]]
        observed="$(benchmark_public)"
        worker="$(benchmark_worker)"
        jq -e --argjson public "$observed" --argjson worker "$worker" '
            .public == $public and .previous_worker == $worker and
            .tested_worker.configuration_sha256 == $worker.configuration_sha256
        ' "$verified" >/dev/null
        jq --argjson worker "$worker" '.worker = $worker' \
            "$DELIVERY_DIR/profile-evidence/worker-benchmark-baseline.json" > "$benchmark_baseline"
        benchmark_read_baseline "$trial"
        ;;
    apply)
        benchmark_read_baseline "$trial"
        benchmark_verify_public
        prior_worker="$(benchmark_worker)"
        jq -e --argjson prior "$prior_worker" '.worker == $prior' "$benchmark_baseline" >/dev/null
        run jobs update "$benchmark_job" --image "$TF_VAR_worker_image" --cpu "$selected" --memory 4Gi \
            --update-env-vars "CLIPFORGE_REVISION=$trial"
        updated="$(benchmark_worker)"
        jq -e --argjson updated "$updated" --argjson prior "$prior_worker" '
            def without_generation: del(.generation, .observed_generation);
            ($updated | without_generation) == (.tested_worker | without_generation) and
            $updated.generation > $prior.generation
        ' "$verified" >/dev/null
        benchmark_verify_public
        jq --argjson worker "$updated" '. + {adopted_worker:$worker}' "$verified" > "$reports/worker-profile-adopted.json"
        ;;
    restore)
        benchmark_restore "$trial"
        ;;
    *)
        exit 2
        ;;
esac
