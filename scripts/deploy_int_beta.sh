#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit
umask 077

[[ "$GITHUB_WORKFLOW_REF" == 'AldemaroCruz/ClipForge/.github/workflows/int-hito-b.yml@refs/heads/ci/bootstrap-sec03' ]]
[[ "$GITHUB_SHA" =~ ^[a-f0-9]{40}$ && "$GITHUB_SHA" == "$APPROVED_COMMIT" ]]
[[ "$DELIVERY_DIR" == "$RUNNER_TEMP"/clipforge-beta-deploy.* && -d "$DELIVERY_DIR" ]]

reports="$DELIVERY_DIR/reports"
project=clipforgebeta2
region=us-central1
frontend=clipforge-int-beta
api=clipforge-int-beta-api
migrator=clipforge-int-beta-migrate
public=https://clipforge-int-beta-816643438938.us-central1.run.app
private=https://clipforge-int-beta-api-816643438938.us-central1.run.app
export TF_IN_AUTOMATION=1 TF_INPUT=0
export TF_VAR_source_revision="$GITHUB_SHA"
TF_VAR_web_image="$(jq -er '.images.web.image' "$reports/candidate.json")"
TF_VAR_worker_image="$(jq -er '.images.worker.image' "$reports/candidate.json")"
export TF_VAR_web_image TF_VAR_worker_image

editorial_model="${INT_EDITORIAL_OPENAI_MODEL:-}"
editorial_credential_version="${INT_EDITORIAL_OPENAI_KEY_VERSION:-}"
TF_VAR_editorial_provider=null
if [[ -n "$editorial_model" || -n "$editorial_credential_version" ]]; then
    [[ "$editorial_model" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$ ]]
    [[ "$editorial_credential_version" =~ ^[1-9][0-9]{0,9}$ ]]
    TF_VAR_editorial_provider="$(jq -nc --arg model "$editorial_model" --arg version "$editorial_credential_version" \
        '{model:$model,credential_version:$version}')"
fi
export TF_VAR_editorial_provider

tf() { terraform -chdir=infra/gcp/int-beta "$@"; }
run() { gcloud run "$@" --project "$project" --region "$region" --quiet; }

apply_beta() {
    local public_enabled="$1" nonce="$2" name="$3" plan
    plan="$DELIVERY_DIR/$name.tfplan"
    tf plan -input=false -lock-timeout=300s -no-color -out "$plan" \
        -var "serve_public=$public_enabled" -var "acceptance_nonce=$nonce" || return
    tf show -json "$plan" | python -m scripts.int_hito_b_delivery plan "$reports/$name-plan.json" || return
    tf apply -input=false -lock-timeout=300s -no-color "$plan"
}

publish_beta() {
    local target image raw digest
    python -m scripts.int_hito_b_delivery registry-auth "$DELIVERY_DIR/registry.json"
    trap 'rm -f -- "$DELIVERY_DIR/registry.json"' EXIT
    mkdir "$DELIVERY_DIR/skopeo-tmp"
    skopeo() {
        docker run --rm --pull never --read-only --cap-drop ALL --security-opt no-new-privileges \
            --tmpfs /tmp:rw,nosuid,nodev,noexec,size=128m --user "$(id -u):$(id -g)" \
            -v "$DELIVERY_DIR:/private" "$SKOPEO_IMAGE" --tmpdir /private/skopeo-tmp "$@"
    }
    for target in web worker; do
        image="$(jq -er --arg target "$target" '.images[$target].image' "$reports/candidate.json")"
        [[ "$image" =~ ^us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/beta-$target@sha256:[a-f0-9]{64}$ ]]
        skopeo copy --preserve-digests --authfile /private/registry.json "oci-archive:/private/images/$target.tar" "docker://$image"
        raw="$DELIVERY_DIR/$target-manifest.json"
        skopeo inspect --raw --authfile /private/registry.json "docker://$image" > "$raw"
        digest="$(sha256sum "$raw" | cut -d ' ' -f 1)"
        [[ "$image" == *"@sha256:$digest" ]]
    done
}

verify_revision() {
    local service="$1" revision image url="$2" description active
    description="$(run services describe "$service" --format=json)"
    jq -e --arg url "$url" '(.metadata.annotations["run.googleapis.com/urls"] | fromjson | index($url)) != null' \
        <<< "$description" > /dev/null
    revision="$(jq -er '.status.latestReadyRevisionName' <<< "$description")"
    [[ "$revision" =~ ^$service-[a-z0-9-]+$ ]]
    image="$(run revisions describe "$revision" --format='value(status.imageDigest)')"
    [[ "$image" == "$TF_VAR_web_image" ]]
    active="$(jq -er '[.status.traffic[] | select(.percent == 100)] | select(length == 1) | .[0].revisionName' \
        <<< "$description")"
    [[ "$active" == "$revision" ]]
    printf '%s\n' "$revision"
}

capture_rollout() {
    local phase="$1" worker_spec worker_configuration worker_editorial migrator_image
    FRONTEND_REVISION="$(verify_revision "$frontend" "$public")"
    API_REVISION="$(verify_revision "$api" "$private")"
    worker_spec="$(run jobs describe clipforge-int-worker --format='json(metadata.generation,spec.template.spec)')"
    [[ "$(jq -er '.spec.template.spec.template.spec.containers[0].image' <<< "$worker_spec")" == "$TF_VAR_worker_image" ]]
    worker_configuration="$(jq -ec '{
        generation: (.metadata.generation | tonumber),
        task_count: (.spec.template.spec.taskCount // 1),
        parallelism: (.spec.template.spec.parallelism // 1),
        timeout_seconds: (.spec.template.spec.template.spec.timeoutSeconds | tonumber),
        max_retries: .spec.template.spec.template.spec.maxRetries,
        cpu: .spec.template.spec.template.spec.containers[0].resources.limits.cpu,
        memory: .spec.template.spec.template.spec.containers[0].resources.limits.memory
    }' <<< "$worker_spec")"
    worker_editorial="$(editorial_settings <<< "$worker_spec")"
    migrator_image="$(run jobs describe "$migrator" --format='value(spec.template.spec.template.spec.containers[0].image)')"
    [[ "$migrator_image" == "$TF_VAR_web_image" ]]
    jq -n --arg commit "$GITHUB_SHA" --arg frontend "$FRONTEND_REVISION" --arg api "$API_REVISION" \
        --arg public_url "$public" --arg api_url "$private" --arg web "$TF_VAR_web_image" \
        --arg worker "$TF_VAR_worker_image" --arg migrator "$migrator_image" \
        --arg utc "$(date -u +%FT%TZ)" --argjson worker_configuration "$worker_configuration" \
        --argjson editorial "$worker_editorial" \
        '{commit:$commit,frontend_revision:$frontend,api_revision:$api,public_url:$public_url,api_url:$api_url,
          web_image:$web,worker_image:$worker,migrator_image:$migrator,observed_utc:$utc,
          worker_configuration:$worker_configuration,editorial:$editorial}' \
        > "$reports/$phase-rollout.json"
}

editorial_settings() {
    jq -ec '
        [.spec.template.spec.template.spec.containers[0].env[]?] |
        def val($name): map(select(.name == $name)) | .[0].value;
        {
            provider: (val("CLIPFORGE_AI_PROVIDER") // "disabled"),
            model: (val("CLIPFORGE_AI_MODEL") // ""),
            timeout: (val("CLIPFORGE_AI_TIMEOUT_SECONDS") // ""),
            key_version: (map(select(.name == "OPENAI_API_KEY")) | .[0].valueFrom.secretKeyRef.key // "")
        } |
        select(.provider == "disabled" or (.provider == "openai" and
            (.model | test("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$")) and
            (.key_version | test("^[1-9][0-9]{0,9}$")) and (.timeout | test("^[0-9]{2,3}$"))))
        '
}

capture_previous() {
    local version front previous_api worker_spec worker worker_editorial migrator_image
    if ! version="$(curl --silent --fail --max-time 10 "$public/environment" |
        jq -er 'select(.environment == "INT") | .revision')"; then
        return 0
    fi
    [[ "$version" =~ ^[a-f0-9]{40}$ ]]
    front="$(run services describe "$frontend" --format=json |
        jq -er '.status.traffic[] | select(.percent == 100) | .revisionName')"
    previous_api="$(run services describe "$api" --format=json |
        jq -er '.status.traffic[] | select(.percent == 100) | .revisionName')"
    worker_spec="$(run jobs describe clipforge-int-worker --format='json(spec.template.spec.template.spec.containers)')"
    worker="$(jq -er '.spec.template.spec.template.spec.containers[0].image' <<< "$worker_spec")"
    worker_editorial="$(editorial_settings <<< "$worker_spec")"
    migrator_image="$(run jobs describe "$migrator" --format='value(spec.template.spec.template.spec.containers[0].image)')"
    [[ "$front" =~ ^clipforge-int-beta-[0-9][0-9a-z-]+$ &&
       "$previous_api" =~ ^clipforge-int-beta-api-[0-9][0-9a-z-]+$ &&
       "$migrator_image" =~ ^us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/beta-web@sha256:[a-f0-9]{64}$ &&
       "$worker" =~ ^us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/beta-worker@sha256:[a-f0-9]{64}$ ]]
    jq -n --arg commit "$version" --arg frontend "$front" --arg api "$previous_api" --arg worker "$worker" \
        --arg migrator "$migrator_image" --argjson editorial "$worker_editorial" \
        '{commit:$commit,frontend_revision:$frontend,api_revision:$api,worker_image:$worker,
          migrator_image:$migrator,editorial:$editorial}' \
        > "$reports/previous-live.json"
}

restore_previous() {
    local previous="$reports/previous-live.json" version front previous_api worker provider model key_version timeout migrator_image
    local -a editorial_options
    version="$(jq -er '.commit' "$previous")" || return
    front="$(jq -er '.frontend_revision' "$previous")" || return
    previous_api="$(jq -er '.api_revision' "$previous")" || return
    worker="$(jq -er '.worker_image' "$previous")" || return
    migrator_image="$(jq -er '.migrator_image' "$previous")" || return
    provider="$(jq -er '.editorial.provider' "$previous")" || return
    if [[ "$provider" == openai ]]; then
        model="$(jq -er '.editorial.model' "$previous")" || return
        key_version="$(jq -er '.editorial.key_version' "$previous")" || return
        timeout="$(jq -er '.editorial.timeout' "$previous")" || return
        editorial_options=(
            --update-env-vars "CLIPFORGE_REVISION=$version,CLIPFORGE_AI_PROVIDER=openai,CLIPFORGE_AI_MODEL=$model,CLIPFORGE_AI_CONFIG_REVISION=$key_version,CLIPFORGE_AI_TIMEOUT_SECONDS=$timeout"
            --update-secrets "OPENAI_API_KEY=clipforge-int-openai-key:$key_version"
        )
    else
        editorial_options=(
            --update-env-vars "CLIPFORGE_REVISION=$version,CLIPFORGE_AI_PROVIDER=disabled"
            --remove-env-vars CLIPFORGE_AI_MODEL,CLIPFORGE_AI_CONFIG_REVISION,CLIPFORGE_AI_TIMEOUT_SECONDS
            --remove-secrets OPENAI_API_KEY
        )
    fi
    run services update "$frontend" --invoker-iam-check || return
    run jobs update clipforge-int-worker --image "$worker" "${editorial_options[@]}" || return
    run services update-traffic "$api" --to-revisions "$previous_api=100" || return
    run services update-traffic "$frontend" --to-revisions "$front=100" || return
    run jobs update "$migrator" --image "$migrator_image" || return
    run services update "$frontend" --no-invoker-iam-check || return
    curl --silent --fail --max-time 15 --retry 3 "$public/health" | jq -e '.status == "ok"' >/dev/null || return
    curl --silent --fail --max-time 15 "$public/environment" |
        jq -e --arg version "$version" '.revision == $version' >/dev/null
}

create_fixture() {
    local speech
    speech='En Guatemala los vecinos recuperaron un huerto comunitario. Empezaron guardando semillas de maíz de varios colores. Luego compartieron turnos para regar y aprender de la cosecha. Un año después, el grupo enseñó a otras escuelas a conservar semillas y a cultivar en espacios pequeños. La lección es clara: cuidar la tierra funciona mejor cuando todos comparten lo que aprenden.'
    espeak-ng -v es -s 148 -w "$DELIVERY_DIR/voice.wav" "$speech $speech"
    ffmpeg -hide_banner -loglevel error -nostdin \
        -f lavfi -i 'testsrc2=size=1280x720:rate=24' -stream_loop -1 -i "$DELIVERY_DIR/voice.wav" \
        -t 120 -c:v libx264 -preset veryfast -pix_fmt yuv420p -threads 2 \
        -b:v 3000k -minrate 3000k -maxrate 3000k -bufsize 6000k -x264-params nal-hrd=cbr \
        -c:a aac -b:a 96k -movflags +faststart "$DELIVERY_DIR/fixture.mp4"
    [[ "$(stat -c %s "$DELIVERY_DIR/fixture.mp4")" -gt 8388608 ]]
}

create_capacity_fixtures() {
    local minutes
    mkdir "$DELIVERY_DIR/capacity"
    for minutes in 3 5 10 20; do
        ffmpeg -hide_banner -loglevel error -nostdin \
            -f lavfi -i 'testsrc2=size=854x480:rate=24' -stream_loop -1 -i "$DELIVERY_DIR/voice.wav" \
            -t "$((minutes * 60))" -c:v libx264 -preset ultrafast -pix_fmt yuv420p -threads 2 \
            -b:v 1300k -minrate 1300k -maxrate 1300k -bufsize 2600k -x264-params nal-hrd=cbr \
            -c:a aac -b:a 96k -movflags +faststart "$DELIVERY_DIR/capacity/${minutes}m.mp4"
    done
    ffmpeg -hide_banner -loglevel error -nostdin -f lavfi \
        -i 'testsrc2=size=1280x720:rate=24,noise=alls=24:allf=t+u:all_seed=613' \
        -stream_loop -1 -i "$DELIVERY_DIR/voice.wav" -t 1200 \
        -c:v libx264 -preset ultrafast -pix_fmt yuv420p -threads 4 \
        -b:v 14000k -maxrate 16000k -bufsize 28000k -x264-params 'nal-hrd=none' \
        -c:a aac -b:a 96k -movflags +faststart "$DELIVERY_DIR/capacity/large.mp4"
    python - "$DELIVERY_DIR/capacity/precise.mp4" "$DELIVERY_DIR/voice.wav" <<'PY'
from pathlib import Path
import sys
from tests.test_hito_c_cuts import make_fixture

make_fixture(Path(sys.argv[1]), voice=Path(sys.argv[2]))
PY
}

capacity_acceptance() {
    local phase="$1" report prior="" state="$DELIVERY_DIR/capacity-private.json"
    local -a evidence_args=() checkpoint_args=()
    case "$phase" in
        setup) report="$reports/browser-capacity-setup.json" ;;
        load)
            create_capacity_fixtures
            report="$reports/browser-capacity-load.json"
            prior="$reports/browser-capacity-setup.json"
            ;;
        cuts)
            report="$reports/browser-capacity-cuts.json"
            prior="$reports/browser-capacity-load.json"
            ;;
        editorial)
            report="$reports/browser-capacity.json"
            prior="$reports/browser-capacity-cuts.json"
            ;;
        cleanup)
            [[ -f "$state" ]] || return 0
            report="$reports/browser-capacity-cleanup.json"
            ;;
    esac
    if [[ -n "$prior" ]]; then
        checkpoint_args=(--prior-report "$prior")
    fi
    if [[ -n "${INT_EDITORIAL_CAPACITY_REPORT:-}" ]]; then
        [[ "$INT_EDITORIAL_CAPACITY_REPORT" == "$reports/prior-provider-capacity.json" ]]
        if [[ "$phase" == editorial ]]; then
            evidence_args=(--reuse-provider-report "$INT_EDITORIAL_CAPACITY_REPORT")
        fi
    fi
    env -u CLOUDSDK_AUTH_ACCESS_TOKEN -u GOOGLE_OAUTH_ACCESS_TOKEN \
        -u GOOGLE_APPLICATION_CREDENTIALS -u CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE \
        python -m scripts.int_hito_b_capacity_browser --commit "$GITHUB_SHA" \
        --frontend-revision "$FRONTEND_REVISION" --api-revision "$API_REVISION" \
        --editorial-model "$editorial_model" --fixture-dir "$DELIVERY_DIR/capacity" \
        --precise-fixture "$DELIVERY_DIR/capacity/precise.mp4" \
        --large-fixture "$DELIVERY_DIR/capacity/large.mp4" \
        --phase "$phase" --state "$state" --report "$report" \
        "${checkpoint_args[@]}" "${evidence_args[@]}"
}

load_replacement_rollout() {
    local rollout="$reports/after-rollout.json"
    [[ -f "$rollout" && ! -L "$rollout" ]]
    jq -e --arg commit "$GITHUB_SHA" --arg web "$TF_VAR_web_image" --arg worker "$TF_VAR_worker_image" \
        '.commit == $commit and .web_image == $web and .worker_image == $worker' "$rollout" >/dev/null
    FRONTEND_REVISION="$(jq -er '.frontend_revision' "$rollout")"
    API_REVISION="$(jq -er '.api_revision' "$rollout")"
}

browser_acceptance() {
    local phase="$1"
    shift
    env -u CLOUDSDK_AUTH_ACCESS_TOKEN -u GOOGLE_OAUTH_ACCESS_TOKEN \
        -u GOOGLE_APPLICATION_CREDENTIALS -u CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE \
        python -m scripts.int_hito_b_browser "$phase" --commit "$GITHUB_SHA" \
        --frontend-revision "$FRONTEND_REVISION" --api-revision "$API_REVISION" \
        --editorial-model "$editorial_model" --state "$DELIVERY_DIR/browser-private.json" \
        --report "$reports/browser-$phase.json" "$@"
}

restore_failed_delivery() {
    if [[ -f "$reports/previous-live.json" ]] && restore_previous; then
        printf '%s\n' 'The last healthy public beta revisions, worker and migrator pin were restored.' > "$reports/acceptance-failure.txt"
    elif apply_beta false "run-$GITHUB_RUN_ID-b$GITHUB_RUN_ATTEMPT" hidden; then
        printf '%s\n' 'Public access disabled after unsuccessful Hito B acceptance.' > "$reports/acceptance-failure.txt"
    else
        printf '%s\n' 'Hito B acceptance failed and disabling public access also failed.' > "$reports/acceptance-failure.txt"
        return 1
    fi
}

rollback_delivery() {
    local result="$?"
    if [[ "$result" -ne 0 ]]; then
        restore_failed_delivery
    fi
}

case "${1:-}" in
    publish)
        publish_beta
        ;;
    prepare)
        tf init -input=false -lockfile=readonly -no-color \
            -backend-config=bucket=clipforgebeta2-tfstate-int -backend-config=prefix=terraform/int-beta
        tf validate -no-color
        capture_previous
        trap rollback_delivery EXIT
        apply_beta false "run-$GITHUB_RUN_ID-b$GITHUB_RUN_ATTEMPT" private
        trap - EXIT
        ;;
    migrate)
        trap rollback_delivery EXIT
        CLOUDSDK_AUTH_ACCESS_TOKEN="$CLIPFORGE_GCP_DEPLOY_TOKEN" run jobs execute "$migrator" --wait
        trap - EXIT
        ;;
    acceptance-open)
        if [[ -n "${INT_DELETION_REPLAY_REPORT:-}" ]]; then
            [[ "$INT_DELETION_REPLAY_REPORT" == "$reports/deletion-replay.json" && ! -L "$INT_DELETION_REPLAY_REPORT" ]]
            jq -e '.schema == "clipforge-int-hito-b-delete-evidence-1" and .status == "passed"
                and .commit == "18924d0cafddaaa30c986e52bb4cfc3776c06059"' \
                "$INT_DELETION_REPLAY_REPORT" > /dev/null
            apply_beta true "run-$GITHUB_RUN_ID-a$GITHUB_RUN_ATTEMPT" replacement
            capture_rollout after
            browser_acceptance deletion-recheck
        else
            create_fixture
            apply_beta true "run-$GITHUB_RUN_ID-b$GITHUB_RUN_ATTEMPT" public
            capture_rollout before
            browser_acceptance prepare --video "$DELIVERY_DIR/fixture.mp4"
        fi
        ;;
    acceptance-verify)
        apply_beta true "run-$GITHUB_RUN_ID-a$GITHUB_RUN_ATTEMPT" replacement
        capture_rollout after
        browser_acceptance verify
        ;;
    capacity-setup|capacity-load|capacity-cuts|capacity-editorial|capacity-cleanup)
        load_replacement_rollout
        capacity_acceptance "${1#capacity-}"
        ;;
    rollback)
        restore_failed_delivery
        ;;
    *)
        exit 2
        ;;
esac
