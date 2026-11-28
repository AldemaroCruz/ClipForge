#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit
umask 077

[[ "$GITHUB_WORKFLOW_REF" == 'AldemaroCruz/ClipForge/.github/workflows/int-hito-b.yml@refs/heads/ci/bootstrap-sec03' ]]
[[ "$GITHUB_SHA" =~ ^[a-f0-9]{40}$ && "$GITHUB_SHA" == "$APPROVED_COMMIT" ]]
[[ "$DELIVERY_DIR" == "$RUNNER_TEMP"/clipforge-beta-deploy.* && -d "$DELIVERY_DIR" ]]
[[ "${INT_ADOPT_WORKER_PROFILE:-false}" != true ]]

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
    local phase="$1" worker_spec worker_configuration worker_editorial api_daily_limit migrator_image
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
    if [[ -n "$editorial_model" ]]; then
        api_daily_limit="$(run revisions describe "$API_REVISION" --format='json(spec.containers)' |
            jq -er '.spec.containers[0].env[] | select(.name == "CLIPFORGE_AI_DAILY_LIMIT") | .value | tonumber')"
        [[ "$api_daily_limit" == 100 ]]
        jq -e --arg model "$editorial_model" '.provider == "openai" and .model == $model and .daily_limit == 100' \
            <<< "$worker_editorial" > /dev/null
        worker_editorial="$(jq -c --argjson limit "$api_daily_limit" '. + {api_daily_limit: $limit}' <<< "$worker_editorial")"
    fi
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
            daily_limit: ((val("CLIPFORGE_AI_DAILY_LIMIT") // "10") | tonumber),
            key_version: (map(select(.name == "OPENAI_API_KEY")) | .[0].valueFrom.secretKeyRef.key // "")
        } |
        select(.provider == "disabled" or (.provider == "openai" and
            (.model | test("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$")) and
            (.daily_limit >= 1 and .daily_limit <= 100 and .daily_limit == (.daily_limit | floor)) and
            (.key_version | test("^[1-9][0-9]{0,9}$")) and (.timeout | test("^[0-9]{2,3}$"))))
        '
}

capture_previous() {
    local version front previous_api worker_spec worker worker_editorial migrator_image recovery_worker migrator_source
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
    recovery_worker="$(jq -ec '.spec.template.spec.template.spec.containers[0] | {
        worker_source: ([.env[] | select(.name == "CLIPFORGE_REVISION")][0].value | select(test("^[a-f0-9]{40}$"))),
        worker_cpu: (.resources.limits.cpu | select(. == "2" or . == "4")),
        worker_memory: (.resources.limits.memory | select(. == "4Gi"))
    }' <<< "$worker_spec")"
    migrator_image="$(run jobs describe "$migrator" --format='value(spec.template.spec.template.spec.containers[0].image)')"
    migrator_source="$(run jobs describe "$migrator" --format='json(spec.template.spec.template.spec.containers)' |
        jq -er '.spec.template.spec.template.spec.containers[0].env[] | select(.name == "CLIPFORGE_REVISION") |
                .value | select(test("^[a-f0-9]{40}$"))')"
    [[ "$front" =~ ^clipforge-int-beta-[0-9][0-9a-z-]+$ &&
       "$previous_api" =~ ^clipforge-int-beta-api-[0-9][0-9a-z-]+$ &&
       "$migrator_image" =~ ^us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/beta-web@sha256:[a-f0-9]{64}$ &&
       "$worker" =~ ^us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/beta-worker@sha256:[a-f0-9]{64}$ ]]
    jq -n --arg commit "$version" --arg frontend "$front" --arg api "$previous_api" --arg worker "$worker" \
        --arg migrator "$migrator_image" --arg migrator_source "$migrator_source" \
        --argjson editorial "$worker_editorial" --argjson worker_settings "$recovery_worker" \
        '{commit:$commit,frontend_revision:$frontend,api_revision:$api,worker_image:$worker,
          migrator_image:$migrator,migrator_source:$migrator_source,editorial:$editorial} + $worker_settings' \
        > "$reports/previous-live.json"
}

restore_previous() {
    local previous="$reports/previous-live.json" version front previous_api worker provider model key_version timeout daily_limit migrator_image
    local keep_public="${1:-false}"
    local worker_source worker_cpu worker_memory migrator_source
    local -a editorial_options
    version="$(jq -er '.commit' "$previous")" || return
    front="$(jq -er '.frontend_revision' "$previous")" || return
    previous_api="$(jq -er '.api_revision' "$previous")" || return
    worker="$(jq -er '.worker_image' "$previous")" || return
    worker_source="$(jq -er '.worker_source' "$previous")" || return
    worker_cpu="$(jq -er '.worker_cpu' "$previous")" || return
    worker_memory="$(jq -er '.worker_memory' "$previous")" || return
    migrator_image="$(jq -er '.migrator_image' "$previous")" || return
    migrator_source="$(jq -er '.migrator_source' "$previous")" || return
    provider="$(jq -er '.editorial.provider' "$previous")" || return
    if [[ "$provider" == openai ]]; then
        model="$(jq -er '.editorial.model' "$previous")" || return
        key_version="$(jq -er '.editorial.key_version' "$previous")" || return
        timeout="$(jq -er '.editorial.timeout' "$previous")" || return
        daily_limit="$(jq -er '.editorial.daily_limit' "$previous")" || return
        editorial_options=(
            --update-env-vars "CLIPFORGE_REVISION=$worker_source,CLIPFORGE_AI_PROVIDER=openai,CLIPFORGE_AI_MODEL=$model,CLIPFORGE_AI_CONFIG_REVISION=$key_version,CLIPFORGE_AI_TIMEOUT_SECONDS=$timeout,CLIPFORGE_AI_DAILY_LIMIT=$daily_limit"
            --update-secrets "OPENAI_API_KEY=clipforge-int-openai-key:$key_version"
        )
    else
        editorial_options=(
            --update-env-vars "CLIPFORGE_REVISION=$worker_source,CLIPFORGE_AI_PROVIDER=disabled"
            --remove-env-vars CLIPFORGE_AI_MODEL,CLIPFORGE_AI_CONFIG_REVISION,CLIPFORGE_AI_TIMEOUT_SECONDS,CLIPFORGE_AI_DAILY_LIMIT
            --remove-secrets OPENAI_API_KEY
        )
    fi
    if [[ "$keep_public" == false ]]; then
        run services update "$frontend" --invoker-iam-check || return
    fi
    run jobs update clipforge-int-worker --image "$worker" --cpu "$worker_cpu" --memory "$worker_memory" "${editorial_options[@]}" || return
    run services update-traffic "$api" --to-revisions "$previous_api=100" || return
    run services update-traffic "$frontend" --to-revisions "$front=100" || return
    run jobs update "$migrator" --image "$migrator_image" --update-env-vars "CLIPFORGE_REVISION=$migrator_source" || return
    if [[ "$keep_public" == false ]]; then
        run services update "$frontend" --no-invoker-iam-check || return
    fi
    curl --silent --fail --max-time 15 --retry 3 "$public/health" | jq -e '.status == "ok"' >/dev/null || return
    curl --silent --fail --max-time 15 "$public/environment" |
        jq -e --arg version "$version" '.revision == $version' >/dev/null
}

create_voice_fixture() {
    local speech
    speech='En Guatemala los vecinos recuperaron un huerto comunitario. Empezaron guardando semillas de maíz de varios colores. Luego compartieron turnos para regar y aprender de la cosecha. Un año después, el grupo enseñó a otras escuelas a conservar semillas y a cultivar en espacios pequeños. La lección es clara: cuidar la tierra funciona mejor cuando todos comparten lo que aprenden.'
    espeak-ng -v es -s 148 -w "$DELIVERY_DIR/voice.wav" "$speech $speech"
}

create_fixture() {
    create_voice_fixture
    ffmpeg -hide_banner -loglevel error -nostdin \
        -f lavfi -i 'testsrc2=size=1280x720:rate=24' -stream_loop -1 -i "$DELIVERY_DIR/voice.wav" \
        -t 120 -c:v libx264 -preset veryfast -pix_fmt yuv420p -threads 2 \
        -b:v 3000k -minrate 3000k -maxrate 3000k -bufsize 6000k -x264-params nal-hrd=cbr \
        -c:a aac -b:a 96k -movflags +faststart "$DELIVERY_DIR/fixture.mp4"
    [[ "$(stat -c %s "$DELIVERY_DIR/fixture.mp4")" -gt 8388608 ]]
}

create_framing_fixture() {
    local colors
    create_voice_fixture
    colors="color=black:s=1280x720:r=24,drawbox=x=0:y=0:w=420:h=360:c=red:t=fill"
    colors+=",drawbox=x=420:y=0:w=440:h=360:c=green:t=fill,drawbox=x=860:y=0:w=420:h=360:c=blue:t=fill"
    colors+=",drawbox=x=0:y=360:w=420:h=360:c=yellow:t=fill,drawbox=x=420:y=360:w=440:h=360:c=magenta:t=fill"
    colors+=",drawbox=x=860:y=360:w=420:h=360:c=cyan:t=fill"
    ffmpeg -hide_banner -loglevel error -nostdin \
        -f lavfi -i "$colors" -stream_loop -1 -i "$DELIVERY_DIR/voice.wav" \
        -t 120 -c:v libx264 -preset veryfast -pix_fmt yuv420p -threads 2 \
        -b:v 2800k -minrate 2800k -maxrate 2800k -bufsize 5600k -x264-params nal-hrd=cbr \
        -c:a aac -b:a 96k -movflags +faststart "$DELIVERY_DIR/framing.mp4"
}

create_zip_fixture() {
    create_voice_fixture
    ffmpeg -hide_banner -loglevel error -nostdin \
        -f lavfi -i 'testsrc2=size=720x1280:rate=24,noise=alls=38:allf=t+u:all_seed=613' \
        -stream_loop -1 -i "$DELIVERY_DIR/voice.wav" -t 240 \
        -c:v libx264 -preset ultrafast -pix_fmt yuv420p -threads 4 \
        -b:v 4500k -maxrate 5600k -bufsize 11200k -c:a aac -b:a 96k -movflags +faststart "$DELIVERY_DIR/archive.mp4"
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
        python -m scripts.int_hito_b_browser "$phase" --commit "${BROWSER_EXPECTED_COMMIT:-$GITHUB_SHA}" \
        --frontend-revision "${BROWSER_EXPECTED_FRONTEND:-$FRONTEND_REVISION}" \
        --api-revision "${BROWSER_EXPECTED_API:-$API_REVISION}" \
        --editorial-model "$editorial_model" --state "$DELIVERY_DIR/browser-private.json" \
        --report "$reports/browser-$phase.json" "$@"
}

browser_on_rollout() {
    local receipt="$1"
    shift
    BROWSER_EXPECTED_COMMIT="$(jq -er '.commit' "$receipt")" \
    BROWSER_EXPECTED_FRONTEND="$(jq -er '.frontend_revision' "$receipt")" \
    BROWSER_EXPECTED_API="$(jq -er '.api_revision' "$receipt")" browser_acceptance "$@"
}

create_d01_fixture() {
    local row words offset duration speech wav filter inputs index
    local -a rows media
    mapfile -t rows < <(python -m app.topic_fixture | jq -c '.[]')
    [[ "${#rows[@]}" -eq 9 ]]
    media=(-f lavfi -i 'color=c=0x223448:s=640x360:r=24' -f lavfi -i 'anullsrc=r=22050:cl=mono')
    filter="[1:a]atrim=duration=1200[base];"
    inputs="[base]"
    index=2
    for row in "${rows[@]}"; do
        words="$(jq -er '.text' <<< "$row")"
        offset="$(jq -er '.start*1000|round' <<< "$row")"
        duration="$(jq -er '.end-.start' <<< "$row")"
        wav="$DELIVERY_DIR/topic-$index.wav"
        printf '%s\n' "$words" | espeak-ng --stdin -v es -s 155 -w "$wav"
        speech="$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$wav")"
        jq -ne --argjson speech "$speech" --argjson duration "$duration" \
            '$speech > 0 and $speech <= $duration' >/dev/null
        media+=(-i "$wav")
        filter+="[$index:a]aformat=sample_rates=22050:channel_layouts=mono,adelay=$offset[voice$index];"
        inputs+="[voice$index]"
        index=$((index + 1))
    done
    filter+="$inputs""amix=inputs=$((index - 1)):duration=first:normalize=0[audio]"
    ffmpeg -hide_banner -loglevel error -nostdin "${media[@]}" -filter_complex "$filter" \
        -map 0:v:0 -map '[audio]' -t 1200 -c:v libx264 -preset ultrafast -crf 26 \
        -pix_fmt yuv420p -threads 2 -c:a aac -b:a 48k -movflags +faststart "$DELIVERY_DIR/topic.mp4"
}

prepare_caption_fixture() {
    local phase="${1:-caption-color-prepare}" previous="$reports/previous-live.json"
    local state="$DELIVERY_DIR/browser-private.json" owner job source_sha video flag=""
    if [[ "$phase" == d01-prepare ]]; then
        create_d01_fixture
        video="$DELIVERY_DIR/topic.mp4"
        flag=",--topic"
    else
        create_framing_fixture
        video="$DELIVERY_DIR/framing.mp4"
    fi
    browser_on_rollout "$previous" "$phase" --video "$video"
    owner="$(jq -er '.owner_id | select(test("^[a-f0-9]{32}$"))' "$state")"
    job="$(jq -er '.job_id | select(test("^[a-f0-9]{32}$"))' "$state")"
    source_sha="$(sha256sum "$video" | cut -d ' ' -f 1)"
    [[ "$source_sha" =~ ^[a-f0-9]{64}$ ]]
    : > "$DELIVERY_DIR/focused-promoting"
    # The accepted HTTP revisions keep serving the same tenant-isolated API.
    # The new image adds the private seed command to the existing worker.
    run jobs update clipforge-int-worker --image "$TF_VAR_worker_image" \
        --update-env-vars "CLIPFORGE_REVISION=$GITHUB_SHA"
    run jobs execute clipforge-int-worker --wait --tasks=1 \
        --args="-m,app.cloud.caption_color_fixture,$owner,$job,$source_sha$flag"
}

caption_color_acceptance() {
    verify_focused_baseline caption-color "$INT_CAPTION_COLOR_ACCEPTANCE"
    prepare_caption_fixture
    browser_on_rollout "$reports/previous-live.json" caption-color-baseline
    apply_beta true "run-$GITHUB_RUN_ID-a$GITHUB_RUN_ATTEMPT" replacement
    capture_rollout after
    browser_acceptance caption-color
}

mixed_zip_acceptance() {
    verify_focused_baseline mixed-zip "$INT_MIXED_ZIP_ACCEPTANCE"
    prepare_caption_fixture
    apply_beta true "run-$GITHUB_RUN_ID-a$GITHUB_RUN_ATTEMPT" replacement
    capture_rollout after
    browser_acceptance mixed-zip
}

d01_acceptance() {
    verify_focused_baseline d01 "$INT_D01_ACCEPTANCE"
    prepare_caption_fixture d01-prepare
    apply_beta true "run-$GITHUB_RUN_ID-a$GITHUB_RUN_ATTEMPT" replacement
    capture_rollout after
    jq -e '.worker_configuration.cpu == "4" and .worker_configuration.memory == "4Gi" and
        .editorial.daily_limit == 100 and .editorial.api_daily_limit == 100' \
        "$reports/after-rollout.json" > /dev/null
    browser_acceptance d01
}

caption_color_cleanup() {
    local phase="${1:-caption-color-cleanup}" state="$DELIVERY_DIR/browser-private.json" revision receipt
    if [[ ! -f "$state" ]]; then
        return 0
    fi
    revision="$(curl --silent --fail --max-time 15 "$public/environment" | jq -er '.revision')"
    receipt="$reports/previous-live.json"
    if [[ "$revision" == "$GITHUB_SHA" ]]; then
        receipt="$reports/after-rollout.json"
    fi
    [[ "$(jq -er '.commit' "$receipt")" == "$revision" ]]
    browser_on_rollout "$receipt" "$phase"
}

verify_focused_baseline() {
    local increment="$1" receipt="$2"
    case "$increment" in
        c04|c05|c06|logos|caption-color|mixed-zip|d01) ;;
        *) return 1 ;;
    esac
    [[ "$receipt" == "$reports/$increment-baseline.json" && -f "$receipt" && ! -L "$receipt" ]]
    jq -e --arg schema "clipforge-int-$increment-baseline-1" --arg increment "$increment" --arg commit "$GITHUB_SHA" \
        --slurpfile previous "$reports/previous-live.json" '
        .schema == $schema and .status == "passed" and .target_commit == $commit and
        (.baseline as $expected | $previous[0] as $live |
        ($expected | {
            commit, frontend_revision, api_revision, worker_image, migrator_image,
            editorial: (.editorial | del(.api_daily_limit))
        }) == ($live | {commit,frontend_revision,api_revision,worker_image,migrator_image,editorial}) and
        (($increment != "logos" and $increment != "caption-color" and $increment != "mixed-zip" and $increment != "d01") or
           (($expected | {worker_source,worker_cpu,worker_memory}) == ($live | {worker_source,worker_cpu,worker_memory})
            and $live.migrator_source == $expected.commit)))
    ' "$receipt" > /dev/null
}

restore_migrator_pin() {
    local image current
    image="$(jq -er '.migrator_image' "$reports/previous-live.json")" || return
    [[ "$image" =~ ^us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/beta-web@sha256:[a-f0-9]{64}$ ]] || return
    current="$(run jobs describe "$migrator" --format='value(spec.template.spec.template.spec.containers[0].image)')" || return
    if [[ "$image" != "$current" ]]; then
        run jobs update "$migrator" --image "$image"
    fi
}

run_migration() {
    CLOUDSDK_AUTH_ACCESS_TOKEN="$CLIPFORGE_GCP_DEPLOY_TOKEN" run jobs execute "$migrator" --wait
}

restore_failed_delivery() {
    local keep_public=false
    if [[ -f "$DELIVERY_DIR/focused-promoting" ]]; then
        keep_public=true
    fi
    if [[ -f "$reports/previous-live.json" ]] && restore_previous "$keep_public"; then
        printf '%s\n' 'The last healthy public beta revisions, worker and migrator pin were restored.' > "$reports/acceptance-failure.txt"
    elif [[ "$keep_public" == true ]]; then
        printf '%s\n' 'Automatic restoration was incomplete. Public access remains enabled.' > "$reports/acceptance-failure.txt"
        return 1
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

if [[ -n "${INT_WORKER_BENCHMARK_BASE:-}" ]]; then
    case "${1:-}" in
        publish|benchmark-prepare|benchmark-setup|benchmark-run|benchmark-restore|benchmark-cleanup) ;;
        *) exit 2 ;;
    esac
fi

case "${1:-}" in
    publish)
        publish_beta
        ;;
    prepare)
        if [[ -e config/int-worker-profile.json ]]; then
            expected_cpu="$(jq -er '.worker_cpu | select(. == 2 or . == 4)' config/int-worker-profile.json)"
            active_cpu="$(run jobs describe clipforge-int-worker --format='value(spec.template.spec.template.spec.containers[0].resources.limits.cpu)')"
            if [[ "$active_cpu" != "$expected_cpu" ]]; then
                printf '%s\n' 'The worker profile must be adopted before a regular INT rollout.' >&2
                exit 1
            fi
        fi
        tf init -input=false -lockfile=readonly -no-color \
            -backend-config=bucket=clipforgebeta2-tfstate-int -backend-config=prefix=terraform/int-beta
        tf validate -no-color
        capture_previous
        if [[ -n "${INT_C04_ACCEPTANCE:-}${INT_CREATOR_LOGOS_ACCEPTANCE:-}" ]]; then
            if [[ -n "${INT_CREATOR_LOGOS_ACCEPTANCE:-}" ]]; then
                verify_focused_baseline logos "$INT_CREATOR_LOGOS_ACCEPTANCE"
            else
                verify_focused_baseline c04 "$INT_C04_ACCEPTANCE"
            fi
            # The additive migration can run while the accepted API and public frontend still serve traffic.
            if ! run jobs update "$migrator" --image "$TF_VAR_web_image"; then
                restore_migrator_pin
                exit 1
            fi
        elif [[ -n "${INT_C05_ACCEPTANCE:-}" ]]; then
            verify_focused_baseline c05 "$INT_C05_ACCEPTANCE"
        elif [[ -n "${INT_C06_ACCEPTANCE:-}" ]]; then
            verify_focused_baseline c06 "$INT_C06_ACCEPTANCE"
        elif [[ -n "${INT_CAPTION_COLOR_ACCEPTANCE:-}" ]]; then
            verify_focused_baseline caption-color "$INT_CAPTION_COLOR_ACCEPTANCE"
        elif [[ -n "${INT_MIXED_ZIP_ACCEPTANCE:-}" ]]; then
            verify_focused_baseline mixed-zip "$INT_MIXED_ZIP_ACCEPTANCE"
        elif [[ -n "${INT_D01_ACCEPTANCE:-}" ]]; then
            verify_focused_baseline d01 "$INT_D01_ACCEPTANCE"
            run jobs describe clipforge-int-worker --format='json(metadata.generation,status.observedGeneration,spec.template.spec)' |
                jq -e --slurpfile prior "$reports/previous-live.json" '
                    .spec.template.spec.template.spec.containers[0] as $container |
                    select((.metadata.generation | tonumber) == (.status.observedGeneration | tonumber) and
                       $container.image == $prior[0].worker_image and
                       $container.resources.limits.cpu == "4" and $container.resources.limits.memory == "4Gi") |
                    {generation: (.metadata.generation | tonumber),
                     observed_generation: (.status.observedGeneration | tonumber),
                     image:$container.image, cpu:$container.resources.limits.cpu,memory:$container.resources.limits.memory,
                     task_count:(.spec.template.spec.taskCount // 1),
                     parallelism:(.spec.template.spec.parallelism // 1),
                     timeout_seconds: (.spec.template.spec.template.spec.timeoutSeconds | tonumber),
                     max_retries: .spec.template.spec.template.spec.maxRetries,
                     editorial: $prior[0].editorial}
                ' > "$reports/d01-prior-worker.json"
        else
            trap rollback_delivery EXIT
            apply_beta false "run-$GITHUB_RUN_ID-b$GITHUB_RUN_ATTEMPT" private
            trap - EXIT
        fi
        ;;
    migrate)
        if [[ -n "${INT_C04_ACCEPTANCE:-}${INT_CREATOR_LOGOS_ACCEPTANCE:-}" ]]; then
            if ! run_migration; then
                restore_migrator_pin
                exit 1
            fi
        else
            trap rollback_delivery EXIT
            run_migration
            trap - EXIT
        fi
        ;;
    acceptance-open)
        if [[ -n "${INT_C04_ACCEPTANCE:-}" ]]; then
            verify_focused_baseline c04 "$INT_C04_ACCEPTANCE"
            create_fixture
            : > "$DELIVERY_DIR/focused-promoting"
            apply_beta true "run-$GITHUB_RUN_ID-a$GITHUB_RUN_ATTEMPT" replacement
            capture_rollout after
            browser_acceptance styles --video "$DELIVERY_DIR/fixture.mp4"
        elif [[ -n "${INT_C05_ACCEPTANCE:-}" ]]; then
            verify_focused_baseline c05 "$INT_C05_ACCEPTANCE"
            create_framing_fixture
            : > "$DELIVERY_DIR/focused-promoting"
            apply_beta true "run-$GITHUB_RUN_ID-a$GITHUB_RUN_ATTEMPT" replacement
            capture_rollout after
            browser_acceptance framing --video "$DELIVERY_DIR/framing.mp4"
        elif [[ -n "${INT_C06_ACCEPTANCE:-}" ]]; then
            verify_focused_baseline c06 "$INT_C06_ACCEPTANCE"
            create_zip_fixture
            : > "$DELIVERY_DIR/focused-promoting"
            apply_beta true "run-$GITHUB_RUN_ID-a$GITHUB_RUN_ATTEMPT" replacement
            capture_rollout after
            browser_acceptance zip --video "$DELIVERY_DIR/archive.mp4"
        elif [[ -n "${INT_CREATOR_LOGOS_ACCEPTANCE:-}" ]]; then
            verify_focused_baseline logos "$INT_CREATOR_LOGOS_ACCEPTANCE"
            create_framing_fixture
            : > "$DELIVERY_DIR/focused-promoting"
            apply_beta true "run-$GITHUB_RUN_ID-a$GITHUB_RUN_ATTEMPT" replacement
            capture_rollout after
            browser_acceptance logos --video "$DELIVERY_DIR/framing.mp4"
        elif [[ -n "${INT_CAPTION_COLOR_ACCEPTANCE:-}" ]]; then
            caption_color_acceptance
        elif [[ -n "${INT_MIXED_ZIP_ACCEPTANCE:-}" ]]; then
            mixed_zip_acceptance
        elif [[ -n "${INT_D01_ACCEPTANCE:-}" ]]; then
            d01_acceptance
        elif [[ -n "${INT_DELETION_REPLAY_REPORT:-}" ]]; then
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
    benchmark-prepare|benchmark-setup|benchmark-run|benchmark-restore|benchmark-cleanup)
        source scripts/int_hito_c_worker_benchmark.sh
        run_worker_benchmark "$@"
        ;;
    rollback)
        if [[ -n "${INT_C04_ACCEPTANCE:-}${INT_C05_ACCEPTANCE:-}${INT_C06_ACCEPTANCE:-}${INT_CREATOR_LOGOS_ACCEPTANCE:-}${INT_CAPTION_COLOR_ACCEPTANCE:-}${INT_MIXED_ZIP_ACCEPTANCE:-}${INT_D01_ACCEPTANCE:-}" && ! -f "$DELIVERY_DIR/focused-promoting" ]]; then
            restore_migrator_pin
        else
            restore_failed_delivery
        fi
        ;;
    caption-color-cleanup)
        [[ -n "${INT_CAPTION_COLOR_ACCEPTANCE:-}${INT_MIXED_ZIP_ACCEPTANCE:-}" ]]
        caption_color_cleanup
        ;;
    d01-cleanup)
        [[ -n "${INT_D01_ACCEPTANCE:-}" ]]
        caption_color_cleanup d01-cleanup
        ;;
    *)
        exit 2
        ;;
esac
