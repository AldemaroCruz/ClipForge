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
public=https://clipforge-int-beta-816643438938.us-central1.run.app
private=https://clipforge-int-beta-api-816643438938.us-central1.run.app
export TF_IN_AUTOMATION=1 TF_INPUT=0
export TF_VAR_source_revision="$GITHUB_SHA"
TF_VAR_web_image="$(jq -er '.images.web.image' "$reports/candidate.json")"
TF_VAR_worker_image="$(jq -er '.images.worker.image' "$reports/candidate.json")"
export TF_VAR_web_image TF_VAR_worker_image

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
    local service="$1" revision image url="$2"
    [[ "$(run services describe "$service" --format='value(status.url)')" == "$url" ]]
    revision="$(run services describe "$service" --format='value(status.latestReadyRevisionName)')"
    [[ "$revision" =~ ^$service-[a-z0-9-]+$ ]]
    image="$(run revisions describe "$revision" --format='value(status.imageDigest)')"
    [[ "$image" == "$TF_VAR_web_image" ]]
    local active
    active="$(run services describe "$service" --format=json |
        jq -er '[.status.traffic[] | select(.percent == 100)] | select(length == 1) | .[0].revisionName')"
    [[ "$active" == "$revision" ]]
    printf '%s\n' "$revision"
}

capture_rollout() {
    local phase="$1"
    FRONTEND_REVISION="$(verify_revision "$frontend" "$public")"
    API_REVISION="$(verify_revision "$api" "$private")"
    worker_spec="$(run jobs describe clipforge-int-worker --format='value(spec.template.spec.template.spec.containers[0].image)')"
    [[ "$worker_spec" == "$TF_VAR_worker_image" ]]
    jq -n --arg commit "$GITHUB_SHA" --arg frontend "$FRONTEND_REVISION" --arg api "$API_REVISION" \
        --arg public_url "$public" --arg api_url "$private" --arg web "$TF_VAR_web_image" \
        --arg worker "$TF_VAR_worker_image" \
        '{commit:$commit,frontend_revision:$frontend,api_revision:$api,public_url:$public_url,api_url:$api_url,web_image:$web,worker_image:$worker}' \
        > "$reports/$phase-rollout.json"
}

create_fixture() {
    local speech
    speech='Este es un ejemplo real para comprobar la beta de ClipForge. Primero voy a subir mi video. Después voy a revisar varios clips. El audio se debe entender con claridad. Me interesa compartir una historia corta, con cortes que conservan la idea principal. Cuando termine puedo descargar los resultados y enviar un comentario sobre el clip.'
    espeak-ng -v es -s 148 -w "$DELIVERY_DIR/voice.wav" "$speech $speech"
    ffmpeg -hide_banner -loglevel error -nostdin \
        -f lavfi -i 'testsrc2=size=1280x720:rate=24' -i "$DELIVERY_DIR/voice.wav" -af apad \
        -t 36 -c:v libx264 -preset veryfast -pix_fmt yuv420p -threads 2 \
        -b:v 3000k -minrate 3000k -maxrate 3000k -bufsize 6000k -x264-params nal-hrd=cbr \
        -c:a aac -b:a 96k -movflags +faststart "$DELIVERY_DIR/fixture.mp4"
    [[ "$(stat -c %s "$DELIVERY_DIR/fixture.mp4")" -gt 8388608 ]]
}

browser_acceptance() {
    local phase="$1"
    shift
    env -u CLOUDSDK_AUTH_ACCESS_TOKEN -u GOOGLE_OAUTH_ACCESS_TOKEN \
        -u GOOGLE_APPLICATION_CREDENTIALS -u CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE \
        python -m scripts.int_hito_b_browser "$phase" --commit "$GITHUB_SHA" \
        --frontend-revision "$FRONTEND_REVISION" --api-revision "$API_REVISION" \
        --state "$DELIVERY_DIR/browser-private.json" --report "$reports/browser-$phase.json" "$@"
}

rollback_first_delivery() {
    local result="$?"
    if [[ "$result" -ne 0 ]]; then
        if apply_beta false "run-$GITHUB_RUN_ID-b$GITHUB_RUN_ATTEMPT" hidden; then
            printf '%s\n' 'Public access disabled after unsuccessful Hito B acceptance.' > "$reports/acceptance-failure.txt"
        else
            printf '%s\n' 'Hito B acceptance failed and disabling public access also failed.' > "$reports/acceptance-failure.txt"
        fi
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
        apply_beta false "run-$GITHUB_RUN_ID-b$GITHUB_RUN_ATTEMPT" private
        ;;
    acceptance)
        trap rollback_first_delivery EXIT
        create_fixture
        apply_beta true "run-$GITHUB_RUN_ID-b$GITHUB_RUN_ATTEMPT" public
        capture_rollout before
        browser_acceptance prepare --video "$DELIVERY_DIR/fixture.mp4"
        apply_beta true "run-$GITHUB_RUN_ID-a$GITHUB_RUN_ATTEMPT" replacement
        capture_rollout after
        browser_acceptance verify
        trap - EXIT
        ;;
    *)
        exit 2
        ;;
esac
