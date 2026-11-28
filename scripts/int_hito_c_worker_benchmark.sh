# shellcheck shell=bash
# Sourced by deploy_int_beta.sh after its protected run and OCI checks.

benchmark_job=clipforge-int-worker
benchmark_baseline="$reports/worker-benchmark-baseline.json"
benchmark_fixture="$DELIVERY_DIR/worker-benchmark.mp4"

benchmark_public() {
    local commit web front_rev api_rev front_image api_image migrator_image active_revision
    commit="$(curl --silent --show-error --fail --max-time 12 "$public/environment" |
        jq -er 'select(.environment == "INT") | .revision')" || return
    [[ "$commit" == "$INT_WORKER_BENCHMARK_BASE" ]] || return
    web="$(curl --silent --show-error --fail --max-time 12 "$public/health")" || return
    jq -e '.status == "ok" and .profile == "int-beta"' <<< "$web" >/dev/null || return
    active_revision='[.status.traffic[] | select(.percent == 100)] | select(length == 1) | .[0].revisionName'
    front_rev="$(run services describe "$frontend" --format=json | jq -er "$active_revision")" || return
    api_rev="$(run services describe "$api" --format=json | jq -er "$active_revision")" || return
    [[ "$front_rev" =~ ^clipforge-int-beta-[0-9]+-[a-z0-9]+$ &&
       "$api_rev" =~ ^clipforge-int-beta-api-[0-9]+-[a-z0-9]+$ ]] || return
    front_image="$(run revisions describe "$front_rev" --format='value(status.imageDigest)')" || return
    api_image="$(run revisions describe "$api_rev" --format='value(status.imageDigest)')" || return
    migrator_image="$(run jobs describe "$migrator" --format='value(spec.template.spec.template.spec.containers[0].image)')" || return
    [[ "$front_image" =~ ^us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/beta-web@sha256:[a-f0-9]{64}$ &&
       "$front_image" == "$api_image" && "$front_image" == "$migrator_image" ]] || return
    jq -ncS --arg commit "$commit" --arg front "$front_rev" --arg api "$api_rev" --arg image "$front_image" \
        '{commit:$commit,frontend_revision:$front,api_revision:$api,web_image:$image,migrator_image:$image}'
}

benchmark_worker() {
    local snapshot invariant
    snapshot="$(run jobs describe "$benchmark_job" --format='json(metadata.generation,status.observedGeneration,spec.template.spec)')" || return
    invariant="$(jq -ecS '
        .spec.template.spec | select(.template.spec.containers | length == 1) |
        .template.spec.containers[0] |=
          (del(.image, .resources.limits.cpu) | .env |= (map(select(.name != "CLIPFORGE_REVISION")) | sort_by(.name)))
    ' <<< "$snapshot" | sha256sum | cut -d ' ' -f 1)" || return
    jq -ecS --arg invariant "$invariant" '
        . as $job | .spec.template.spec as $spec | $spec.template.spec.containers[0] as $container |
        {generation: ($job.metadata.generation | tonumber), observed_generation: ($job.status.observedGeneration | tonumber),
         image: $container.image,
         source: ([$container.env[] | select(.name == "CLIPFORGE_REVISION")] | select(length == 1) | .[0].value),
         cpu: $container.resources.limits.cpu, memory: $container.resources.limits.memory,
         task_count: ($spec.taskCount // 1), parallelism: ($spec.parallelism // 1),
         timeout_seconds: ($spec.template.spec.timeoutSeconds | tonumber),
         configuration_sha256: $invariant} |
        select(.generation == .observed_generation and .memory == "4Gi"
            and .task_count == 1 and .parallelism == 1 and .timeout_seconds == 1200
            and (.cpu == "2" or .cpu == "4") and (.source | test("^[a-f0-9]{40}$"))
            and (.image | test("^us-central1-docker\\.pkg\\.dev/clipforgebeta2/clipforge-int/beta-worker@sha256:[a-f0-9]{64}$")))
    ' <<< "$snapshot"
}

benchmark_read_baseline() {
    [[ -f "$benchmark_baseline" && ! -L "$benchmark_baseline" ]] || return
    jq -e --arg source "$INT_WORKER_BENCHMARK_BASE" --arg target "$GITHUB_SHA" --arg worker "$TF_VAR_worker_image" '
        .schema == "clipforge-int-worker-benchmark-1" and .public.commit == $source
        and .target_commit == $target and .target_worker == $worker and .worker.source == $source
        and .worker.cpu == "2" and .worker.memory == "4Gi"
        and (.worker.image | test("^us-central1-docker\\.pkg\\.dev/clipforgebeta2/clipforge-int/beta-worker@sha256:[a-f0-9]{64}$"))
        and (.fixture.sha256 | test("^[a-f0-9]{64}$"))
    ' "$benchmark_baseline" >/dev/null
}

benchmark_verify_public() {
    local observed
    observed="$(benchmark_public)" || return
    jq -e --argjson actual "$observed" '.public == $actual' "$benchmark_baseline" >/dev/null
}

benchmark_browser() {
    local phase="$1" cpus="$2" sha front_rev api_rev state report
    local -a prior=()
    sha="$(jq -er '.fixture.sha256' "$benchmark_baseline")"
    front_rev="$(jq -er '.public.frontend_revision' "$benchmark_baseline")"
    api_rev="$(jq -er '.public.api_revision' "$benchmark_baseline")"
    state="$DELIVERY_DIR/worker-benchmark-cpu$cpus-private.json"
    report="$reports/worker-benchmark-cpu$cpus-$phase.json"
    if [[ "$phase" == benchmark ]]; then
        prior=(--prior-report "$reports/worker-benchmark-cpu$cpus-setup.json")
    fi
    env -u CLOUDSDK_AUTH_ACCESS_TOKEN -u GOOGLE_OAUTH_ACCESS_TOKEN \
        -u GOOGLE_APPLICATION_CREDENTIALS -u CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE \
        python -m scripts.int_hito_b_capacity_browser --commit "$INT_WORKER_BENCHMARK_BASE" \
        --frontend-revision "$front_rev" --api-revision "$api_rev" --fixture-dir "$DELIVERY_DIR" \
        --large-fixture "$benchmark_fixture" --phase "$phase" --case-timeout 780 \
        --benchmark-cpus "$cpus" --benchmark-sha256 "$sha" --state "$state" --report "$report" "${prior[@]}"
}

benchmark_prepare() {
    local active worker sha bytes
    [[ ! -e "$benchmark_baseline" && ! -e "$benchmark_fixture" ]]
    active="$(benchmark_public)"
    worker="$(benchmark_worker)"
    jq -e --arg source "$INT_WORKER_BENCHMARK_BASE" '.cpu == "2" and .source == $source' <<< "$worker" >/dev/null
    create_voice_fixture
    ffmpeg -hide_banner -loglevel error -nostdin \
        -f lavfi -i 'testsrc2=size=1280x720:rate=24,noise=alls=12:allf=t+u:all_seed=613' \
        -stream_loop -1 -i "$DELIVERY_DIR/voice.wav" -t 600 \
        -c:v libx264 -preset ultrafast -pix_fmt yuv420p -threads 2 \
        -b:v 2600k -maxrate 3200k -bufsize 5200k -c:a aac -b:a 96k -movflags +faststart "$benchmark_fixture"
    sha="$(sha256sum "$benchmark_fixture" | cut -d ' ' -f 1)"
    bytes="$(stat -c %s "$benchmark_fixture")"
    (( bytes >= 8388608 && bytes <= 314572800 ))
    jq -n --argjson active "$active" --argjson worker "$worker" --arg target "$GITHUB_SHA" \
        --arg image "$TF_VAR_worker_image" --arg sha "$sha" --argjson bytes "$bytes" \
        '{schema:"clipforge-int-worker-benchmark-1",public:$active,worker:$worker,target_commit:$target,
          target_worker:$image,fixture:{sha256:$sha,bytes:$bytes,duration_seconds:600}}' > "$benchmark_baseline"
}

benchmark_setup() {
    local cpus="$1"
    [[ "$cpus" == "2" || "$cpus" == "4" ]]
    benchmark_read_baseline
    benchmark_verify_public
    benchmark_browser setup "$cpus"
}

benchmark_run() {
    local cpus="$1" current configured after
    [[ "$cpus" == "2" || "$cpus" == "4" ]]
    benchmark_read_baseline
    benchmark_verify_public
    [[ -f "$benchmark_fixture" && ! -L "$benchmark_fixture" ]]
    [[ "$(sha256sum "$benchmark_fixture" | cut -d ' ' -f 1)" == "$(jq -er '.fixture.sha256' "$benchmark_baseline")" ]]
    current="$(benchmark_worker)"
    if [[ "$cpus" == "2" ]]; then
        jq -e --argjson current "$current" '.worker == $current' "$benchmark_baseline" >/dev/null
    else
        jq -e '.status == "passed" and .benchmark.cpu == 2' \
            "$reports/worker-benchmark-cpu2-benchmark.json" >/dev/null
        jq -e --argjson current "$current" '. == $current' "$reports/worker-benchmark-cpu2-after.json" >/dev/null
    fi
    run jobs update "$benchmark_job" --image "$TF_VAR_worker_image" --cpu "$cpus" --memory 4Gi \
        --update-env-vars "CLIPFORGE_REVISION=$GITHUB_SHA"
    configured="$(benchmark_worker)"
    jq -e --argjson current "$current" --argjson configured "$configured" --arg cpu "$cpus" \
        --arg image "$TF_VAR_worker_image" --arg commit "$GITHUB_SHA" '
        $configured.cpu == $cpu and $configured.image == $image and $configured.source == $commit and
        $configured.generation > $current.generation and
        .worker.configuration_sha256 == $configured.configuration_sha256
    ' "$benchmark_baseline" >/dev/null
    printf '%s\n' "$configured" > "$reports/worker-benchmark-cpu$cpus-before.json"
    benchmark_browser benchmark "$cpus"
    after="$(benchmark_worker)"
    [[ "$after" == "$configured" ]]
    benchmark_verify_public
    printf '%s\n' "$after" > "$reports/worker-benchmark-cpu$cpus-after.json"
}

benchmark_restore() {
    local current restored image source
    [[ -e "$benchmark_baseline" ]] || return 0
    benchmark_read_baseline || return
    current="$(benchmark_worker)" || return
    jq -e --argjson current "$current" \
        '.worker.configuration_sha256 == $current.configuration_sha256' "$benchmark_baseline" >/dev/null || return
    image="$(jq -er '.worker.image' "$benchmark_baseline")" || return
    source="$(jq -er '.worker.source' "$benchmark_baseline")" || return
    if ! jq -e --arg image "$image" --arg source "$source" '.image == $image and .source == $source and .cpu == "2"' \
            <<< "$current" >/dev/null; then
        jq -e --arg image "$TF_VAR_worker_image" --arg source "$GITHUB_SHA" '.image == $image and .source == $source' \
            <<< "$current" >/dev/null || return
        run jobs update "$benchmark_job" --image "$image" --cpu 2 --memory 4Gi \
            --update-env-vars "CLIPFORGE_REVISION=$source" || return
    fi
    restored="$(benchmark_worker)" || return
    jq -e --argjson current "$current" --argjson restored "$restored" '
        def settings: del(.generation, .observed_generation);
        (.worker | settings) == ($restored | settings) and
        (if ($current | settings) == (.worker | settings)
         then $restored.generation == $current.generation
         else $restored.generation > $current.generation end)
    ' "$benchmark_baseline" >/dev/null || return
    benchmark_verify_public || return
    jq -n --argjson before "$current" --argjson worker "$restored" --arg utc "$(date -u +%FT%TZ)" \
        '{status:"passed",observed_before_restore:$before,worker:$worker,observed_utc:$utc}' \
        > "$reports/worker-benchmark-restored.json"
}

benchmark_cleanup() {
    local cpus result=0
    [[ -e "$benchmark_baseline" ]] || return 0
    benchmark_read_baseline || return
    for cpus in 2 4; do
        if [[ -f "$DELIVERY_DIR/worker-benchmark-cpu$cpus-private.json" ]]; then
            benchmark_browser cleanup "$cpus" || result=1
        fi
    done
    return "$result"
}

run_worker_benchmark() {
    [[ "${INT_WORKER_BENCHMARK_BASE:-}" =~ ^[a-f0-9]{40}$ &&
       "$INT_WORKER_BENCHMARK_BASE" != "$GITHUB_SHA" ]]
    case "$1" in
        benchmark-prepare) benchmark_prepare ;;
        benchmark-setup) benchmark_setup "$2" ;;
        benchmark-run) benchmark_run "$2" ;;
        benchmark-restore) benchmark_restore ;;
        benchmark-cleanup) benchmark_cleanup ;;
        *) return 2 ;;
    esac
}
