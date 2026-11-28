#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ "$GITHUB_WORKFLOW_REF" == 'AldemaroCruz/ClipForge/.github/workflows/int-hito-b.yml@refs/heads/ci/bootstrap-sec03' ]]
[[ "$GITHUB_SHA" == "$APPROVED_COMMIT" && "$GITHUB_SHA" =~ ^[a-f0-9]{40}$ ]]
[[ "$DELIVERY_DIR" == "$RUNNER_TEMP"/clipforge-beta-deploy.* ]]
reports="$DELIVERY_DIR/reports"
scratch="$DELIVERY_DIR/startup-e02"
mkdir "$scratch"

jq -e --arg commit "$GITHUB_SHA" 'select(.target_commit == $commit and .status == "passed") | .e01_startup' \
    "$reports/e02-baseline.json" > "$scratch/historical.json"
jq -e --arg commit "$GITHUB_SHA" 'select(.commit == $commit and .phase == "e02" and .status == "passed") | .startup_subject' \
    "$reports/browser-e02.json" > "$scratch/current.json"

access=""
if access="$(timeout 20s gcloud auth print-access-token --quiet 2>"$scratch/access.err")"; then
    [[ "$access" =~ ^[A-Za-z0-9._-]{40,4096}$ ]] || access=""
else
    access=""
fi

scope='https://run.googleapis.com/v2/projects/clipforgebeta2/locations/us-central1/jobs/clipforge-int-worker/executions'
capture_resource() {
    local url="$1" target="$2" http
    if [[ -z "$access" ]]; then
        printf 'credential_unavailable'
    elif http="$(printf 'Authorization: Bearer %s\n' "$access" |
        curl --silent --show-error --globoff --proto '=https' --connect-timeout 5 --max-time 15 --max-filesize 1048576 \
            --header @- --output "$target.tmp" --write-out '%{http_code}' "$url" 2>"$target.err")"; then
        if [[ "$http" == 200 ]] && jq -e 'type == "object"' "$target.tmp" >/dev/null; then
            mv -- "$target.tmp" "$target"
            printf 'available'
        else
            printf 'http_%s' "$http"
        fi
    else
        printf 'transport_unavailable'
    fi
}

capture_log() {
    local filter="$1" target="$2"
    if [[ -z "$filter" ]]; then
        printf 'unavailable'
    elif timeout 25s gcloud logging read "$filter" --project=clipforgebeta2 --limit=8 --freshness=7d --quiet \
      --format='json(timestamp,jsonPayload.event,jsonPayload.task_id,jsonPayload.job_id,jsonPayload.fence,jsonPayload.execution,jsonPayload.worker_started_epoch,jsonPayload.request_epoch,jsonPayload.operation)' \
      > "$target.tmp" 2> "$target.err" && jq -e 'type == "array"' "$target.tmp" >/dev/null; then
        mv -- "$target.tmp" "$target"
        printf 'available'
    elif grep -Eiq 'PERMISSION_DENIED|permission.*denied|logging[.]logEntries[.]list' "$target.err"; then
        printf 'permission_denied'
    else
        printf 'unavailable'
    fi
}

for label in historical current; do
    subject="$scratch/$label.json"
    intake="$scratch/$label"
    mkdir "$intake"
    claim_status="recorded_by_worker"
    if [[ "$label" == historical ]]; then
        claim_filter="$(python -m scripts.int_hito_e02_startup claim-filter "$subject" "$intake")"
        claim_status="$(capture_log "$claim_filter" "$intake/claims.json")"
    fi
    dispatch_filter="$(python -m scripts.int_hito_e02_startup dispatch-filter "$subject" "$intake")"
    dispatch_status="$(capture_log "$dispatch_filter" "$intake/dispatch.json")"
    execution="$(python -m scripts.int_hito_e02_startup execution "$subject" "$intake")"
    operation="$(python -m scripts.int_hito_e02_startup operation "$subject" "$intake")"
    execution_status="identity_unavailable"
    tasks_status="$execution_status"
    operation_status="$execution_status"
    if [[ -n "$execution" ]]; then
        execution_status="$(capture_resource "$scope/$execution?fields=name,job,createTime,startTime,completionTime" "$intake/execution.json")"
        tasks_status="$(capture_resource "$scope/$execution/tasks?pageSize=2&fields=tasks(name,execution,index,retried,createTime,scheduledTime,startTime,completionTime)" "$intake/tasks.json")"
    fi
    if [[ -n "$operation" ]]; then
        operation_status="$(capture_resource "https://run.googleapis.com/v2/$operation?fields=name,done,metadata(name),response(name)" "$intake/operation.json")"
    fi
    jq -n --arg claims "$claim_status" --arg dispatch "$dispatch_status" --arg execution "$execution_status" \
        --arg tasks "$tasks_status" --arg operation "$operation_status" \
        '{claim_log:$claims,dispatch_log:$dispatch,execution:$execution,tasks:$tasks,operation:$operation}' \
        > "$intake/http.json"
    python -m scripts.int_hito_e02_startup summarize "$subject" "$intake" > "$scratch/$label-summary.json"
done
unset access
jq -n --arg commit "$GITHUB_SHA" --slurpfile e01 "$scratch/historical-summary.json" \
    --slurpfile e02 "$scratch/current-summary.json" \
    '{schema:"clipforge-int-e02-worker-startup-1",commit:$commit,prior_e01:$e01[0],current_e02:$e02[0],
      scope:"UTC wall timestamps from PostgreSQL, Cloud Run and Python; signed offsets, optional provider fields; no retrospective estimate of older runs"}' \
    > "$reports/e02-worker-startup.json"
