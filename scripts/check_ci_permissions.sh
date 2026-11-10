#!/usr/bin/env bash
# Host-side checks over exclusive CI scratch; no application or scanner execution.
set -euo pipefail
umask 077

if [[ $# != 3 ]]; then
  echo 'Usage: check_ci_permissions.sh IMAGE LABEL trivy|gitleaks|ci|browser' >&2
  exit 2
fi
image=$1
label=$2
profile=$3
: "${CI_CONTAINER_USER:?Runner UID:GID is required}"
: "${CI_REPORTS:?Exclusive report directory is required}"
: "${CI_PERMISSION_INPUT:?Readonly fixture directory is required}"
[[ "$label" =~ ^[a-z0-9-]+$ ]]
[[ "$CI_CONTAINER_USER" =~ ^[0-9]+:[0-9]+$ ]]
[[ "$CI_CONTAINER_USER" == "$(id -u):$(id -g)" && "$(id -u)" != 0 ]]
[[ "$(stat -c '%u:%g' "$CI_REPORTS")" == "$CI_CONTAINER_USER" ]]
[[ "$(stat -c '%a' "$CI_REPORTS")" == 700 ]]

run=(--rm --pull never --platform linux/amd64 --network none --read-only
     --cap-drop ALL --security-opt no-new-privileges
     --tmpfs '/tmp:rw,exec,nosuid,size=256m' --user "$CI_CONTAINER_USER")
host_paths=()
container_paths=()
case "$profile" in
  trivy)
    : "${CI_CACHE:?Exclusive cache is required}"
    : "${CI_SCAN_TMP:?Exclusive scanner scratch is required}"
    host_paths=("$CI_CACHE" "$CI_REPORTS" "$CI_SCAN_TMP")
    container_paths=(/cache /reports /scan-tmp)
    report_host=$CI_REPORTS
    report_container=/reports
    ;;
  gitleaks)
    host_paths=("$CI_REPORTS")
    container_paths=(/reports)
    report_host=$CI_REPORTS
    report_container=/reports
    ;;
  ci)
    host_paths=("$CI_REPORTS")
    container_paths=(/ci-results)
    report_host=$CI_REPORTS
    report_container=/ci-results
    ;;
  browser)
    : "${CI_BROWSER_REPORTS:?Exclusive browser reports are required}"
    host_paths=("$CI_BROWSER_REPORTS")
    container_paths=(/ci-results)
    report_host=$CI_BROWSER_REPORTS
    report_container=/ci-results
    run+=(--init --shm-size=1g)
    ;;
  *) echo 'Unsupported permission profile.' >&2; exit 2 ;;
esac
for index in "${!host_paths[@]}"; do
  path=${host_paths[$index]}
  [[ -d "$path" && ! -L "$path" ]]
  [[ "$(stat -c '%u:%g' "$path")" == "$CI_CONTAINER_USER" ]]
  [[ "$(stat -c '%a' "$path")" == 700 ]]
  run+=(--mount "type=bind,src=$path,dst=${container_paths[$index]}")
done
fixture=$CI_PERMISSION_INPUT/permission-input.txt
[[ -f "$fixture" && ! -L "$fixture" ]]
[[ "$(stat -c '%u:%g:%a' "$fixture")" == "$CI_CONTAINER_USER:600" ]]
fixture_hash=$(sha256sum "$fixture" | awk '{print $1}')
run+=(--mount "type=bind,src=$CI_PERMISSION_INPUT,dst=/inputs,readonly")
mkdir -p -- "$CI_REPORTS/permissions"
log=$CI_REPORTS/permissions/$label.log
[[ ! -e "$log" ]]
{
  printf 'runner_identity=%s\nprofile=%s\n' "$CI_CONTAINER_USER" "$profile"
  printf 'image_id=%s\n' "$(docker image inspect --format '{{.Id}}' "$image")"
  printf 'configured_user=%s\n' "$(docker image inspect --format '{{json (index .Config "User")}}' "$image")"
  for path in "${host_paths[@]}"; do stat -c 'host_path=%n uid=%u gid=%g mode=%a' "$path"; done
  printf 'default_effective_identity='
  docker run --rm --pull never --platform linux/amd64 --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh "$image" \
    -ec 'printf "%s:%s\n" "$(id -u)" "$(id -g)"'
} > "$log"

payload=$(cat <<'CONTAINER_PROBE'
set -eu
umask 077
LC_ALL=C
export LC_ALL
identity=$1
label=$2
report=$3
shift 3
actual="$(id -u):$(id -g)"
printf 'effective_identity=%s\n' "$actual"
test "$actual" = "$identity"
awk '/^(Uid|Gid|CapEff|CapPrm|CapBnd|NoNewPrivs):/ {print}' /proc/self/status
for field in CapEff CapPrm CapBnd; do
  value=$(awk -v key="$field:" '$1==key {print $2}' /proc/self/status)
  test "$value" = 0000000000000000
done
test "$(awk '$1=="NoNewPrivs:" {print $2}' /proc/self/status)" = 1
for path in / /inputs; do
  awk -v path="$path" '$2==path {print "mount=" $2 " options=" $4; if ($4 ~ /(^|,)ro(,|$)/) ok=1} END {exit !ok}' /proc/mounts
done
test "$(stat -c '%u:%g:%a' /inputs/permission-input.txt)" = "$identity:600"
test "$(cat /inputs/permission-input.txt)" = clipforge-ci-readonly-input
if error=$( ( : > /inputs/permission-input.txt ) 2>&1 ); then
  echo 'Readonly fixture accepted a write.' >&2; exit 1
fi
case "$error" in *'Read-only file system'*) printf 'readonly_write_rejected=EROFS\n' ;; *) printf '%s\n' "$error" >&2; exit 1 ;; esac
for path in "$@"; do
  stat -c 'container_path=%n uid=%u gid=%g mode=%a' "$path"
  test "$(stat -c '%u:%g:%a' "$path")" = "$identity:700"
  probe=$path/.ci-permission-$label
  test ! -e "$probe"
  mkdir -- "$probe"
  printf 'probe\n' > "$probe/file"
  test "$(stat -c '%u:%g:%a' "$probe/file")" = "$identity:600"
  rm -- "$probe/file"
  rmdir -- "$probe"
  printf 'create_delete_passed=%s\n' "$path"
done
handoff=$report/.ci-permission-handoff-$label
test ! -e "$handoff"
printf 'clipforge-ci-runner-readable\n' > "$handoff"
test "$(stat -c '%u:%g:%a' "$handoff")" = "$identity:600"
printf 'handoff_created=%s\n' "$handoff"
CONTAINER_PROBE
)
docker run "${run[@]}" --entrypoint /bin/sh "$image" -ec "$payload" sh \
  "$CI_CONTAINER_USER" "$label" "$report_container" "${container_paths[@]}" >> "$log" 2>&1
handoff=$report_host/.ci-permission-handoff-$label
[[ "$(stat -c '%u:%g:%a' "$handoff")" == "$CI_CONTAINER_USER:600" ]]
[[ "$(cat "$handoff")" == clipforge-ci-runner-readable ]]
rm -- "$handoff"
[[ "$(sha256sum "$fixture" | awk '{print $1}')" == "$fixture_hash" ]]
printf 'runner_read_and_delete=passed\nreadonly_fixture_hash=%s\n' "$fixture_hash" >> "$log"
printf 'Permissions passed: %s (%s).\n' "$label" "$profile"
