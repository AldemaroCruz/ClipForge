#!/bin/bash
# Installation only, from the dedicated standard Ubuntu Noble GCE image.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C DEBIAN_FRONTEND=noninteractive
unset APT_CONFIG

readonly noble_state_dir=/var/lib/clipforge-postgres
readonly noble_provenance="$noble_state_dir/package-provenance.txt"
readonly ubuntu_keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
# Expected hashes of the public archive signing files, verified before APT.
readonly ubuntu_archive_file_sha256=80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31
readonly pgdg_archive_file_sha256=0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76
readonly apt_minimum=2.8.4ubuntu0.1
readonly -a fixed_packages=(
    'libxml2=2.9.14+dfsg-1.3ubuntu3.10'
    'libpq5=18.7-1.pgdg24.04+2'
    'postgresql-common=297.pgdg24.04+1'
    'postgresql-client-common=297.pgdg24.04+1'
    'postgresql-17=17.12-1.pgdg24.04+1'
    'postgresql-client-17=17.12-1.pgdg24.04+1'
)
readonly -A fixed_archive_sha256=(
    [libxml2]=c5a065f85c1e6f605741e365e40cad71c3ceb0e85e2791400bd35b8896e12ad1
    [libpq5]=c982d16d81c3dacba5b85797af37c5e6b34a73e20ddbbf41a61098276db53a3d
    [postgresql-common]=cb5abb222b58f976f34dc43a5db4476b35dc566580579ede5e5246a00909569c
    [postgresql-client-common]=01c7d14b3cf73a67c7ec68be5b43751ff722bfd46f7bada887944b1493f648f0
    [postgresql-17]=b514c145a5bab6a984ffb9c457f590fce79d574a68e7b8672c6511030f803428
    [postgresql-client-17]=f34a296d8374df264afcb54cf2b171afe9bfad3b9971ea60a091db86ff6c8ded
)

noble_blocked() {
    printf 'CLIPFORGE_DB01_NOBLE_BLOCKED %s\n' "$1" >&2
    exit 1
}

path_exists() { [[ -e $1 || -L $1 ]]; }
trusted_directory() { [[ -d $1 && ! -L $1 && $(stat -c '%u:%g:%a' -- "$1") == 0:0:700 ]]; }
trusted_receipt() { [[ -f $1 && ! -L $1 && $(stat -c '%u:%g:%a:%h' -- "$1") == 0:0:600:1 ]]; }

startup_state() {
    local root=$1
    # The future bootstrap writes its durable journal before making storage changes.
    # A partial journal directory is deliberately enough to preserve the system.
    if path_exists "$root/db01"; then
        if [[ -d $root && ! -L $root ]] && trusted_directory "$root/db01"; then
            printf '%s\n' bootstrap_state_present
        else
            printf '%s\n' blocked
        fi
    elif path_exists "$root/data" || path_exists "$root/noble-install.partial"; then
        printf '%s\n' blocked
    elif path_exists "$root/package-provenance.txt"; then
        if trusted_directory "$root" && trusted_receipt "$root/package-provenance.txt"; then
            printf '%s\n' installed
        else
            printf '%s\n' blocked
        fi
    elif path_exists "$root"; then
        printf '%s\n' blocked
    else
        printf '%s\n' fresh
    fi
}

verify_platform() {
    [[ $EUID == 0 && -r /etc/os-release ]] || noble_blocked root_linux_required
    # shellcheck source=/dev/null
    . /etc/os-release
    [[ $ID == ubuntu && $VERSION_ID == 24.04 && $VERSION_CODENAME == noble \
        && $(dpkg --print-architecture) == amd64 && $(uname -m) == x86_64 ]] \
        || noble_blocked ubuntu_noble_amd64_required
}

verify_blank_postgres() {
    local clusters processes tcp unix units
    if command -v pg_lsclusters > /dev/null; then
        clusters=$(timeout 10s /usr/bin/pg_lsclusters --no-header)
        [[ -z $clusters ]] || noble_blocked postgres_cluster_exists
    fi
    if compgen -G '/etc/postgresql/*/*' > /dev/null || compgen -G '/var/lib/postgresql/*/*' > /dev/null; then
        noble_blocked postgres_cluster_paths_exist
    fi
    processes=$(timeout 10s ps -eo comm=)
    tcp=$(timeout 10s ss -H -ltn 'sport = :5432')
    unix=$(timeout 10s ss -H -lx)
    units=$(timeout 10s systemctl list-units 'postgresql*' --state=active,activating,reloading,deactivating --no-legend --no-pager --plain)
    if grep -Eq '^[[:blank:]]*(postgres|postmaster)[[:blank:]]*$' <<< "$processes" || \
        grep -Eq '\.s\.PGSQL\.[0-9]+([[:blank:]]|$)' <<< "$unix" || [[ -n $tcp || -n $units ]]; then
        noble_blocked postgres_process_listener_or_unit_present
    fi
}

verify_masks() {
    local rows
    rows=$(timeout 10s systemctl list-unit-files postgresql.service 'postgresql@.service' --no-legend --no-pager)
    awk '$1 == "postgresql.service" && $2 == "masked" { main++ }
         $1 == "postgresql@.service" && $2 == "masked" { template++ }
         END { exit !(NR == 2 && main == 1 && template == 1) }' <<< "$rows"
    [[ $(cat /etc/postgresql-common/createcluster.conf) == 'create_main_cluster = false' ]]
}

verify_pinned_install() {
    local spec
    for spec in "${fixed_packages[@]}"; do
        [[ $(dpkg-query -W -f='${Version} ${db:Status-Status}' "${spec%%=*}") == "${spec#*=} installed" ]] \
            || noble_blocked exact_pinned_package_required
    done
    sha256sum --check --status <<'ELF_AND_UNIT'
1d0518b561093b7245c38e223be6ac7cb2ea7f01a44aa284b53dba48a23d0ad4  /usr/lib/postgresql/17/bin/postgres
209e941be9eb2eb9ab36caaa0b81d1c6b36c8f5d7268c24f19e81039137e6485  /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14
ac9bf71c90ca096a55e73b6c4a7ea08c6c8159eee10db60642a9058d67d6668e  /usr/lib/systemd/system/postgresql@.service
ELF_AND_UNIT
}

write_apt_policy() {
    local dir=$1
    cat > "$dir/reviewed.sources" <<SOURCES
Types: deb
URIs: https://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates
Components: main universe
Architectures: amd64
Signed-By: $ubuntu_keyring

Types: deb
URIs: https://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main universe
Architectures: amd64
Signed-By: $ubuntu_keyring

Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt/
Suites: noble-pgdg
Components: main
Architectures: amd64
Signed-By: $dir/pgdg.asc B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
SOURCES
    cat > "$dir/reviewed.preferences" <<'PREFERENCES'
Package: postgresql-17 postgresql-client-17 postgresql-common postgresql-client-common libpq5
Pin: release n=noble-pgdg
Pin-Priority: 501

Package: *
Pin: release n=noble-pgdg
Pin-Priority: -1
PREFERENCES
    # Source and cache isolation avoids lock contention over system lists.
    # The real installation still honors the native bounded dpkg lock.
    cat > "$dir/reviewed.conf" <<APT
Dir::Etc::Parts "/dev/null";
Dir::Etc::Main "/dev/null";
Dir::Etc::SourceList "$dir/reviewed.sources";
Dir::Etc::SourceParts "-";
Dir::Etc::Preferences "$dir/reviewed.preferences";
Dir::Etc::PreferencesParts "-";
Dir::State::Lists "$dir/lists";
Dir::Cache::Archives "$dir/archives";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
DPkg::Lock::Timeout "45";
Acquire::Retries "0";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowWeakRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::Check-Valid-Until "true";
Acquire::Languages "none";
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";
APT::Get::AllowUnauthenticated "false";
APT::Update::Error-Mode "any";
APT
}

verify_apt_record() {
    local name=$1 version=$2 architecture=$3 digest=$4
    timeout 20s apt-cache show "$name=$version" | awk -v name="$name" -v version="$version" -v arch="$architecture" -v sha="$digest" '
        BEGIN { RS=""; FS="\n" }
        {
            p=v=a=h=f=""
            for (i=1; i<=NF; i++) {
                if ($i ~ /^Package: /) p=substr($i,10)
                if ($i ~ /^Version: /) v=substr($i,10)
                if ($i ~ /^Architecture: /) a=substr($i,15)
                if ($i ~ /^SHA256: /) h=substr($i,9)
                if ($i ~ /^Filename: /) f=substr($i,11)
            }
            if (p==name && v==version && a==arch && h==sha && f ~ /^pool\//) found=1
        }
        END { exit !found }
    '
}

resolve_archives() {
    local dir=$1 spec name version architecture digest archive current
    local -a changes=()
    timeout 30s apt-get -s --no-install-recommends --no-remove install "${fixed_packages[@]}" > "$dir/solver.txt"
    if grep -Eq '^(Remv|Purg) ' "$dir/solver.txt"; then noble_blocked apt_removal_proposed; fi
    sed -nE 's/^Inst ([^ ]+)( \[[^]]+\])? \(([^ ]+) .*/\1=\3/p' "$dir/solver.txt" > "$dir/changes.txt"
    [[ $(awk '/^Inst / { n++ } END {print n+0}' "$dir/solver.txt") == "$(wc -l < "$dir/changes.txt")" ]]
    mapfile -t changes < "$dir/changes.txt"
    for spec in "${changes[@]}"; do
        [[ $spec =~ ^[a-z0-9][a-z0-9+.-]*(:amd64)?=[A-Za-z0-9.+:~_-]+$ ]] || noble_blocked apt_resolution_invalid
        name=${spec%%=*}
        version=${spec#*=}
        if current=$(dpkg-query -W -f='${Version}' "$name" 2>/dev/null); then
            dpkg --compare-versions "$version" ge "$current" || noble_blocked apt_downgrade_proposed
        fi
    done
    printf '%s\n' "${fixed_packages[@]}" "${changes[@]}" | sed -E 's/:amd64=/=/' | sort -u > "$dir/install-lock.txt"
    awk -F= 'seen[$1]++ { duplicate=1 } END { exit duplicate }' "$dir/install-lock.txt"
    mapfile -t locked_packages < "$dir/install-lock.txt"

    for spec in "${fixed_packages[@]}"; do
        name=${spec%%=*}
        version=${spec#*=}
        architecture=amd64
        if [[ $name == postgresql-common || $name == postgresql-client-common ]]; then architecture=all; fi
        verify_apt_record "$name" "$version" "$architecture" "${fixed_archive_sha256[$name]}"
        printf 'pinned_archive\t%s\t%s\t%s\t%s\n' "$name" "$version" "$architecture" "${fixed_archive_sha256[$name]}"
    done > "$dir/pinned.tsv"

    timeout --kill-after=10s 150s apt-get --download-only -y --no-install-recommends --no-remove install "${locked_packages[@]}"
    shopt -s nullglob
    for archive in "$dir"/archives/*.deb; do
        name=$(dpkg-deb -f "$archive" Package)
        version=$(dpkg-deb -f "$archive" Version)
        architecture=$(dpkg-deb -f "$archive" Architecture)
        digest=$(sha256sum "$archive" | cut -d' ' -f1)
        [[ $architecture == amd64 || $architecture == all ]]
        verify_apt_record "$name" "$version" "$architecture" "$digest"
        if [[ ${fixed_archive_sha256[$name]+present} ]]; then
            [[ $digest == "${fixed_archive_sha256[$name]}" ]]
        fi
        printf '%s=%s\t%s\t%s\n' "$name" "$version" "$architecture" "$digest"
    done | sort > "$dir/downloads.tsv"
    sed -E 's/:amd64=/=/' "$dir/changes.txt" | sort > "$dir/changed-specs.txt"
    cut -f1 "$dir/downloads.tsv" | cmp -s "$dir/changed-specs.txt" -
}

cleanup_first_boot() {
    local code=$?
    trap - EXIT
    if [[ -n $policy ]]; then
        if [[ $policy -ef /usr/sbin/policy-rc.d ]]; then rm -- /usr/sbin/policy-rc.d; fi
        rm -- "$policy"
    fi
    if [[ $dir =~ ^/run/clipforge-db01-noble\.[[:alnum:]]{8}$ && -d $dir && ! -L $dir ]]; then
        rm -rf -- "$dir"
    fi
    exit "$code"
}

prepare_first_boot() (
    # A failed installation leaves a durable marker and the masks in place.
    local dir policy= current spec
    local -a locked_packages=()
    timeout --kill-after=5s 180s cloud-init status --wait > /dev/null
    verify_blank_postgres
    for spec in apt libapt-pkg6.0t64; do
        current=$(dpkg-query -W -f='${Version}' "$spec")
        dpkg --compare-versions "$current" ge "$apt_minimum" || noble_blocked apt_fix_required
    done
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || noble_blocked ubuntu_ca_bundle_required
    printf '%s  %s\n' "$ubuntu_archive_file_sha256" "$ubuntu_keyring" | sha256sum --check --status
    path_exists /usr/sbin/policy-rc.d && noble_blocked existing_service_policy
    path_exists /etc/postgresql-common/createcluster.conf && noble_blocked existing_cluster_policy

    mkdir -m 0700 -- "$noble_state_dir"
    mkdir -m 0700 -- "$noble_state_dir/noble-install.partial"
    dir=$(mktemp -d /run/clipforge-db01-noble.XXXXXXXX)
    chmod 0755 "$dir"
    install -d -m 0755 "$dir/lists" "$dir/archives"
    trap cleanup_first_boot EXIT
    curl -q --fail --silent --show-error --proto '=https' --noproxy '*' --retry 0 --connect-timeout 10 \
        --max-time 25 --max-filesize 16384 https://www.postgresql.org/media/keys/ACCC4CF8.asc -o "$dir/pgdg.asc"
    printf '%s  %s\n' "$pgdg_archive_file_sha256" "$dir/pgdg.asc" | sha256sum --check --status
    chmod 0644 "$dir/pgdg.asc"
    write_apt_policy "$dir"
    export APT_CONFIG="$dir/reviewed.conf"
    timeout --kill-after=10s 120s apt-get update
    resolve_archives "$dir"

    install -d -m 0755 /etc/postgresql-common
    (set -o noclobber; printf '%s\n' 'create_main_cluster = false' > /etc/postgresql-common/createcluster.conf)
    chmod 0644 /etc/postgresql-common/createcluster.conf
    timeout 15s systemctl mask postgresql.service postgresql@.service
    verify_masks
    policy=$(mktemp /usr/sbin/.clipforge-db01-policy.XXXXXXXX)
    cat > "$policy" <<'POLICY'
#!/bin/sh
case "$1" in postgresql|postgresql.service|postgresql@*) exit 101 ;; esac
exit 0
POLICY
    chmod 0755 "$policy"
    ln -- "$policy" /usr/sbin/policy-rc.d
    timeout --kill-after=15s 200s apt-get --no-download -y --no-install-recommends --no-remove \
        -o Dpkg::Options::=--force-confold install "${locked_packages[@]}"
    for spec in "${locked_packages[@]}"; do
        [[ $(dpkg-query -W -f='${Version} ${db:Status-Status}' "${spec%%=*}") == "${spec#*=} installed" ]]
    done
    verify_pinned_install
    verify_masks
    verify_blank_postgres

    {
        printf '%s\n' 'clipforge-db01-noble-startup-provenance-1' 'postgresql_installed_masked_uninitialized'
        printf 'ubuntu_key_sha256\t%s\npgdg_key_sha256\t%s\n' "$ubuntu_archive_file_sha256" "$pgdg_archive_file_sha256"
        printf 'pgdg_key_fingerprint\t%s\n' B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
        printf 'os\t%s\nkernel\t%s\n' 'ubuntu/24.04/noble/amd64' "$(uname -r)"
        sed "s|$dir/pgdg.asc|PGDG-key-above|" "$dir/reviewed.sources"
        cat "$dir/pinned.tsv" "$dir/install-lock.txt" "$dir/downloads.tsv"
        (cd "$dir/lists"; sha256sum -- *_InRelease *_Packages*)
        timeout 20s apt-cache policy "${fixed_packages[@]%%=*}"
        dpkg-query -W -f='installed\t${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n' \
            apt libapt-pkg6.0t64 ubuntu-keyring ca-certificates openssl libssl3t64 "${fixed_packages[@]%%=*}"
        sha256sum /usr/lib/postgresql/17/bin/postgres /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14 \
            /usr/lib/systemd/system/postgresql@.service
    } > "$noble_state_dir/noble-install.partial/provenance.txt"
    # This path exists only on a completed installation, never on a retry.
    mv -T -- "$noble_state_dir/noble-install.partial/provenance.txt" "$noble_provenance"
    rmdir -- "$noble_state_dir/noble-install.partial"
)

route_startup() {
    NOBLE_FIRST_INSTALL=0
    case "$(startup_state "$1")" in
        bootstrap_state_present)
            printf '%s\n' 'CLIPFORGE_DB01_NOBLE_BOOTSTRAP_STATE_PRESERVED'
            ;;
        installed)
            verify_pinned_install
            verify_masks
            verify_blank_postgres
            printf '%s\n' 'CLIPFORGE_DB01_NOBLE_PRIOR_INSTALL_VERIFIED'
            ;;
        fresh)
            prepare_first_boot
            NOBLE_FIRST_INSTALL=1
            printf '%s\n' 'CLIPFORGE_DB01_NOBLE_INSTALLED_MASKED_UNINITIALIZED'
            ;;
        *) noble_blocked prior_install_or_storage_preserved ;;
    esac
}

main() {
    [[ $# == 0 ]] || noble_blocked startup_arguments_forbidden
    verify_platform
    route_startup "$noble_state_dir"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
