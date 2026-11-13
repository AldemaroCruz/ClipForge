#!/bin/bash
# Future VM startup only. TF-INT-01 never executes this recipe.
# Debian 13 / PostgreSQL 17, signed Debian archive; no SQL or secret retrieval.
set -euo pipefail
umask 077
. /etc/os-release
test "$ID" = debian && test "$VERSION_CODENAME" = trixie
test -f /usr/share/keyrings/debian-archive-keyring.gpg
# Never reconfigure an existing PostgreSQL cluster or format a disk.
if compgen -G '/etc/postgresql/*/*/postgresql.conf' >/dev/null; then
  echo 'Existing PostgreSQL configuration requires manual review.' >&2
  exit 1
fi
cat > /etc/apt/sources.list.d/debian.sources <<'SOURCES'
Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://deb.debian.org/debian-security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
SOURCES
apt_options=(-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/debian.sources -o Dir::Etc::sourceparts=- -o Acquire::AllowInsecureRepositories=false)
apt-get "${apt_options[@]}" update
# APT verifies signed InRelease and package hashes using the image's Debian keys.
# This reviewed minor version must still exist and be re-reviewed before apply.
DEBIAN_FRONTEND=noninteractive apt-get "${apt_options[@]}" install --no-install-recommends -y postgresql-common
printf 'create_main_cluster = false\n' > /etc/postgresql-common/createcluster.conf
systemctl mask postgresql.service postgresql@.service
DEBIAN_FRONTEND=noninteractive apt-get "${apt_options[@]}" install --no-install-recommends -y \
  postgresql-17=17.12-0+deb13u1 postgresql-client-17=17.12-0+deb13u1 \
  openssl python3 e2fsprogs util-linux
systemctl mask postgresql.service postgresql@.service
install -d -m 0700 /var/lib/clipforge-postgres
dpkg-query -W postgresql-17 postgresql-client-17 > /var/lib/clipforge-postgres/package-provenance.txt
# Separate protected procedure must initialize/mount the data disk, issue TLS,
# create SCRAM roles, load secrets, enable the service and prove restore.
echo 'Packages installed; PostgreSQL remains uninitialized and masked.'
