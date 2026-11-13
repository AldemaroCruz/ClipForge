FROM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS gosu
WORKDIR /src
ADD https://codeload.github.com/tianon/gosu/tar.gz/29b939aa5bd4dc588af765b8248f6e39150d2565 /tmp/gosu.tar.gz
RUN echo '2b70da8a5480fafedc16bb1fc91b572f064d03df736cbd91a616af2f1b66ab51  /tmp/gosu.tar.gz' | sha256sum -c - && tar -xzf /tmp/gosu.tar.gz --strip-components=1 -C /src && go mod download && go mod verify
RUN CGO_ENABLED=0 GOBIN=/out go install -trimpath github.com/tianon/gosu@29b939aa5bd4dc588af765b8248f6e39150d2565 && /out/gosu --version && go version -m /out/gosu
FROM postgres:18.6-trixie@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42
RUN printf '%s\n' 'Types: deb' 'URIs: http://snapshot.debian.org/archive/debian/20261109T000000Z/' 'Suites: trixie trixie-updates' 'Components: main' 'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' 'Check-Valid-Until: no' '' 'Types: deb' 'URIs: http://snapshot.debian.org/archive/debian-security/20261109T000000Z/' 'Suites: trixie-security' 'Components: main' 'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' 'Check-Valid-Until: no' > /etc/apt/ci-security.sources && apt-get -o Dir::Etc::sourcelist=/etc/apt/ci-security.sources -o Dir::Etc::sourceparts=- update && apt-get -o Dir::Etc::sourcelist=/etc/apt/ci-security.sources -o Dir::Etc::sourceparts=- install -y --no-install-recommends zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 && rm -rf /var/lib/apt/lists/*
COPY --from=gosu --chmod=0755 /out/gosu /usr/local/bin/gosu
RUN gosu nobody true
