#!/usr/bin/env bash
# Builds the linux/amd64 no-plugin release archive and its checksums.txt from
# the checked-out commit into <output dir>, then verifies them.
#
# Every input comes from the commit and the pinned Go toolchain, so two builds
# of one commit with the same RELEASE_TAG are byte-identical:
# - the embedded model catalogs are the files committed under
#   internal/registry/models (upstream's release build refreshes them from
#   router-for-me/models at build time; this build does not);
# - the build date is the commit time (SOURCE_DATE_EPOCH);
# - -trimpath keeps the build directory out of the binary;
# - the tarball has fixed modes, mtime, numeric owner 0:0, a fixed member
#   order and no extended headers, and gzip stores no name or timestamp.
#
# Usage: GO_VERSION=1.26.4 [RELEASE_TAG=v<version>-cvu.<n>] internal-release-build.sh <output dir>
# Without RELEASE_TAG the version is dev-<commit>. When GITHUB_OUTPUT is set,
# writes version, commit, sha, build_date and checksum to it.
set -euo pipefail

out="${1:?usage: $0 <output dir>}"
: "${GO_VERSION:?GO_VERSION is required}"
export GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS='' LC_ALL=C TZ=UTC

actual_go="$(go env GOVERSION)"
if [[ "$actual_go" != "go$GO_VERSION" ]]; then
  echo "::error::Go is $actual_go, expected go$GO_VERSION" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  git status --short --untracked-files=no >&2
  echo "::error::tracked files differ from the commit; the release builds the committed bytes only" >&2
  exit 1
fi
command -v readelf > /dev/null || sudo apt-get install -y binutils

sha="$(git rev-parse HEAD)"
commit="${sha:0:7}"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)"
export SOURCE_DATE_EPOCH
build_date="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
if [[ -n "${RELEASE_TAG:-}" ]]; then
  version="${RELEASE_TAG#v}"
else
  version="dev-${commit}"
fi
archive_name="CLIProxyAPI_${version}_linux_amd64_no-plugin.tar.gz"
members=(LICENSE README.md README_CN.md cli-proxy-api config.example.yaml)

stage="$(mktemp -d)"
unpacked="$(mktemp -d)"
trap 'rm -rf "$stage" "$unpacked"' EXIT

go build -trimpath -buildvcs=false \
  -ldflags="-s -w -X main.Version=${version} -X main.Commit=${commit} -X main.BuildDate=${build_date}" \
  -o "$stage/cli-proxy-api" ./cmd/server/

if readelf -l "$stage/cli-proxy-api" | grep -q 'Requesting program interpreter'; then
  readelf -l "$stage/cli-proxy-api" >&2
  echo "::error::no-plugin linux binary must not require a dynamic interpreter" >&2
  exit 1
fi

cp LICENSE README.md README_CN.md config.example.yaml "$stage/"
chmod 0644 "$stage/LICENSE" "$stage/README.md" "$stage/README_CN.md" "$stage/config.example.yaml"
chmod 0755 "$stage/cli-proxy-api"

mkdir -p "$out"
tar --create --format=ustar --sort=name --mtime="@$SOURCE_DATE_EPOCH" \
  --owner=0 --group=0 --numeric-owner --directory="$stage" "${members[@]}" |
  gzip -n > "$out/$archive_name"
(cd "$out" && sha256sum "$archive_name" > checksums.txt)
cat "$out/checksums.txt"

# Verify what was written.
test "$(cd "$out" && ls | sort)" = "$(printf '%s\n' "$archive_name" checksums.txt | sort)"
test "$(wc -l < "$out/checksums.txt")" = 1
(cd "$out" && sha256sum --check --strict checksums.txt)
test "$(tar -tzf "$out/$archive_name")" = "$(printf '%s\n' "${members[@]}")"
tar -C "$unpacked" -xzf "$out/$archive_name"
# The binary prints its embedded build identity first, then the flag usage.
banner="$(cd "$unpacked" && ./cli-proxy-api -h 2>&1 | head -n 1 || true)"
echo "$banner"
test "$banner" = "CLIProxyAPI Version: ${version}, Commit: ${commit}, BuiltAt: ${build_date}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "version=$version"
    echo "commit=$commit"
    echo "sha=$sha"
    echo "build_date=$build_date"
    echo "checksum=$(cut -d ' ' -f 1 "$out/checksums.txt")"
  } >> "$GITHUB_OUTPUT"
fi
