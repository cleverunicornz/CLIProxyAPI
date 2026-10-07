#!/usr/bin/env bash
# Decides whether the release tag RELEASE_TAG may be published for the built
# commit TARGET_SHA, through the GitHub API.
#
#   check  read only: passes when the tag is absent, or when it already points
#          at TARGET_SHA and has no release (a retry of an interrupted publish).
#   claim  creates the tag on TARGET_SHA. Creating an existing ref fails, so of
#          two concurrent publishers only one creates it; an existing tag then
#          passes only under the same condition as check.
#
# Any other answer, including every lookup error, stops the run.
set -euo pipefail

mode="${1:-}"
: "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}" "${RELEASE_TAG:?}" "${TARGET_SHA:?}"
api="${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}"
body="$(mktemp)"
trap 'rm -f "$body"' EXIT

fail() {
  echo "::error::$*" >&2
  exit 1
}

# request METHOD PATH [JSON]: prints the HTTP status and leaves the response
# body in $body. The token reaches curl on stdin, never on its command line.
request() {
  local args=(--silent --show-error --output "$body" --write-out '%{http_code}'
    --request "$1" --header @- --header 'Accept: application/vnd.github+json'
    --header 'X-GitHub-Api-Version: 2022-11-28')
  if [[ $# -ge 3 ]]; then
    args+=(--header 'Content-Type: application/json' --data "$3")
  fi
  printf 'Authorization: Bearer %s\n' "$GH_TOKEN" | curl "${args[@]}" "$api/$2"
}

# require_on_target: the ref in $body must be the lightweight tag on TARGET_SHA.
require_on_target() {
  local found
  found="$(jq -r '"\(.ref) \(.object.type) \(.object.sha)"' "$body")" ||
    fail "unexpected answer for tag $RELEASE_TAG"
  [[ "$found" == "refs/tags/$RELEASE_TAG commit $TARGET_SHA" ]] ||
    fail "tag $RELEASE_TAG is ${found#* }, not commit $TARGET_SHA; choose the next -cvu.<n>"
}

# require_resumable: the tag exists; it must be on TARGET_SHA without a release.
require_resumable() {
  local status
  status="$(request GET "git/ref/tags/$RELEASE_TAG")"
  [[ "$status" == 200 ]] || fail "looking up tag $RELEASE_TAG returned HTTP $status"
  require_on_target
  status="$(request GET "releases/tags/$RELEASE_TAG")"
  case "$status" in
    404) echo "tag $RELEASE_TAG is already on $TARGET_SHA without a release; continuing" ;;
    200) fail "release $RELEASE_TAG already exists" ;;
    *) fail "looking up release $RELEASE_TAG returned HTTP $status" ;;
  esac
}

case "$mode" in
  check)
    status="$(request GET "git/ref/tags/$RELEASE_TAG")"
    case "$status" in
      404) echo "tag $RELEASE_TAG is unused" ;;
      200) require_resumable ;;
      *) fail "looking up tag $RELEASE_TAG returned HTTP $status" ;;
    esac
    ;;
  claim)
    payload="$(jq -cn --arg ref "refs/tags/$RELEASE_TAG" --arg sha "$TARGET_SHA" '{ref: $ref, sha: $sha}')"
    status="$(request POST git/refs "$payload")"
    case "$status" in
      201)
        require_on_target
        echo "created tag $RELEASE_TAG on $TARGET_SHA"
        ;;
      422) require_resumable ;;
      *) fail "creating tag $RELEASE_TAG returned HTTP $status" ;;
    esac
    ;;
  *)
    fail "usage: $0 check|claim"
    ;;
esac
