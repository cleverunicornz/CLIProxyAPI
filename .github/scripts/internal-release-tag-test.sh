#!/usr/bin/env bash
# Tests internal-release-tag.sh against a stubbed curl: every lookup error,
# a tag on another commit and an existing release stop the run; only an
# absent tag, a newly created tag, or a tag already on the built commit with
# no release pass. claim must POST exactly once, creating refs/tags/<tag> at
# exactly the built commit; check must POST nothing.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/internal-release-tag.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/bin"
cat > "$work/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Answers from $STUB_ROUTES lines "METHOD path|status|body"; status "neterr"
# exits like a failed connection. Unrouted requests fail the test. Each
# request's --data is appended to $STUB_POSTS as "METHOD path|data".
method=GET out="" url="" data=""
for arg in "$@"; do
  if [[ "$arg" == *test-token* ]]; then echo "token passed on the command line" >&2; exit 99; fi
done
while [[ $# -gt 0 ]]; do
  case "$1" in
    --request) method="$2"; shift 2 ;;
    --output) out="$2"; shift 2 ;;
    --data) data="$2"; shift 2 ;;
    --header|--write-out) shift 2 ;;
    --*) shift ;;
    *) url="$1"; shift ;;
  esac
done
cat > /dev/null
key="$method ${url#https://api.example.test/repos/o/r/}"
echo "$key" >> "$STUB_CALLS"
if [[ -n "$data" ]]; then printf '%s|%s\n' "$key" "$data" >> "$STUB_POSTS"; fi
line="$(grep -F -- "$key|" "$STUB_ROUTES" | head -n 1 || true)"
if [[ -z "$line" ]]; then echo "unrouted request: $key" >&2; exit 98; fi
IFS='|' read -r _ status body <<< "$line"
if [[ "$status" == neterr ]]; then echo "curl: (6) Could not resolve host" >&2; exit 6; fi
printf '%s' "$body" > "$out"
printf '%s' "$status"
STUB
chmod +x "$work/bin/curl"

tag=v1.2.3-cvu.1
built=1111111111111111111111111111111111111111
other=2222222222222222222222222222222222222222
ref_ok="{\"ref\":\"refs/tags/$tag\",\"object\":{\"type\":\"commit\",\"sha\":\"$built\"}}"
ref_other="{\"ref\":\"refs/tags/$tag\",\"object\":{\"type\":\"commit\",\"sha\":\"$other\"}}"
ref_annotated="{\"ref\":\"refs/tags/$tag\",\"object\":{\"type\":\"tag\",\"sha\":\"$built\"}}"
get_ref="GET git/ref/tags/$tag"
get_release="GET releases/tags/$tag"
post_ref="POST git/refs"

failures=0

# posts_problem MODE: prints what is wrong with the requests the last run
# sent, or nothing. claim sends exactly one request with a body, the POST
# creating refs/tags/$tag at $built and nothing else; other modes send none.
posts_problem() {
  local want=0 count
  [[ "$1" == claim ]] && want=1
  count="$(wc -l < "$work/posts")"
  if ((count != want)); then
    echo "sent $count request(s) with a body, expected $want"
  elif ((want == 1)) && ! jq -e --arg ref "refs/tags/$tag" --arg sha "$built" \
    '. == {ref: $ref, sha: $sha}' > /dev/null 2>&1 <<< "$(sed -n "s#^$post_ref|##p" "$work/posts")"; then
    echo "posted $(cat "$work/posts"), expected $post_ref creating refs/tags/$tag at $built"
  fi
}

# run_case NAME MODE EXPECT(pass|stop) ROUTE...; $case_script overrides the
# script under test.
run_case() {
  local name="$1" mode="$2" expect="$3" result problem
  shift 3
  printf '%s\n' "$@" > "$work/routes"
  : > "$work/calls"
  : > "$work/posts"
  if PATH="$work/bin:$PATH" STUB_ROUTES="$work/routes" STUB_CALLS="$work/calls" STUB_POSTS="$work/posts" \
    GH_TOKEN=test-token GITHUB_API_URL=https://api.example.test GITHUB_REPOSITORY=o/r \
    RELEASE_TAG="$tag" TARGET_SHA="$built" bash "${case_script:-$script}" "$mode" > "$work/out" 2>&1; then
    result=pass
  else
    result=stop
  fi
  problem="$(posts_problem "$mode")"
  if [[ "$result" == "$expect" && -z "$problem" ]] && ! grep -q -e 'unrouted request' -e 'token passed' "$work/out"; then
    echo "ok   $mode: $name"
  else
    echo "FAIL $mode: $name (expected $expect, got $result)${problem:+; $problem}"
    sed 's/^/     /' "$work/out"
    failures=$((failures + 1))
  fi
}

run_case "absent tag" check pass "$get_ref|404|{}"
run_case "tag on built commit, no release" check pass "$get_ref|200|$ref_ok" "$get_release|404|{}"
run_case "tag on another commit" check stop "$get_ref|200|$ref_other"
run_case "annotated tag" check stop "$get_ref|200|$ref_annotated"
run_case "tag on built commit with a release" check stop "$get_ref|200|$ref_ok" "$get_release|200|{}"
run_case "tag lookup server error" check stop "$get_ref|500|{}"
run_case "tag lookup forbidden" check stop "$get_ref|403|{}"
run_case "tag lookup network error" check stop "$get_ref|neterr|"
run_case "tag lookup returns a list" check stop "$get_ref|200|[$ref_ok]"
run_case "release lookup error" check stop "$get_ref|200|$ref_ok" "$get_release|502|{}"

run_case "creates the tag" claim pass "$post_ref|201|$ref_ok"
run_case "created on another commit" claim stop "$post_ref|201|$ref_other"
run_case "retry: tag on built commit, no release" claim pass "$post_ref|422|{}" "$get_ref|200|$ref_ok" "$get_release|404|{}"
run_case "race: tag on another commit" claim stop "$post_ref|422|{}" "$get_ref|200|$ref_other"
run_case "retry: release already exists" claim stop "$post_ref|422|{}" "$get_ref|200|$ref_ok" "$get_release|200|{}"
run_case "create rejected, tag absent" claim stop "$post_ref|422|{}" "$get_ref|404|{}"
run_case "create forbidden" claim stop "$post_ref|403|{}"
run_case "create network error" claim stop "$post_ref|neterr|"
run_case "lookup error after conflict" claim stop "$post_ref|422|{}" "$get_ref|500|{}"
run_case "unknown mode" bogus stop

# The posted-body check itself: a copy of the script that creates the tag on
# another commit must fail even though the stub answers 201 with the right ref.
sed 's/--arg sha "$TARGET_SHA"/--arg sha "${TARGET_SHA\/\/1\/2}"/' "$script" > "$work/wrong-sha.sh"
if cmp -s "$script" "$work/wrong-sha.sh"; then
  echo "FAIL claim: wrong-SHA copy of the script could not be made"
  failures=$((failures + 1))
else
  before=$failures
  case_script="$work/wrong-sha.sh" run_case "wrong SHA posted (must FAIL)" claim pass "$post_ref|201|$ref_ok" > "$work/wrong-out"
  if ((failures == before + 1)) && grep -q "posted .*\"sha\":\"$other\"" "$work/wrong-out"; then
    failures=$before
    echo "ok   claim: a POST with the wrong SHA is rejected"
  else
    failures=$((before + 1))
    echo "FAIL claim: a POST with the wrong SHA was not rejected"
    sed 's/^/     /' "$work/wrong-out"
  fi
fi

if ((failures > 0)); then
  echo "$failures case(s) failed" >&2
  exit 1
fi
echo "all cases passed"
