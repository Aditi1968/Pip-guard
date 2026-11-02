#!/usr/bin/env bash
# Create the public pip guard demo repository and its five Track C pull requests.
#
#   bash demo/make_prs.sh <you>/pipguard-demo <you>/pip-guard <pip-guard commit SHA>
#
# Needs: git, gh (authenticated: `gh auth login`), uv. The user runs this; CI never does.
# It creates a PUBLIC repo (Actions minutes are free only for public repos; PRD zero-cost).
#
# Expected outcomes (PRD Track C):
#   1. add-planted        requets==2.31.0 (typosquat, reads creds, spawns sh, connect())  -> block, FAIL
#   2. benign-bump        six 1.16.0 -> 1.17.0                                            -> allow, PASS
#   3. unpinned-spec      flask>=3                                                        -> warn,  PASS
#   4. forced-timeout     sleepy==1.0.0 (sleeps at import)                                -> incomplete, FAIL
#   5. download-failure   six==99.0.0 (does not exist on PyPI)                            -> error, FAIL
set -euo pipefail

DEMO="${1:?usage: make_prs.sh OWNER/DEMO_REPO OWNER/PIPGUARD_REPO PIPGUARD_SHA}"
PIPGUARD="${2:?pip guard repo, e.g. you/pip-guard}"
SHA="${3:?pinned pip guard commit SHA (40 hex)}"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "SHA must be a full 40-hex commit"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"
echo "building demo repo in $WORK"

cp -R "$HERE/template/." "$WORK/"
(cd "$ROOT" && uv run python -m demo.build_wheels "$WORK/vendor/wheels")
sed -i.bak "s#OWNER/pip-guard/action@PIPGUARD_COMMIT_SHA#$PIPGUARD/action@$SHA#" \
  "$WORK/.github/workflows/pipguard.yml" && rm "$WORK/.github/workflows/pipguard.yml.bak"

cd "$WORK"
git init -q -b main
git add .
git commit -qm "Demo repo: pinned requirements and pip guard workflow"
gh repo create "$DEMO" --public --source . --push

pr() {  # branch, title, body, requirements.txt contents
  git checkout -q -b "$1" main
  printf '%s\n' "$4" > requirements.txt
  git commit -qam "$2"
  git push -q -u origin "$1"
  gh pr create --repo "$DEMO" --base main --head "$1" --title "$2" --body "$3"
  git checkout -q main
}

pr add-planted      "Add requets"               "Track C 1: planted typosquat. Expect block." $'six==1.16.0\nrequets==2.31.0'
pr benign-bump      "Bump six to 1.17.0"        "Track C 2: benign bump. Expect allow."     'six==1.17.0'
pr unpinned-spec    "Add flask (unpinned)"      "Track C 3: unpinned spec. Expect warn."    $'six==1.16.0\nflask>=3'
pr forced-timeout   "Add sleepy"                "Track C 4: import never returns. Expect incomplete." $'six==1.16.0\nsleepy==1.0.0'
pr download-failure "Pin six to a missing version" "Track C 5: download fails. Expect error." 'six==99.0.0'

echo "done: https://github.com/$DEMO/pulls"
