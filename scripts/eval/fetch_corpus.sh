#!/usr/bin/env bash
###############################################################################
#  YOU RUN THIS BY HAND, LOCALLY. NEVER IN CI.
#
#  Downloads the Track A corpus sources into ~/pipguard-data (outside the repo):
#    - Datadog malicious-software-packages-dataset (ENCRYPTED LIVE MALWARE zips)
#    - OpenSSF malicious-packages (OSV JSON reports, no code)
#    - a list of all PyPI project names (for the random benign band)
#  It only clones and downloads. It never unzips, installs, imports or runs
#  anything. Do not unzip the Datadog samples yourself; build_manifest and
#  batch_static extract them into a quarantine dir and only parse them.
#  Never commit or redistribute anything under ~/pipguard-data.
###############################################################################
set -euo pipefail

DATA="${PIPGUARD_DATA:-$HOME/pipguard-data}"
mkdir -p "$DATA"

[ -d "$DATA/datadog" ] || git clone --depth 1 \
  https://github.com/DataDog/malicious-software-packages-dataset "$DATA/datadog"
[ -d "$DATA/ossf" ] || git clone --depth 1 \
  https://github.com/ossf/malicious-packages "$DATA/ossf"

# All PyPI project names (PEP 691 JSON simple index), one per line, for --random-names.
curl -fsSL -H "Accept: application/vnd.pypi.simple.v1+json" https://pypi.org/simple/ \
  | python -I -c "import json, sys; print('\n'.join(p['name'] for p in json.load(sys.stdin)['projects']))" \
  > "$DATA/pypi-names.txt"

echo "done: $DATA (datadog, ossf, pypi-names.txt). Read scripts/eval/README.md next."
