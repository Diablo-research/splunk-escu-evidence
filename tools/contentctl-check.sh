#!/bin/bash
# Applies every proposed detection in this repository to the current splunk/security_content develop branch,
# runs the repository's field-order hook and `contentctl-ng build`, and writes contentctl-build.txt in the repo root.
# Usage (Linux / WSL, as a normal user): bash tools/contentctl-check.sh <repo>
set -uo pipefail
REPO="$(cd "$1" && pwd)"
WORK="$HOME/escu-evidence-contentctl"
OUT="$REPO/contentctl-build.txt"
export PATH="$HOME/.local/bin:$PATH"
command -v git >/dev/null || { echo "git is missing (sudo apt install -y git)"; exit 1; }
command -v uv  >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh
mkdir -p "$WORK" && cd "$WORK"
[ -d security_content ] || git clone -q --depth 1 https://github.com/splunk/security_content.git
cd security_content
git fetch -q --depth 1 origin develop && git reset -q --hard FETCH_HEAD && git clean -qfd
BASE=$(git rev-parse --short HEAD)
before=$(ls detections/endpoint/*.yml | wc -l)
files=()
for f in "$REPO"/*/detections/*.yml; do cp "$f" detections/endpoint/; files+=("detections/endpoint/$(basename "$f")"); done
[ -x "$WORK/venv/bin/python" ] || uv venv -q --python 3.14 "$WORK/venv"
uv pip install -q --python "$WORK/venv/bin/python" contentctl-ng==1.1.1
{
  echo "splunk/security_content develop $BASE, contentctl-ng 1.1.1, $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "Added ${#files[@]} proposed detections:"; printf '  %s\n' "${files[@]}"
  echo; echo "== scripts/enforce_yaml_field_order.py =="
  "$WORK/venv/bin/python" scripts/enforce_yaml_field_order.py "${files[@]}" 2>&1
  echo; echo "== contentctl-ng build =="
} > "$OUT"
"$WORK/venv/bin/contentctl-ng" build > "$WORK/build.log" 2>&1
rc=$?
grep -iE 'error|invalid|Writing [0-9]+ detections|Successfully built' "$WORK/build.log" | tail -25 >> "$OUT"
for f in "${files[@]}"; do
  n=$(sed -n 's/^name: //p' "$f" | head -1)
  if grep -qF "[ESCU - $n - Rule]" dist/*/default/savedsearches.conf 2>/dev/null; then echo "built: ESCU - $n - Rule" >> "$OUT"; else echo "NOT FOUND in savedsearches.conf: $n" >> "$OUT"; fi
done
echo "exit code: $rc" >> "$OUT"
cat "$OUT"
exit $rc
