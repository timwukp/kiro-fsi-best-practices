#!/usr/bin/env bash
# test-policy.sh - regression tests for the admin policy files (bash + jq; read-only, no network).
#
#   bash managed-settings/tests/test-policy.sh
#
# Structure: both policy files carry the same rules apart from the sign-in rule; only deny/ask and
# the documented fields; no backslash in any pattern (an unescaped one is invalid JSON, and Kiro
# does not document its meaning in a pattern); shell patterns use only "*" and end with "*"; the
# rule table in managed-settings/README.md lists the rules in file order.
# Vectors (tests/shell-vectors.tsv): the effect the shell rules give a command under the documented
# semantics ("*" matches any sequence of characters, against the whole command). This simulates the
# matching; it does not drive a Kiro client. Verify real behaviour on a pilot machine. Every shell
# rule needs at least one vector. The README check compares rule number, capability and effect; the
# pattern summaries in the table are prose and are reviewed by hand.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; DIR="$(cd "$HERE/.." && pwd)"
A="$DIR/managed-settings.banking.json"; B="$DIR/managed-settings.option-b.json"
command -v jq >/dev/null 2>&1 || { echo "test-policy: jq is required"; exit 1; }
PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
check() { if [ "$2" = true ]; then ok; else bad "$1"; fi; }

echo "== structure"
check "Option A and Option B rules differ beyond rule 1" \
  "$(jq -n --slurpfile a "$A" --slurpfile b "$B" '$a[0].rules[1:] == $b[0].rules[1:]')"
for f in "$A" "$B"; do
  n="$(basename "$f")"
  check "$n: effects must be deny or ask" "$(jq '[.rules[].effect] | all(. == "deny" or . == "ask")' "$f")"
  check "$n: unknown rule field" "$(jq '[.rules[] | keys[]] | all(. == "capability" or . == "match" or . == "exclude" or . == "effect")' "$f")"
  check "$n: a pattern contains a backslash" "$(jq '[.rules[] | (.match // [])[], (.exclude // [])[]] | all(contains("\\") | not)' "$f")"
  check "$n: a shell pattern uses ? or ** or does not end with *" \
    "$(jq '[.rules[] | select(.capability == "shell") | (.match // [])[], (.exclude // [])[]] | all(endswith("*") and (contains("?") | not) and (contains("**") | not))' "$f")"
  check "$n: a shell pattern starts with *" "$(jq '[.rules[] | select(.capability == "shell") | .match[]] | all(startswith("*") | not)' "$f")"
  check "$n: duplicate pattern inside a rule" "$(jq '[.rules[] | (.match // []) | length == (unique | length)] | all' "$f")"
done
readme="$(grep -E '^\| [0-9]+ \| `[a-z_]+` / (deny|ask) ' "$DIR/README.md" | sed -E 's/^\| ([0-9]+) \| `([a-z_]+)` \/ (deny|ask) .*/\1 \2 \3/')"
json="$(jq -r '.rules | to_entries[] | "\(.key + 1) \(.value.capability) \(.value.effect)"' "$A")"
if [ "$readme" = "$json" ]; then ok; else bad "README.md rule table does not match the rule order in managed-settings.banking.json"; fi

echo "== shell vectors"
effect() { # command file -> deny | ask | none
  jq -r --arg c "$1" '
    def re: gsub("(?<c>[\\\\.^$+?()\\[\\]{}|])"; "\\\(.c)") | gsub("\\*"; ".*") | "^" + . + "$";
    def hit($pats): any($pats[]; . as $p | $c | test($p | re));
    [.rules[] | select(.capability == "shell")
      | select(hit(.match // []) and (hit(.exclude // []) | not)) | .effect]
    | if index("deny") then "deny" elif index("ask") then "ask" else "none" end' "$2"
}
VECTORS=0
while IFS=$'\t' read -r expected cmd || [ -n "${expected:-}" ]; do
  case "$expected" in ''|\#*) continue ;; esac
  case "$expected" in deny|ask|none) ;; *) bad "shell-vectors.tsv: unknown expected effect [$expected]"; continue ;; esac
  [ -n "${cmd:-}" ] || { bad "shell-vectors.tsv: row [$expected] has no command"; continue; }
  VECTORS=$((VECTORS + 1))
  for f in "$A" "$B"; do
    got="$(effect "$cmd" "$f")"
    if [ "$got" = "$expected" ]; then ok; else bad "$(basename "$f"): [$cmd] expected $expected, got $got"; fi
  done
done < "$HERE/shell-vectors.tsv"
if [ "$VECTORS" -ge 60 ]; then ok; else bad "only $VECTORS vectors were read from shell-vectors.tsv (expected at least 60)"; fi
# Every shell rule must be exercised by at least one vector that it alone can explain.
for f in "$A"; do
  n="$(jq '[.rules[] | select(.capability == "shell")] | length' "$f")"
  i=0
  while [ "$i" -lt "$n" ]; do
    hit=0
    while IFS=$'\t' read -r expected cmd || [ -n "${expected:-}" ]; do
      case "$expected" in deny|ask) ;; *) continue ;; esac
      if jq -e --arg c "$cmd" --argjson i "$i" '
          def re: gsub("(?<c>[\\\\.^$+?()\\[\\]{}|])"; "\\\(.c)") | gsub("\\*"; ".*") | "^" + . + "$";
          [.rules[] | select(.capability == "shell")][$i] | any(.match[]; . as $p | $c | test($p | re))' "$f" >/dev/null 2>&1; then hit=1; break; fi
    done < "$HERE/shell-vectors.tsv"
    if [ "$hit" = 1 ]; then ok; else bad "no vector exercises shell rule #$((i + 1)) (counting shell rules only) in $(basename "$f")"; fi
    i=$((i + 1))
  done
done

echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
