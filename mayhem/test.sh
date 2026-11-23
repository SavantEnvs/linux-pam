#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

M="$SRC/mayhem"
[ -f "$M/build-test/build.ninja" ] && [ -x "$M/out/pam_oracle" ] || { echo "test build missing: run mayhem/build.sh" >&2; emit_ctrf meson-test 0 1; exit 1; }

# 1) upstream's own suite (tst-* programs), already built by build.sh
log=$(mktemp)
meson test -C "$M/build-test" --no-rebuild --print-errorlogs 2>&1 | tee "$log"
ok=$(sed -n 's/^Ok: *\([0-9]*\).*/\1/p' "$log" | tail -1)
fail=$(sed -n 's/^Fail: *\([0-9]*\).*/\1/p' "$log" | tail -1)
xpass=$(sed -n 's/^Unexpected Pass: *\([0-9]*\).*/\1/p' "$log" | tail -1)
tout=$(sed -n 's/^Timeout: *\([0-9]*\).*/\1/p' "$log" | tail -1)
skip=$(sed -n 's/^Skipped: *\([0-9]*\).*/\1/p' "$log" | tail -1)
xfail=$(sed -n 's/^Expected Fail: *\([0-9]*\).*/\1/p' "$log" | tail -1)
passed=$(( ${ok:-0} + ${xfail:-0} ))
failed=$(( ${fail:-0} + ${xpass:-0} + ${tout:-0} ))
[ -n "$ok" ] || failed=$(( failed + 1 ))   # no summary = the runner itself broke

# 2) known-answer checks of the modules through the public API (golden output)
scratch=$(mktemp -d)
if "$M/out/pam_oracle" "$M/build-test/modules" "$scratch" > "$scratch/actual.txt" \
   && diff -u "$M/oracle/expected.txt" "$scratch/actual.txt"; then
  passed=$(( passed + 1 ))
else
  echo "pam_oracle: output differs from mayhem/oracle/expected.txt" >&2
  failed=$(( failed + 1 ))
fi
rm -rf "$scratch" "$log"
emit_ctrf meson-test "$passed" "$failed" "${skip:-0}"
