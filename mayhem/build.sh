#!/usr/bin/env bash
#
# mayhem/build.sh — Linux-PAM: sanitized libpam + modules (meson) and the fuzz harnesses,
# plus a normal-flags build for the functional suite (meson test + mayhem/oracle).
# Re-runnable and offline: meson/ninja come from apt, nothing is fetched.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
M="$SRC/mayhem"
# pam_group and pam_namespace read the fixed path SCONFIG_DIR/<file>. The fuzz build points
# it at /proc/self/fd/$SCONF_FD, a descriptor each harness opens on its own mkdtemp scratch
# dir (pam_fuzz_common.h pf_init), so parallel fuzzer processes never share the file.
SCONF_FD=997
SCONF=/proc/self/fd/$SCONF_FD

COMMON_OPTS=(-Ddocs=disabled -Di18n=disabled -Dexamples=false -Dselinux=disabled
  -Daudit=disabled -Deconf=disabled -Dlogind=disabled -Delogind=disabled -Dnis=disabled
  -Dpam_userdb=disabled -Dpwaccess=disabled -Dopenssl=disabled -Dxtests=false)

# setup_or_reconfigure <builddir> <opts...>: idempotent meson setup (no wipe on re-run).
setup() {
  local dir="$1"; shift
  if [ -f "$dir/build.ninja" ]; then
    meson setup --reconfigure "$dir" "$@"
  else
    meson setup "$dir" "$@"
  fi
}

# 1) Sanitized + coverage-instrumented libpam and modules (pam_unix-try-getspnam: fuzz_pam_unix
#    mocks the shadow lookup so pam_unix verifies in-process instead of exec-ing unix_chkpwd).
#    Shared objects reference the
#    sanitizer/SanCov runtime that only the harness executable links, hence b_lundef=false.
# UBSan's pointer-overflow check is relaxed (only when sanitizers are on): libpam's
# pam_overwrite_string(NULL) computes NULL+0 in pam_end() for every handle, so it fires on
# every input. ASan and every other UBSan check stay on and halting.
RELAX=""
case "$SANITIZER_FLAGS" in *undefined*|*pointer-overflow*) RELAX="-fno-sanitize=pointer-overflow" ;; esac
FUZZ_CFLAGS="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
setup "$M/build-fuzz" "${COMMON_OPTS[@]}" -Dpam_unix-try-getspnam=true -Db_lundef=false -Dsconfigdir="$SCONF" \
  -Dbuildtype=plain -Dc_args="-O1 $FUZZ_CFLAGS" -Dc_link_args="$SANITIZER_FLAGS"
ninja -C "$M/build-fuzz" -j"$MAYHEM_JOBS"

# 2) Harnesses: fuzzer + standalone reproducer each, linked against the sanitized libpam.
mkdir -p "$M/out"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$M/lsan_off.cc" -o "$M/out/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$M/out/standalone_main.o"
HFLAGS=(-I"$SRC/libpam/include" -I"$SRC/libpam_misc/include" -I"$SRC/libpamc/include"
  -I"$M/build-fuzz" -DPAM_MODDIR="\"$M/build-fuzz/modules\"" -DPAM_FUZZ_SCONF_FD=$SCONF_FD)
LIBS=(-L"$M/build-fuzz/libpam" -lpam -Wl,-rpath,"$M/build-fuzz/libpam")
for h in "$M"/harnesses/fuzz_*.c; do
  name=$(basename "$h" .c)
  # harnesses that mock libc calls (PF_INTERPOSE) export them so the modules bind to them
  extra=(); grep -q PF_INTERPOSE "$h" && extra=(-rdynamic)
  # misc_conv lives in libpam_misc
  grep -q 'security/pam_misc.h' "$h" && extra+=(-L"$M/build-fuzz/libpam_misc" -lpam_misc
    -Wl,-rpath,"$M/build-fuzz/libpam_misc")
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${HFLAGS[@]}" $RELAX -c "$h" -o "$M/out/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$M/out/$name.o" "$M/out/lsan_off.o" \
    "${LIBS[@]}" "${extra[@]}" -ldl -o "$M/out/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$M/out/standalone_main.o" "$M/out/$name.o" \
    "$M/out/lsan_off.o" "${LIBS[@]}" "${extra[@]}" -ldl -o "$M/out/$name-standalone"
done

# 3) Functional suite with the project's normal flags: upstream's meson tests + the
#    known-answer oracle in mayhem/oracle.
TEST_OPTS=("${COMMON_OPTS[@]}")
[ -z "$COVERAGE_FLAGS" ] || TEST_OPTS+=(-Dc_args="$COVERAGE_FLAGS" -Dc_link_args="$COVERAGE_FLAGS")
CFLAGS= LDFLAGS= setup "$M/build-test" "${TEST_OPTS[@]}"
ninja -C "$M/build-test" -j"$MAYHEM_JOBS"
$CC -O2 $COVERAGE_FLAGS -I"$SRC/libpam/include" -I"$M/build-test" "$M/oracle/pam_oracle.c" \
  -L"$M/build-test/libpam" -lpam -Wl,-rpath,"$M/build-test/libpam" -o "$M/out/pam_oracle"
echo "build.sh: done"
