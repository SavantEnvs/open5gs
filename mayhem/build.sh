#!/usr/bin/env bash
#
# open5gs/mayhem/build.sh — MINING layer (mine-d2707b0): builds the SBI multipart harness
# (mayhem/harnesses/sbi-multipart-fuzz.c) as a sanitized libFuzzer target (+ standalone reproducer),
# plus the gtp/nas libs that mayhem/test.sh's oracle links. Below, the original two-harness notes:
#
# Fuzzed surface (attacker-controlled bytes off the wire, NOT files):
#   nas_message_fuzz — ogs_nas_emm_decode(): the EPS NAS / EMM+ESM message decoder. byte0 is the
#                      security-header|protocol-discriminator, byte1 the message type; the rest is the
#                      per-message IE soup (TLV/TV/LV). Links libnas_eps_dep (lib/nas/{common,eps}).
#   gtp_message_fuzz — ogs_gtp2_parse_msg(): the GTPv2-C message/IE parser used on S5/S8/S11. Header
#                      (flags|type|length|TEID|seq) + TLV IEs. Links libgtp_dep (lib/gtp + proto/core).
#
# open5gs builds with meson; the fuzzers only LINK the protocol libs (core/proto/app/ipfw + nas/gtp),
# NOT mongodb / the SBI/NF daemons. But the top-level `meson setup` CONFIGURES the whole project, so
# the apt deps in mayhem/Dockerfile must satisfy configure (gnutls/ssl/curl/microhttpd/nghttp2/mongoc/
# sctp/idn/tins/talloc/yaml). We then `ninja` ONLY the two fuzzer targets, so the heavy NF code is
# never compiled or linked. `ninja -k 0` keeps going if an unrelated target would fail.
#
# Build contract from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/STANDALONE_FUZZ_MAIN.
# We pass $SANITIZER_FLAGS through meson's CFLAGS so the protocol libraries (the fuzzed code) are
# instrumented with ASan+UBSan, not just the harness.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS= builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# DEBUG_FLAGS: explicit DWARF-3 so Mayhem triage can read symbols (clang-19 defaults to DWARF-5).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
export DEBUG_FLAGS
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# COVERAGE_FLAGS: SanitizerCoverage for the fuzzed code — REQUIRED, and easy to lose here.
# $LIB_FUZZING_ENGINE (-fsanitize=fuzzer) reaches the compiler ONLY as meson's `lib_fuzzing_engine`
# option, which meson splices into the fuzzer target's *link_args*. At link time it supplies the
# libFuzzer driver/main but instruments nothing: SanCov is a codegen pass, so it must be on the
# COMPILE line of every object we want coverage from. Without -fsanitize=fuzzer-no-link in CFLAGS
# no object carries edge counters — the binary has no __sancov_* sections, libFuzzer starts and
# warns "no interesting inputs were found so far. Is the code instrumented for coverage?", burns
# ~200k execs/s finding nothing, and every Mayhem run ends `failed=false` at edges_covered=0. That
# is a silent hard failure of the integrated gate (SPEC §6.2 item 11) that docker build, fuzz-smoke
# and a green CI job all pass. Keep this on the compile line for BOTH builds below so the
# standalone reproducer stays coverage-capable too (the callbacks come from the ASan runtime).
: "${COVERAGE_FLAGS:=-fsanitize=fuzzer-no-link}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"

SRC="${SRC:-/mayhem}"
OUT="/mayhem"
cd "$SRC"

# open5gs's headers split a macro across tokens and use printf-style logging clang -Werror trips on;
# the upstream OSS-Fuzz build.sh suppresses exactly these. -Wno-error keeps a benign upstream warning
# (it floods otherwise) from failing the build.
EXTRA_C="-Wno-compound-token-split-by-macro -Wno-format -Wno-error -fcommon"

# Sanitizer relaxation (the ONE benign-UB relaxation allowed): open5gs's NAS decoder reaches the ESM
# message container IE by casting the raw, unaligned pkbuf cursor straight to
# `ogs_nas_esm_message_container_t *` (lib/nas/eps/ies.c:810). On x86 this load is harmless, but
# UBSan's `alignment` check fires on it for essentially every NAS message that carries an ESM
# container — including upstream's OWN seed corpus (nas-message-seed.1/2.raw). Left on, it would halt
# the run on the very first interesting input and mask real bugs. Drop ONLY the `alignment` check;
# every other UBSan check and all of ASan stay halting (-fno-sanitize-recover=all is still in force).
SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=alignment"

# Second benign-UB relaxation, same character as the alignment one above and needed for the same
# reason. The vendored asn1c PER runtime opens an open-type chunk with `uint8_t *buf = 0; size_t
# bufLen = 0;` and, when the first chunk length decodes as 0, skips the REALLOC branch and calls
# `per_get_many_bits(pd, buf + bufLen, 0, 0)` (lib/asn1c/common/aper_opentype.c:43). That is a literal
# `NULL + 0`: UB by the letter of C, completely harmless in practice (0 bits are read, nothing is
# dereferenced). UBSan's `pointer-overflow` check fires on it for the all-zero 5-byte input — which is
# in upstream's OWN ngap/s1ap seed corpus — so with -fno-sanitize-recover=all the process aborts on
# seed #1 of every run. Both APER targets (ngap_message_fuzz, s1ap_message_fuzz) then die before
# covering anything, which is precisely the 0-edge integrated-gate failure this relaxation exists to
# avoid, and it masks every real ASN.1 bug behind it. Drop ONLY `pointer-overflow`; ASan and every
# other UBSan check stay halting.
SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=pointer-overflow"
export CC CXX
# $DEBUG_FLAGS (-g -gdwarf-3) after $SANITIZER_FLAGS so DWARF-3 overrides the -g inside SANITIZER_FLAGS.
export CFLAGS="$SANITIZER_FLAGS $COVERAGE_FLAGS $DEBUG_FLAGS $EXTRA_C"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="$SANITIZER_FLAGS $COVERAGE_FLAGS $DEBUG_FLAGS"

FUZZERS="sbi_multipart_fuzz"
# Libraries the functional oracle (mayhem/test.sh) links: built by the upstream-provided harness targets.
ORACLE_DEPS="tests/fuzzing/gtp_message_fuzz tests/fuzzing/nas_message_fuzz"

# ── 0a) the mining harness enters the meson tree ─────────────────────────────────────────────────
# BASE has no SBI harness. mayhem/harnesses/sbi-multipart-fuzz.c (builds a multipart response through
# ogs_sbi_build_response -> build_multipart) is registered by appending an executable() to
# tests/fuzzing/meson.build for the duration of this build only; the tracked file is restored at the end.
MESON_FILE="$SRC/tests/fuzzing/meson.build"
cp "$MESON_FILE" "$SRC/meson.build.fuzzing.orig"
cat >> "$MESON_FILE" <<'MESON'

executable(
    'sbi_multipart_fuzz',
    sources : files('../../mayhem/harnesses/sbi-multipart-fuzz.c'),
    c_args : [testunit_core_cc_flags, sbi_cc_flags],
    dependencies : [libsbi_dep, libcore_dep],
    link_args: lib_fuzzing_engine
)
MESON
restore_meson() { [ -f "$SRC/meson.build.fuzzing.orig" ] && mv -f "$SRC/meson.build.fuzzing.orig" "$MESON_FILE"; return 0; }
trap restore_meson EXIT

# ── 0) LeakSanitizer off, at build time ──────────────────────────────────────────────────────────
# LSan ptrace-attaches at exit, which collides with Mayhem's own tracer (0-edge "Run Failed").
# mayhem/lsan_off.cc defines __lsan_is_turned_off(); it is linked into every fuzzer via meson's
# project-wide c_link_args. ASan and UBSan stay on and halting.
ASAN_OBJ="${TMPDIR:-/tmp}/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$ASAN_OBJ"

# ── 0b) meson subprojects, from the in-image cache (the build re-runs offline) ───────────────────
# mayhem/Dockerfile clones the wrap-git subprojects the configure step needs to $SUBPROJECTS_CACHE.
: "${SUBPROJECTS_CACHE:=/opt/open5gs-subprojects}"
for d in freeDiameter prometheus-client-c; do
  [ -d "$SRC/subprojects/$d" ] || cp -a "$SUBPROJECTS_CACHE/$d" "$SRC/subprojects/$d"
done

# ── 1) libFuzzer targets ───────────────────────────────────────────────────────────────────────
# --default-library=static so the fuzzer binaries embed the protocol libs (self-contained); talloc
# resolves transitively from libogscore's pkg-config (no need to spell it out). lib_fuzzing_engine is
# passed as a meson STRING option that becomes the fuzzer's link_args, so it must be a SINGLE clang
# argument (e.g. -fsanitize=fuzzer) — appending extra libs here makes clang treat the whole string as
# one bad '-fsanitize=' value.  Instead we inject lsan_off.o via -Dc_link_args (project-wide
# link args, independent of the per-target lib_fuzzing_engine option).
BD="$SRC/mayhem-build"
rm -rf "$BD"
meson setup "$BD" --default-library=static -Dfuzzing=true \
  -Dlib_fuzzing_engine="$LIB_FUZZING_ENGINE" \
  -Dc_link_args="$ASAN_OBJ"
ninja -C "$BD" -k 0 -j"$MAYHEM_JOBS" \
  $ORACLE_DEPS tests/fuzzing/sbi_multipart_fuzz
for f in $FUZZERS; do
  cp "$BD/tests/fuzzing/$f" "$OUT/$f"
  echo "built libFuzzer target: $OUT/$f"
done

# ── 2) standalone reproducers ────────────────────────────────────────────────────────────────────
# Re-run the SAME meson config but point lib_fuzzing_engine at the StandaloneFuzzTargetMain object
# (a run-once driver: feeds each argv file to LLVMFuzzerTestOneInput, no libFuzzer runtime).
SBD="$SRC/mayhem-standalone"
rm -rf "$SBD"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/standalone_main.o"
# Same single-token rule as above: lib_fuzzing_engine becomes the fuzzer's link_args verbatim, so
# point it at the standalone driver object alone.  lsan_off.o still baked in via c_link_args.
meson setup "$SBD" --default-library=static -Dfuzzing=true \
  -Dlib_fuzzing_engine="$SRC/standalone_main.o" \
  -Dc_link_args="$ASAN_OBJ"
ninja -C "$SBD" -k 0 -j"$MAYHEM_JOBS" \
  $ORACLE_DEPS tests/fuzzing/sbi_multipart_fuzz
for f in $FUZZERS; do
  cp "$SBD/tests/fuzzing/$f" "$OUT/$f-standalone"
  echo "built standalone reproducer: $OUT/$f-standalone"
done

# ── 3) test suite for mayhem/test.sh ───────────────────────────────────────────────────────────────
# test.sh runs a self-contained golden oracle over the parse path (mayhem/test.sh compiles + runs it
# against the libFuzzer targets' own libs). Nothing to pre-build here beyond the fuzzers above; the
# oracle reuses the libFuzzer binaries (it replays known PDUs through them in standalone form).

echo "build.sh complete:"
ls -la $(for f in $FUZZERS; do echo "$OUT/$f" "$OUT/$f-standalone"; done) 2>&1 || true
