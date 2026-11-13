#!/usr/bin/env bash
# mayhem/build.sh: builds pmacct twice (sanitized for the fuzz harnesses, normal flags for the test oracle),
# then links the fuzz targets and their -standalone reproducers into /mayhem. Offline and re-runnable.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

# libcdada is pre-built into the image (mayhem/Dockerfile); pkg-config must not find anything else.
CDADA=/opt/toolchains/deps/libcdada-0.6.4
export PKG_CONFIG_PATH=

# pmacct's configure script is generated; regenerate it so this works after `git clean -ffdX`.
./autogen.sh > /tmp/pmacct-autogen.log 2>&1 || { tail -30 /tmp/pmacct-autogen.log; exit 1; }

# 1) Test/oracle build: the project's normal flags, no sanitizers.
mkdir -p mayhem/build-test
(cd mayhem/build-test \
  && env -u CFLAGS -u LDFLAGS ../../configure --without-external-deps --disable-shared CC="$CC" \
       CFLAGS="-O2 $COVERAGE_FLAGS -I$CDADA/include" LDFLAGS="$COVERAGE_FLAGS -L$CDADA/lib" > configure.log 2>&1 \
  && make -j"$MAYHEM_JOBS" > make.log 2>&1) || { tail -30 mayhem/build-test/configure.log mayhem/build-test/make.log; exit 1; }

# 2) Sanitized build of the project itself. UBSan's alignment and function checks are relaxed: pmacct's parsers read packed
#    wire structs through casts of arbitrary buffer offsets, and its hash tables call comparators through
#    differently-typed function pointers; both fire on nearly every input.
mkdir -p mayhem/build-fuzz
FUZZ_CFLAGS="$SANITIZER_FLAGS -fno-sanitize=alignment,function $DEBUG_FLAGS -fsanitize=fuzzer-no-link -I$CDADA/include"
(cd mayhem/build-fuzz \
  && env -u CFLAGS -u LDFLAGS ../../configure --without-external-deps --disable-shared CC="$CC" \
       CFLAGS="$FUZZ_CFLAGS" LDFLAGS="-L$CDADA/lib" > configure.log 2>&1 \
  && make -j"$MAYHEM_JOBS" > make.log 2>&1) || { tail -30 mayhem/build-fuzz/configure.log mayhem/build-fuzz/make.log; exit 1; }

# 3) Harness objects (compiled with the project's flags), LSan hook, then link each target.
cd mayhem/build-fuzz/src
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o lsan_off.o
make -s -f "$SRC/mayhem/harness.mk" harness_bmp.o harness_bgp.o harness_netflow.o nfacctd_lib.o

LIBS="libdaemons.la -L$CDADA/lib -lcdada -lstdc++ -lpcap -ldl -lm -lpthread"
link() { # link <name> <objects> <engine-or-main> <output>
  local name="$1" objs="$2" main="$3" out="$4"
  /bin/bash ../libtool --silent --tag=CC --mode=link "$CC" -O2 $SANITIZER_FLAGS $DEBUG_FLAGS $main \
    -o "$out" $objs lsan_off.o $LIBS
}
for t in bmp bgp netflow; do
  objs="harness_$t.o"
  [ "$t" = netflow ] && objs="$objs nfacctd_lib.o"
  link "$t" "$objs" "$LIB_FUZZING_ENGINE" "/mayhem/$t"
  link "$t" "$objs" "$STANDALONE_FUZZ_MAIN" "/mayhem/$t-standalone"
done
