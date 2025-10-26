#!/bin/sh
# Author: Daniel Starke
# Date: 2025-09-01
# Notes:
# Built on Linux. Tested with Debian 12.10.0.
# Installed build dependencies:
# sudo apt install -y p7zip-full build-essential bison flex texinfo texlive texlive-plain-generic cmake licensecheck help2man gengetopt osslsigncode opensc pcscd
# Target distribution has the following directory structure:
# bin                   # user applications (e.g. gcc)
# i686-w64-mingw32      # x86 target directory
#   include             # x86 specific headers
#   lib                 # x86 specific libraries
# include               # target independent headers
# share                 # help files and GDB specific data
#   gdb
#     python            # Python library path for GDB
#   license             # copyright and license overview
#   opensc              # OpenSC specific data
#   source-highlight
#     esc.style         # GDB syntax highlighting color schema
#   ssl                 # OpenSSL specific data
#   terminfo            # GDB TUI terminal information database (ncurses)
# x86_64-w64-mingw32    # x64 target directory and build tools
#   bin                 # x64 hosted build tools
#   include             # x64 specific headers
#   lib                 # x64 specific libraries

# directories
ROOT="$(pwd)"         # root directory
PREFIX='/mingw64-64'  # target directory
SRC="${ROOT}/src"     # source directory
BUILD="${ROOT}/build" # temporary build directory
HOST="${ROOT}/host"   # temporary cross-compiler root
LICENSE="${PREFIX}/share/license" # target license directory

# packet versions
ZLIB='zlib-1.3.1'                       # https://zlib.net/
GMP='gmp-6.3.0'                         # https://gmplib.org/
MPFR='mpfr-4.2.2'                       # https://www.mpfr.org/
MPC='mpc-1.2.1'                         # https://www.multiprecision.org/mpc/
ISL='isl-0.27'                          # https://libisl.sourceforge.io/ or https://gcc.gnu.org/pub/gcc/infrastructure/
CLOOG_ISL='cloog-0.21.1'                # https://github.com/periscop/cloog or http://www.bastoul.net/cloog/
BINUTILS='binutils-2.45'                # https://ftp.gnu.org/gnu/binutils/
MINGW='mingw-w64-v13.0.0'               # https://sourceforge.net/projects/mingw-w64/
GCC='gcc-15.2.0'                        # https://gcc.gnu.org/
EXPAT='expat-2.7.1'                     # https://libexpat.github.io/
NCURSES='ncurses-6.5'                   # https://ftp.gnu.org/gnu/ncurses/
BOOST='boost_1_89_0'                    # https://www.boost.org/
HIGHLIGHT='source-highlight-3.1.9'      # https://ftp.gnu.org/gnu/src-highlite/
IPT='libipt-2.1.2'                      # https://github.com/intel/libipt
WINIPT='winipt-c78e5616'                # https://github.com/ionescu007/winipt
XXHASH='xxHash-0.8.3'                   # https://github.com/Cyan4973/xxHash
FFI='libffi-3.5.2'                      # https://github.com/libffi/libffi
ICONV='libiconv-1.18'                   # https://www.gnu.org/software/libiconv/
PYTHON='Python-3.13.7'                  # https://www.python.org/downloads/source/
GDB='gdb-gdb-16.3.90.20250511'          # https://github.com/ssbssa/gdb
# optional extras (comment out if unneeded)
ZSTD='zstd-1.5.7'                       # https://github.com/facebook/zstd/releases
OCL_SDK='OpenCL-SDK-v2025.07.23-Source' # https://github.com/KhronosGroup/OpenCL-SDK
OPENSSL='openssl-3.4.2'                 # https://openssl-library.org/source/
P11='libp11-0.4.16'                     # https://github.com/OpenSC/libp11/
SC_HSM_EMBED='sc-hsm-embedded-2.12'     # https://github.com/CardContact/sc-hsm-embedded/
OPENPACE='openpace-1.1.3'               # https://github.com/frankmorgner/openpace/releases
OPENSC='OpenSC-0.26.1'                  # https://github.com/OpenSC/OpenSC/ (without manufacturer specific tools)
OSSLSIGNCODE='osslsigncode-2.10'        # https://github.com/mtrojnar/osslsigncode/releases
#SIGN=''                                 # path to script which accepts a single file as argument for code signing

# build configuration
GCC_LANGS='c,c++,lto'
GCC_HOST_CONFIG='--enable-seh-exceptions --with-arch=core2 --with-tune=generic --enable-threads=posix --disable-nls --disable-libstdcxx-verbose --disable-libstdcxx-pch --enable-clocale=generic --enable-shared=libstdc++ --enable-static --enable-libatomic --enable-fully-dynamic-string --enable-lto --enable-plugins --enable-libgomp --with-dwarf2 --disable-win32-registry --enable-version-specific-runtime-libs --enable-checking=release'
GCC_TARGET_CONFIG='--enable-seh-exceptions --with-arch=core2 --with-tune=generic --enable-threads=posix --disable-nls --disable-libstdcxx-verbose --disable-libstdcxx-pch --enable-clocale=generic --enable-shared=libstdc++ --enable-static --enable-libatomic --enable-fully-dynamic-string --enable-lto --enable-plugins --enable-libgomp --with-dwarf2 --enable-mingw-wildcard=platform --disable-win32-registry --enable-version-specific-runtime-libs --enable-checking=release'
MCRTDLL='ucrt' # default: msvcrt-os
THREADS=$(nproc)
LOG="${ROOT}/build-mingw64.log"

export LANG='C'
export LC_ALL='C'
export CFLAGS='-std=gnu17 -O2 -march=core2 -mtune=generic -fno-ident -mstackrealign -fomit-frame-pointer -fno-strict-aliasing -Wno-maybe-uninitialized'
export CXXFLAGS='-O2 -march=core2 -mtune=generic -fno-ident -mstackrealign -fomit-frame-pointer -fno-strict-aliasing -Wno-maybe-uninitialized'
export LDFLAGS='-s -Wl,-no-undefined' # no debug symbols

# commands
alias rcp='cp'
cp --help | grep -q reflink && alias rcp='cp --reflink=auto'

STEP_START=${START:-1} # set START to skip until given step number
STEP_I=1
STEP_N="$(grep -h "^\\(if \\)\\?step ['\"]" "${0}" | wc -l)"
step() {
	echo "\e[1mStep ${STEP_I}/${STEP_N}: ${*}\e[0m"
	STEP_I=$((STEP_I + 1))
	if [ "$STEP_I" -le "$STEP_START" ]; then
		echo 'Skipped.'
		return 1
	fi
	return 0
}

error() {
	echo "\e[1;31mError: ${*}\e[0m" >&2
	exit 1
}

download() {
	FILE="$1"
	URL="$(echo "$2" | sed "s/@FILE@/$1/g")"
	test -f "${SRC}/${FILE}" || wget --progress=bar:force:noscroll -O "${SRC}/${FILE}" "${URL}" >>"${LOG}" 2>&1 || error "Failed to download ${FILE} from ${URL}."
}

verify() {
	INPUT="$(basename "$1")"
	cd "${SRC}" || error "Unknown directory ${SRC}."
	echo "Verifying SHA256 of ${SRC}/${INPUT}." >>"${LOG}" 2>&1
	cat <<"_EOF" | grep -e "^[0-9a-f]\{64\}  ${INPUT}\$" | sha256sum --check --status >>"${LOG}" 2>&1 || error "Failed to verify ${INPUT}."
c50c0e7f9cb188980e2cc97e4537626b1672441815587f1eab69d2a1bfbef5d2  binutils-2.45.tar.xz
85a33fa22621b4f314f8e85e1a5e2a9363d22e4f4992925d4bb3bc631b5a0c7a  boost_1_89_0.tar.bz2
d370cf9990d2be24bfb24750e355bac26110051248cabf2add61f9b3867fb1d7  cloog-0.21.1.tar.gz
354552544b8f99012e5062f7d570ec77f14b412a3ff5c7d8d0dae62c0d217c30  expat-2.7.1.tar.xz
a6e21868ead545cf87f0c01f84276e4b5281d672098591c1c896241f09363478  gcc-11.5.0.tar.xz
71cd373d0f04615e66c5b5b14d49c1a4c1a08efa7b30625cd240b11bab4062b3  gcc-12.5.0.tar.xz
9c4ce6dbb040568fdc545588ac03c5cbc95a8dbf0c7aa490170843afb59ca8f5  gcc-13.4.0.tar.xz
e0dc77297625631ac8e50fa92fffefe899a4eb702592da5c32ef04e2293aca3a  gcc-14.3.0.tar.xz
e2b09ec21660f01fecffb715e0120265216943f038d0e48a9868713e54f06cea  gcc-15.1.0.tar.xz
438fd996826b0c82485a29da03a72d71d6e3541a83ec702df4271f6fe025d24e  gcc-15.2.0.tar.xz
f2fdf827f9bc95736f6c6b5196bd0e1d6d3ad43568fe7e31989d94c363075a8a  gdb-gdb-16.3.90.20250511.tar.gz
a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898  gmp-6.3.0.tar.xz
6d8babb59e7b672e8cb7870e874f3f7b813b6e00e6af3f8b04f7579965643d5c  isl-0.27.tar.xz
f3a3082a23b37c293a4fcd1053147b371f2ff91fa7ea1b2a52e335676bac82dc  libffi-3.5.2.tar.gz
3b08f5f4f9b4eb82f151a7040bfd6fe6c6fb922efe4b1659c66ea933276965e8  libiconv-1.18.tar.gz
713d3e76b6c3073b122a9f5b6c025bc301a0436582f132caf782814363acf60f  libipt-2.1.2.tar.gz
97777640492fa9e5831497e5892e291dfbf39a7b119d9cb6abb3ec8c56d17553  libp11-0.4.16.tar.gz
ba8876404cbf250d4b40c80b4be335b1fbf92e69a161ce4af8a5c628903d31cc  mingw-w64-v13.0.0.zip
17503d2c395dfcf106b622dc142683c1199431d095367c6aacba6eec30340459  mpc-1.2.1.tar.gz
b67ba0383ef7e8a8563734e2e889ef5ec3c3b898a01d00fa0a6869ad81c6ce01  mpfr-4.2.2.tar.xz
136d91bc269a9a5785e5f9e980bc76ab57428f604ce3e5a5a90cebc767971cc6  ncurses-6.5.tar.gz
707fca9df630708e0e59a7d4a8a7a016c56c83a585957f0fd9f806c0762f1944  sc-hsm-embedded-2.12.tar.gz
29dc06da27d264d8e8592d0ba3e5d3d3ecefb3394f808e67b70ad3124b291a38  OpenCL-SDK-v2025.07.23-Source.zip
ef82a172d82e8300b91b4ec08df282292ac841f9233188e00554f56e97c2c089  openpace-1.1.3.tar.gz
5c4928bac2786dcaff9b2dfa43cd3de301bd137193a57adfb1a7a555656691ce  OpenSC-0.26.1.tar.gz
17b02459fc28be415470cccaae7434f3496cac1306b86b52c83886580e82834c  openssl-3.4.2.tar.gz
2a864e6127ee2350fb648070fa0d459c534ac6400ca0048886aeab7afb250f65  osslsigncode-2.10.tar.gz
5462f9099dfd30e238def83c71d91897d8caa5ff6ebc7a50f14d4802cdaaa79a  Python-3.13.7.tar.xz
3a7fd28378cb5416f8de2c9e77196ec915145d44e30ff4e0ee8beb3fe6211c91  source-highlight-3.1.9.tar.gz
e0c4c7fdbc6990b9158a8de0b18fdf444f78bd3e48456bc65cbc605cbe993251  winipt-c78e5616.zip
aae608dfe8213dfd05d909a57718ef82f30722c392344583d3f39050c7f29a80  xxHash-0.8.3.tar.gz
9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23  zlib-1.3.1.tar.gz
eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3  zstd-1.5.7.tar.gz
_EOF
}

extract() {
	INPUT="$1"
	cd "${SRC}" || error "Unknown directory ${SRC}."
	if [ "x${INPUT}" != "x${INPUT%.tar.gz}" ]; then
		test ! -d "${INPUT%.tar.gz}" && (tar xzf "${INPUT}" || error "Failed to extract ${INPUT}.")
	elif [ "x${INPUT}" != "x${INPUT%.tar.bz2}" ]; then
		test ! -d "${INPUT%.tar.bz2}" && (tar xjf "${INPUT}" || error "Failed to extract ${INPUT}.")
	elif [ "x${INPUT}" != "x${INPUT%.tar.xz}" ]; then
		test ! -d "${INPUT%.tar.xz}" && (tar xJf "${INPUT}" || error "Failed to extract ${INPUT}.")
	elif [ "x${INPUT}" != "x${INPUT%.zip}" ]; then
		test ! -d "${INPUT%.zip}" && (unzip "${INPUT}" >/dev/null || error "Failed to extract ${INPUT}.")
	else
		error "Unknown file extension in ${INPUT}. Extraction failed."
	fi
}

# check MCRTDLL value
case "${MCRTDLL}" in
	crtdll*|msvcrt10*|msvcrt20*|msvcrt40*|msvcr40*|msvcr70*|msvcr71*|msvcr80*|msvcr90*|msvcr100*|msvcr110*|msvcr120*|msvcrt-os*|msvcrtd*|ucrt*)
		;;
	*)
		error "Invalid value for MCRTDLL: ${MCRTDLL}."
		;;
esac

# check optional package dependencies
test "x${P11}" != 'x' -a "x${OPENSSL}" = 'x' && error "${P11} requires OpenSSL."
test "x${SC_HSM_EMBED}" != 'x' -a "x${OPENSSL}" = 'x' && error "${SC_HSM_EMBED} requires OpenSSL."
test "x${OPENSC}" != 'x' -a "x${OPENSSL}" = 'x' && error "${OPENSC} requires OpenSSL."
test "x${OSSLSIGNCODE}" != 'x' -a "x${OPENSSL}" = 'x' && error "${OSSLSIGNCODE} requires OpenSSL."

# create source directory
mkdir -p "${SRC}" || error "Failed to create ${SRC}."

# create log file
if [ "${STEP_START}" -eq 1 ]; then
	: >"${LOG}"
else
	: >>"${LOG}"
fi

if step 'download sources'; then
	EXPAT_RELEASE_TAG=$(echo "${EXPAT}" | awk 'BEGIN { FS="[-.]" } { print "R_" $2 "_" $3 "_" $4 }')
	BOOST_RELEASE_TAG=$(echo "${BOOST}" | awk 'BEGIN { FS="_" } { print $2 "." $3 "." $4 }')
	OCL_RELEASE_TAG=$(echo "${OCL_SDK}" | awk 'BEGIN { FS="-" } { print $3 }')
	download "${ZLIB}.tar.gz" "https://zlib.net/@FILE@"
	download "${GMP}.tar.xz" "https://gmplib.org/download/gmp/@FILE@"
	download "${MPFR}.tar.xz" "https://www.mpfr.org/${MPFR}/@FILE@"
	download "${MPC}.tar.gz" "https://www.multiprecision.org/downloads/@FILE@"
	download "${ISL}.tar.xz" "https://libisl.sourceforge.io/@FILE@"
	download "${CLOOG_ISL}.tar.gz" "https://github.com/periscop/cloog/releases/download/${CLOOG_ISL}/@FILE@"
	download "${BINUTILS}.tar.xz" "https://ftp.gnu.org/gnu/binutils/@FILE@"
	download "${MINGW}.zip" "https://sourceforge.net/projects/mingw-w64/files/mingw-w64/mingw-w64-release/@FILE@/download"
	download "${GCC}.tar.xz" "https://ftp.fu-berlin.de/unix/languages/gcc/releases/${GCC}/@FILE@"
	download "${EXPAT}.tar.xz" "https://github.com/libexpat/libexpat/releases/download/${EXPAT_RELEASE_TAG}/@FILE@"
	download "${NCURSES}.tar.gz" "https://ftp.gnu.org/gnu/ncurses/@FILE@"
	download "${BOOST}.tar.bz2" "https://archives.boost.io/release/${BOOST_RELEASE_TAG}/source/@FILE@"
	download "${HIGHLIGHT}.tar.gz" "https://ftp.gnu.org/gnu/src-highlite/@FILE@"
	download "${IPT}.tar.gz" "https://github.com/intel/libipt/archive/refs/tags/v${IPT#libipt-}.tar.gz"
	download "${WINIPT}.zip" "https://codeload.github.com/ionescu007/winipt/zip/${WINIPT#winipt-}"
	download "${XXHASH}.tar.gz" "https://github.com/Cyan4973/xxHash/archive/refs/tags/v${XXHASH#xxHash-}.tar.gz"
	download "${FFI}.tar.gz" "https://github.com/libffi/libffi/releases/download/v${FFI#libffi-}/@FILE@"
	download "${ICONV}.tar.gz" "https://ftp.gnu.org/pub/gnu/libiconv/@FILE@"
	download "${PYTHON}.tar.xz" "https://www.python.org/ftp/python/${PYTHON#Python-}/@FILE@"
	download "${GDB}.tar.gz" "https://github.com/ssbssa/gdb/archive/refs/tags/${GDB#gdb-}.tar.gz"
	[ "x${ZSTD}" != 'x' ] && download "${ZSTD}.tar.gz" "https://github.com/facebook/zstd/releases/download/v${ZSTD#zstd-}/@FILE@"
	[ "x${OCL_SDK}" != 'x' ] && download "${OCL_SDK}.zip" "https://github.com/KhronosGroup/OpenCL-SDK/releases/download/${OCL_RELEASE_TAG}/@FILE@"
	[ "x${OPENSSL}" != "x" ] && download "${OPENSSL}.tar.gz" "https://github.com/openssl/openssl/releases/download/${OPENSSL}/@FILE@"
	[ "x${P11}" != 'x' ] && download "${P11}.tar.gz" "https://github.com/OpenSC/libp11/releases/download/${P11}/@FILE@"
	[ "x${SC_HSM_EMBED}" != 'x' ] && download "${SC_HSM_EMBED}.tar.gz" "https://github.com/CardContact/sc-hsm-embedded/archive/refs/tags/V${SC_HSM_EMBED#sc-hsm-embedded-}.tar.gz"
	[ "x${OPENPACE}" != 'x' ] && download "${OPENPACE}.tar.gz" "https://github.com/frankmorgner/openpace/releases/download/${OPENPACE#openpace-}/@FILE@"
	[ "x${OPENSC}" != 'x' ] && download "${OPENSC}.tar.gz" "https://github.com/OpenSC/OpenSC/archive/refs/tags/${OPENSC#OpenSC-}.tar.gz"
	[ "x${OSSLSIGNCODE}" != 'x' ] && download "${OSSLSIGNCODE}.tar.gz" "https://github.com/mtrojnar/osslsigncode/archive/refs/tags/${OSSLSIGNCODE#osslsigncode-}.tar.gz"
fi

if step 'verify sources'; then
	verify "${SRC}/${ZLIB}".*
	verify "${SRC}/${GMP}".*
	verify "${SRC}/${MPFR}".*
	verify "${SRC}/${MPC}".*
	verify "${SRC}/${ISL}".*
	verify "${SRC}/${CLOOG_ISL}".*
	verify "${SRC}/${BINUTILS}".*
	verify "${SRC}/${MINGW}".*
	verify "${SRC}/${GCC}".*
	verify "${SRC}/${EXPAT}".*
	verify "${SRC}/${NCURSES}".*
	verify "${SRC}/${BOOST}".*
	verify "${SRC}/${HIGHLIGHT}".*
	verify "${SRC}/${IPT}".*
	verify "${SRC}/${WINIPT}".*
	verify "${SRC}/${XXHASH}".*
	verify "${SRC}/${FFI}".*
	verify "${SRC}/${ICONV}".*
	verify "${SRC}/${PYTHON}".*
	verify "${SRC}/${GDB}".*
	[ "x${ZSTD}" != 'x' ] && verify "${SRC}/${ZSTD}".*
	[ "x${OCL_SDK}" != 'x' ] && verify "${SRC}/${OCL_SDK}".*
	[ "x${OPENSSL}" != 'x' ] && verify "${SRC}/${OPENSSL}".*
	[ "x${P11}" != 'x' ] && verify "${SRC}/${P11}".*
	[ "x${SC_HSM_EMBED}" != 'x' ] && verify "${SRC}/${SC_HSM_EMBED}".*
	[ "x${OPENPACE}" != 'x' ] && verify "${SRC}/${OPENPACE}".*
	[ "x${OPENSC}" != 'x' ] && verify "${SRC}/${OPENSC}".*
	[ "x${OSSLSIGNCODE}" != 'x' ] && verify "${SRC}/${OSSLSIGNCODE}".*
fi

if step 'prepare sources'; then
	extract "${SRC}/${ZLIB}".*
	extract "${SRC}/${GMP}".*
	extract "${SRC}/${MPFR}".*
	extract "${SRC}/${MPC}".*
	extract "${SRC}/${ISL}".*
	extract "${SRC}/${CLOOG_ISL}".*
	extract "${SRC}/${BINUTILS}".*
	extract "${SRC}/${MINGW}".*
	extract "${SRC}/${GCC}".*
	extract "${SRC}/${EXPAT}".*
	extract "${SRC}/${NCURSES}".*
	extract "${SRC}/${BOOST}".*
	extract "${SRC}/${HIGHLIGHT}".*
	extract "${SRC}/${IPT}".*
	extract "${SRC}/${WINIPT}".*
	extract "${SRC}/${XXHASH}".*
	extract "${SRC}/${FFI}".*
	extract "${SRC}/${ICONV}".*
	extract "${SRC}/${PYTHON}".*
	extract "${SRC}/${GDB}".*
	[ "x${ZSTD}" != 'x' ] && extract "${SRC}/${ZSTD}".*
	[ "x${OCL_SDK}" != 'x' ] && extract "${SRC}/${OCL_SDK}".*
	[ "x${OPENSSL}" != 'x' ] && extract "${SRC}/${OPENSSL}".*
	[ "x${P11}" != 'x' ] && extract "${SRC}/${P11}".*
	[ "x${SC_HSM_EMBED}" != 'x' ] && extract "${SRC}/${SC_HSM_EMBED}".*
	[ "x${OPENPACE}" != 'x' ] && extract "${SRC}/${OPENPACE}".*
	[ "x${OPENSC}" != 'x' ] && extract "${SRC}/${OPENSC}".*
	[ "x${OSSLSIGNCODE}" != 'x' ] && extract "${SRC}/${OSSLSIGNCODE}".*
fi

if step 'remove previous build'; then
	test ! -d "${PREFIX}" || rm -rf "${PREFIX}/"* || error "Failed to delete ${PREFIX}."
	test ! -d "${BUILD}" || rm -rf "${BUILD}" || error "Failed to delete ${BUILD}."
	test ! -d "${HOST}" || rm -rf "${HOST}" || error "Failed to delete ${HOST}."
fi

if step 'prepare output directories'; then
	mkdir -p "${PREFIX}" || error "Failed to create ${PREFIX}."
	mkdir -p "${BUILD}" || error "Failed to create ${BUILD}."
	for p in "${HOST}" "${PREFIX}"; do
		for t in 'i686-w64-mingw32' 'x86_64-w64-mingw32'; do
			for d in 'include' 'lib/bfd-plugins'; do
				mkdir -p "${p}/${t}/${d}" || error "Failed to create ${p}/${t}/${d}."
			done
		done
	done
fi

if step 'patch GCC source'; then
	rm -rf "${BUILD}/gcc-src"
	rcp -r "${SRC}/${GCC}" "${BUILD}/gcc-src" || error "Failed to copy GCC source to ${BUILD}/gcc-src."
	cd "${BUILD}/gcc-src/gcc"
	MINGW32_H='config/i386/mingw32.h'
	test -f "${MINGW32_H}" || MINGW32_H='config/mingw/mingw32.h'
	# fix default include header path
	sed -i 's|/mingw/include|/x86_64-w64-mingw32/include|g' "${MINGW32_H}" || error "Failed to patch ${BUILD}/gcc-src/gcc/${MINGW32_H}."
	# change 32-bit default library path
	sed -i 's|/mingw/lib/|/i686-w64-mingw32/lib|g' "${MINGW32_H}" || error "Failed to patch ${BUILD}/gcc-src/gcc/${MINGW32_H}."
	# fix https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105506
	sed -i 's|-DUNICODE}|-DUNICODE} -D__USE_MINGW_ACCESS|g' 'config/i386/mingw-w64.h' || error "Failed to patch ${BUILD}/gcc-src/gcc/config/i386/mingw-w64.h."
	# fix multilib specific library paths
	sed -i 's|MULTILIB_OSDIRNAMES = .*|MULTILIB_OSDIRNAMES = /../../x86_64-w64-mingw32/lib /../../i686-w64-mingw32/lib|g' 'config/i386/t-mingw-w64' || error "Failed to patch ${BUILD}/gcc-src/gcc/config/i386/t-mingw-w64."
	# recycle binutils include path (unused anyway) for target independant include headers
	sed -i 's|{ TOOL_INCLUDE_DIR.*|{ PREFIX "include", "COMMON", 0, 0, 0, 0 },|g' 'cppdefault.cc' || error "Failed to patch ${BUILD}/gcc-src/gcc/cppdefault.cc."
	# fix target specific include paths
	awk -- "$(cat << '_PATCH'
BEGIN {
	ST = 0
}
/#ifdef LOCAL_INCLUDE_DIR/ {
	print "#if 0 // LOCAL_INCLUDE_DIR"
	next
}
/NATIVE_SYSTEM_HEADER_DIR, NATIVE_SYSTEM_HEADER_COMPONENT/ {
	if (ST == 0) {
		print "    { PREFIX \"x86_64-w64-mingw32/include\", NATIVE_SYSTEM_HEADER_COMPONENT \"64\", 0, 0, 0, 0 },"
		print "    { PREFIX \"i686-w64-mingw32/include\", NATIVE_SYSTEM_HEADER_COMPONENT \"32\", 0, 0, 0, 0 },"
		ST = 1
	}
	next
}
{
	print $0
}
_PATCH
)" 'cppdefault.cc' > 'cppdefault.cc.tmp' || error "Failed to patch ${BUILD}/gcc-src/gcc/cppdefault.cc."
	mv -f 'cppdefault.cc.tmp' 'cppdefault.cc' || error "Failed to replace ${BUILD}/gcc-src/gcc/cppdefault.cc."
	# use 'i686-w64-mingw32/include' for -m32 and 'x86_64-w64-mingw32/include' for -m64
	awk -- "$(cat << '_PATCH'
BEGIN {
	ST = 0
}
/^add_standard_paths/ {
	ST = 1
}
ST == 3 {
	# use different include header path for 32-bit and 64-bit builds
	print "      const bool isNativeComponent64 = p->component != NULL && strcmp(p->component, NATIVE_SYSTEM_HEADER_COMPONENT \"64\") == 0;"
	print "      const bool isNativeComponent32 = p->component != NULL && strcmp(p->component, NATIVE_SYSTEM_HEADER_COMPONENT \"32\") == 0;"
	print "      if ((isNativeComponent64 && imultilib) || (isNativeComponent32 && !imultilib)) continue;"
	ST = 4
}
ST == 2 {
	ST = 3
}
ST >= 1 && /cpp_include_defaults/ {
	ST = 2
}
/^}$/ {
	ST = 0
}
{
	print $0
}
_PATCH
)" 'incpath.cc' > 'incpath.cc.tmp' || error "Failed to patch ${BUILD}/gcc-src/gcc/incpath.cc."
	mv -f 'incpath.cc.tmp' 'incpath.cc' || error "Failed to replace ${BUILD}/gcc-src/gcc/incpath.cc."
	# enable -fuse-linker-plugin by default
	sed -i 's/Var(flag_use_linker_plugin)/Var(flag_use_linker_plugin) Init(1)/g' 'common.opt' || error "Failed to patch ${BUILD}/gcc-src/gcc/common.opt."
	# use architecture specific libstdc++.dll suffix
	cd "${BUILD}/gcc-src/libstdc++-v3"
	sed -i '/mingw/,/;;/{/soname_spec=/s/suffix}/suffix}'"'\$(echo \"\$CC\" | grep -q '[-]m32' \&\& echo -x86 || echo -x64)'"'/g}' 'configure' || error "Failed to patch ${BUILD}/gcc-src/libstdc++-v3/configure."
fi

if step "patch MinGW headers"; then
	rm -rf "${BUILD}/mingw-w64-headers"
	rcp -r "${SRC}/${MINGW}/mingw-w64-headers" "${BUILD}/mingw-w64-headers" || error "Failed to copy MinGW headers to ${BUILD}/mingw-w64-headers."
	cd "${BUILD}/mingw-w64-headers"
	# patches required for OpenSC minidriver
	cat << '_EOF' >'include/cardmod.h' || error "Failed to patch ${MINGW}/include/cardmod.h."
/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */

#ifndef _INC_CARDMOD
#define _INC_CARDMOD
#include <windows.h>
#include <wincrypt.h>
#include <winscard.h>
#include <specstrings.h>
#include <bcrypt.h>

#define CARD_DATA_VALUE_UNKNOWN ((DWORD)-1)

#define CARD_RETURN_KEY_HANDLE 0x1000000

#define CARD_BUFFER_SIZE_ONLY     0x20000000
#define CARD_PADDING_INFO_PRESENT 0x40000000

#define CARD_PADDING_NONE  1
#define CARD_PADDING_PKCS1 2
#define CARD_PADDING_PSS   4
#define CARD_PADDING_OAEP  8

#define CARD_CACHE_FILE_CURRENT_VERSION                    1
#define CARD_CAPABILITIES_CURRENT_VERSION                  1
#define CONTAINER_INFO_CURRENT_VERSION                     1
#define PIN_CACHE_POLICY_CURRENT_VERSION                   6
#define PIN_INFO_CURRENT_VERSION                           6
#define PIN_INFO_REQUIRE_SECURE_ENTRY                      1
#define CARD_FILE_INFO_CURRENT_VERSION                     1
#define CARD_FREE_SPACE_INFO_CURRENT_VERSION               1
#define CARD_KEY_SIZES_CURRENT_VERSION                     1
#define CARD_RSA_KEY_DECRYPT_INFO_VERSION_ONE              1
#define CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO              2
#define CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION          CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO
#define CARD_SIGNING_INFO_BASIC_VERSION                    1
#define CARD_SIGNING_INFO_CURRENT_VERSION                  2
#define CARD_DH_AGREEMENT_INFO_VERSION                     2
#define CARD_DERIVE_KEY_VERSION                            1
#define CARD_DERIVE_KEY_VERSION_TWO                        2
#define CARD_DERIVE_KEY_CURRENT_VERSION                    CARD_DERIVE_KEY_VERSION_TWO
#define CARD_IMPORT_KEYPAIR_VERSION_SEVEN                  7
#define CARD_IMPORT_KEYPAIR_CURRENT_VERSION                CARD_IMPORT_KEYPAIR_VERSION_SEVEN
#define CARD_CHANGE_AUTHENTICATOR_VERSION_SEVEN            7
#define CARD_CHANGE_AUTHENTICATOR_CURRENT_VERSION          CARD_CHANGE_AUTHENTICATOR_VERSION_SEVEN
#define CARD_CHANGE_AUTHENTICATOR_RESPONSE_VERSION_SEVEN   7
#define CARD_CHANGE_AUTHENTICATOR_RESPONSE_CURRENT_VERSION CARD_CHANGE_AUTHENTICATOR_RESPONSE_VERSION_SEVEN
#define CARD_AUTHENTICATE_VERSION_SEVEN                    7
#define CARD_AUTHENTICATE_CURRENT_VERSION                  CARD_AUTHENTICATE_VERSION_SEVEN
#define CARD_AUTHENTICATE_RESPONSE_VERSION_SEVEN           7
#define CARD_AUTHENTICATE_RESPONSE_CURRENT_VERSION         CARD_AUTHENTICATE_RESPONSE_VERSION_SEVEN
#define CARD_DATA_VERSION_SEVEN                            7
#define CARD_DATA_VERSION_SIX                              6
#define CARD_DATA_VERSION_FIVE                             5
#define CARD_DATA_VERSION_FOUR                             4
#define CARD_DATA_CURRENT_VERSION                          CARD_DATA_VERSION_SEVEN

#define szBASE_CSP_DIR                         "mscp"
#define szINTERMEDIATE_CERTS_DIR               "mscerts"
#define szCACHE_FILE                           "cardcf"
#define szCARD_IDENTIFIER_FILE                 "cardid"
#define szCONTAINER_MAP_FILE                   "cmapfile"
#define szROOT_STORE_FILE                      "msroots"
#define szUSER_SIGNATURE_CERT_PREFIX           "ksc"
#define szUSER_KEYEXCHANGE_CERT_PREFIX         "kxc"
#define szUSER_SIGNATURE_PRIVATE_KEY_PREFIX    "kss"
#define szUSER_SIGNATURE_PUBLIC_KEY_PREFIX     "ksp"
#define szUSER_KEYEXCHANGE_PRIVATE_KEY_PREFIX  "kxs"
#define szUSER_KEYEXCHANGE_PUBLIC_KEY_PREFIX   "kxp"
#define wszCARD_USER_EVERYONE                 L"anonymous"
#define wszCARD_USER_USER                     L"user"
#define wszCARD_USER_ADMIN                    L"admin"
#define CCP_CONTAINER_INFO                    L"Container Info"
#define CCP_PIN_IDENTIFIER                    L"PIN Identifier"
#define CCP_ASSOCIATED_ECDH_KEY               L"Associated ECDH Key"
#define CP_CARD_FREE_SPACE                    L"Free Space"
#define CP_CARD_CAPABILITIES                  L"Capabilities"
#define CP_CARD_KEYSIZES                      L"Key Sizes"
#define CP_CARD_READ_ONLY                     L"Read Only Mode"
#define CP_CARD_CACHE_MODE                    L"Cache Mode"
#define CP_SUPPORTS_WIN_X509_ENROLLMENT       L"Supports Windows x.509 Enrollment"
#define CP_CARD_GUID                          L"Card Identifier"
#define CP_CARD_SERIAL_NO                     L"Card Serial Number"
#define CP_CARD_PIN_INFO                      L"PIN Information"
#define CP_CARD_LIST_PINS                     L"PIN List"
#define CP_CARD_AUTHENTICATED_STATE           L"Authenticated State"
#define CP_CARD_PIN_STRENGTH_VERIFY           L"PIN Strength Verify"
#define CP_CARD_PIN_STRENGTH_CHANGE           L"PIN Strength Change"
#define CP_CARD_PIN_STRENGTH_UNBLOCK          L"PIN Strength Unblock"
#define CP_PARENT_WINDOW                      L"Parent Window"
#define CP_PIN_CONTEXT_STRING                 L"PIN Context String"
#define CP_KEY_IMPORT_SUPPORT                 L"Key Import Support"
#define CP_ENUM_ALGORITHMS                    L"Algorithms"
#define CP_PADDING_SCHEMES                    L"Padding Schemes"
#define CP_CHAINING_MODES                     L"Chaining Modes"
#define CSF_IMPORT_KEYPAIR                    L"Import Key Pair"
#define CSF_CHANGE_AUTHENTICATOR              L"Change Authenticator"
#define CSF_AUTHENTICATE                      L"Authenticate"
#define CKP_CHAINING_MODE                     L"ChainingMode"
#define CKP_INITIALIZATION_VECTOR             L"IV"
#define CKP_BLOCK_LENGTH                      L"BlockLength"

#define MAX_CONTAINER_NAME_LEN           39
#define CARD_CREATE_CONTAINER_KEY_GEN    1
#define CARD_CREATE_CONTAINER_KEY_IMPORT 2
#define CONTAINER_MAP_VALID_CONTAINER    1
#define CONTAINER_MAP_DEFAULT_CONTAINER  2

#define AT_KEYEXCHANGE 1
#define AT_SIGNATURE   2
#define AT_ECDSA_P256  3
#define AT_ECDSA_P384  4
#define AT_ECDSA_P521  5
#define AT_ECDHE_P256  6
#define AT_ECDHE_P384  7
#define AT_ECDHE_P521  8

#define MAX_PINS                                 8
#define ROLE_EVERYONE                            0
#define ROLE_USER                                1
#define ROLE_ADMIN                               2
#define PIN_SET_NONE                             0x00
#define PIN_SET_ALL_ROLES                        0xFF
#define CREATE_PIN_SET(PinId)                    (1 << PinId)
#define SET_PIN(PinSet, PinId)                   PinSet |= CREATE_PIN_SET(PinId)
#define IS_PIN_SET(PinSet, PinId)                (0 != (PinSet & CREATE_PIN_SET(PinId)))
#define CLEAR_PIN(PinSet, PinId)                 PinSet &= ~CREATE_PIN_SET(PinId)
#define PIN_CHANGE_FLAG_UNBLOCK                  1
#define PIN_CHANGE_FLAG_CHANGEPIN                2
#define CP_CACHE_MODE_GLOBAL_CACHE               1
#define CP_CACHE_MODE_SESSION_ONLY               2
#define CP_CACHE_MODE_NO_CACHE                   3
#define CARD_AUTHENTICATE_GENERATE_SESSION_PIN   0x10000000
#define CARD_AUTHENTICATE_SESSION_PIN            0x20000000
#define CARD_PIN_STRENGTH_PLAINTEXT              1
#define CARD_PIN_STRENGTH_SESSION_PIN            2
#define CARD_PIN_SILENT_CONTEXT                  0x00000040
#define CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE 1
#define CARD_AUTHENTICATE_PIN_PIN                2

#define CARD_SECURE_KEY_INJECTION_NO_CARD_MODE 1
#define CARD_KEY_IMPORT_PLAIN_TEXT             1
#define CARD_KEY_IMPORT_RSA_KEYEST             2
#define CARD_KEY_IMPORT_ECC_KEYEST             4
#define CARD_KEY_IMPORT_SHARED_SYMMETRIC       8

#define CARD_CIPHER_OPERATION     1
#define CARD_ASYMMETRIC_OPERATION 2
#define CARD_3DES_112_ALGORITHM   BCRYPT_3DES_112_ALGORITHM
#define CARD_3DES_ALGORITHM       BCRYPT_3DES_ALGORITHM
#define CARD_AES_ALGORITHM        BCRYPT_AES_ALGORITHM
#define CARD_BLOCK_PADDING        BCRYPT_BLOCK_PADDING
#define CARD_CHAIN_MODE_CBC       BCRYPT_CHAIN_MODE_CBC

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _CARD_DIRECTORY_ACCESS_CONDITION {
  InvalidDirAc           = 0,
  UserCreateDeleteDirAc  = 1,
  AdminCreateDeleteDirAc = 2
} CARD_DIRECTORY_ACCESS_CONDITION;

typedef enum _CARD_FILE_ACCESS_CONDITION {
  InvalidAc                = 0,
  EveryoneReadUserWriteAc  = 1,
  UserWriteExecuteAc       = 2,
  EveryoneReadAdminWriteAc = 3,
  UnknownAc                = 4,
  UserReadWriteAc          = 5,
  AdminReadWriteAc         = 6
} CARD_FILE_ACCESS_CONDITION;

typedef enum {
  AlphaNumericPinType      = 0,
  ExternalPinType          = 1,
  ChallengeResponsePinType = 2,
  EmptyPinType             = 3
} SECRET_TYPE;

typedef enum {
  AuthenticationPin   = 0,
  DigitalSignaturePin = 1,
  EncryptionPin       = 2,
  NonRepudiationPin   = 3,
  AdministratorPin    = 4,
  PrimaryCardPin      = 5,
  UnblockOnlyPin      = 6
} SECRET_PURPOSE;

typedef enum {
  PinCacheNormal       = 0,
  PinCacheTimed        = 1,
  PinCacheNone         = 2,
  PinCacheAlwaysPrompt = 3
} PIN_CACHE_POLICY_TYPE;

typedef struct _CARD_CACHE_FILE_FORMAT {
  BYTE bVersion;
  BYTE bPinsFreshness;
  WORD wContainersFreshness;
  WORD wFilesFreshness;
} CARD_CACHE_FILE_FORMAT, *PCARD_CACHE_FILE_FORMAT;

typedef struct _CARD_SIGNING_INFO {
  DWORD  dwVersion;
  BYTE   bContainerIndex;
  DWORD  dwKeySpec;
  DWORD  dwSigningFlags;
  ALG_ID aiHashAlg;
  PBYTE  pbData;
  DWORD  cbData;
  PBYTE  pbSignedData;
  DWORD  cbSignedData;
  LPVOID pPaddingInfo;
  DWORD  dwPaddingType;
} CARD_SIGNING_INFO, *PCARD_SIGNING_INFO;

typedef struct _CARD_CAPABILITIES {
  DWORD   dwVersion;
  WINBOOL fCertificateCompression;
  WINBOOL fKeyGen;
} CARD_CAPABILITIES, *PCARD_CAPABILITIES;

typedef struct _CONTAINER_INFO {
  DWORD dwVersion;
  DWORD dwReserved;
  DWORD cbSigPublicKey;
  PBYTE pbSigPublicKey;
  DWORD cbKeyExPublicKey;
  PBYTE pbKeyExPublicKey;
} CONTAINER_INFO, *PCONTAINER_INFO;

typedef struct _CONTAINER_MAP_RECORD {
  WCHAR wszGuid[MAX_CONTAINER_NAME_LEN + 1];
  BYTE bFlags;
  BYTE bReserved;
  WORD wSigKeySizeBits;
  WORD wKeyExchangeKeySizeBits;
} CONTAINER_MAP_RECORD, *PCONTAINER_MAP_RECORD;

typedef struct _CARD_RSA_DECRYPT_INFO {
  DWORD  dwVersion;
  BYTE   bContainerIndex;
  DWORD  dwKeySpec;
  PBYTE  pbData;
  DWORD  cbData;
  LPVOID pPaddingInfo;
  DWORD  dwPaddingType;
} CARD_RSA_DECRYPT_INFO, *PCARD_RSA_DECRYPT_INFO;

typedef ULONG_PTR CARD_KEY_HANDLE, *PCARD_KEY_HANDLE;

typedef struct _CARD_DERIVE_KEY {
  DWORD   dwVersion;
  DWORD   dwFlags;
  LPCWSTR pwszKDF;
  BYTE    bSecretAgreementIndex;
  PVOID   pParameterList;
  PUCHAR  pbDerivedKey;
  DWORD   cbDerivedKey;
  LPWSTR  pwszAlgId;
  DWORD   dwKeyLen;
  CARD_KEY_HANDLE hKey;
} CARD_DERIVE_KEY, *PCARD_DERIVE_KEY;

typedef struct _CARD_FILE_INFO {
  DWORD                      dwVersion;
  DWORD                      cbFileSize;
  CARD_FILE_ACCESS_CONDITION AccessCondition;
} CARD_FILE_INFO, *PCARD_FILE_INFO;

typedef struct _CARD_FREE_SPACE_INFO {
  DWORD dwVersion;
  DWORD dwBytesAvailable;
  DWORD dwKeyContainersAvailable;
  DWORD dwMaxKeyContainers;
} CARD_FREE_SPACE_INFO, *PCARD_FREE_SPACE_INFO;

typedef struct _CARD_DH_AGREEMENT_INFO {
  DWORD dwVersion;
  BYTE  bContainerIndex;
  DWORD dwFlags;
  DWORD dwPublicKey;
  PBYTE pbPublicKey;
  PBYTE pbReserved;
  DWORD cbReserved;
  BYTE  bSecretAgreementIndex;
} CARD_DH_AGREEMENT_INFO, *PCARD_DH_AGREEMENT_INFO;

typedef struct _CARD_KEY_SIZES {
  DWORD dwVersion;
  DWORD dwMinimumBitlen;
  DWORD dwDefaultBitlen;
  DWORD dwMaximumBitlen;
  DWORD dwIncrementalBitlen;
} CARD_KEY_SIZES, *PCARD_KEY_SIZES;

typedef struct _CARD_DATA CARD_DATA, *PCARD_DATA;
typedef DWORD PIN_ID, *PPIN_ID;
typedef DWORD PIN_SET, *PPIN_SET;

typedef struct _PIN_CACHE_POLICY {
  DWORD dwVersion;
  PIN_CACHE_POLICY_TYPE PinCachePolicyType;
  DWORD dwPinCachePolicyInfo;
} PIN_CACHE_POLICY, *PPIN_CACHE_POLICY;

typedef struct _PIN_INFO {
  DWORD dwVersion;
  SECRET_TYPE PinType;
  SECRET_PURPOSE PinPurpose;
  PIN_SET dwChangePermission;
  PIN_SET dwUnblockPermission;
  PIN_CACHE_POLICY PinCachePolicy;
  DWORD dwFlags;
} PIN_INFO, *PPIN_INFO;

typedef struct _CARD_ENCRYPTED_DATA {
  PBYTE pbEncryptedData;
  DWORD cbEncryptedData;
} CARD_ENCRYPTED_DATA, *PCARD_ENCRYPTED_DATA;

typedef struct _CARD_IMPORT_KEYPAIR {
  DWORD dwVersion;
  BYTE bContainerIndex;
  PIN_ID PinId;
  DWORD dwKeySpec;
  DWORD dwKeySize;
  DWORD cbInput;
  BYTE pbInput[0];
} CARD_IMPORT_KEYPAIR, *PCARD_IMPORT_KEYPAIR;

typedef struct _CARD_CHANGE_AUTHENTICATOR {
  DWORD dwVersion;
  DWORD dwFlags;
  PIN_ID dwAuthenticatingPinId;
  DWORD cbAuthenticatingPinData;
  PIN_ID dwTargetPinId;
  DWORD cbTargetData;
  DWORD cRetryCount;
  BYTE pbData[0];
} CARD_CHANGE_AUTHENTICATOR, *PCARD_CHANGE_AUTHENTICATOR;

typedef struct _CARD_CHANGE_AUTHENTICATOR_RESPONSE {
  DWORD dwVersion;
  DWORD cAttemptsRemaining;
} CARD_CHANGE_AUTHENTICATOR_RESPONSE, *PCARD_CHANGE_AUTHENTICATOR_RESPONSE;

typedef struct _CARD_AUTHENTICATE {
  DWORD dwVersion;
  DWORD dwFlags;
  PIN_ID PinId;
  DWORD cbPinData;
  BYTE pbPinData[0];
} CARD_AUTHENTICATE, *PCARD_AUTHENTICATE;

typedef struct _CARD_AUTHENTICATE_RESPONSE {
  DWORD dwVersion;
  DWORD cbSessionPin;
  DWORD cAttemptsRemaining;
  BYTE pbSessionPin[0];
} CARD_AUTHENTICATE_RESPONSE, *PCARD_AUTHENTICATE_RESPONSE;

typedef LPVOID (WINAPI *PFN_CSP_ALLOC)(SIZE_T Size);
typedef LPVOID (WINAPI *PFN_CSP_REALLOC)(LPVOID Address, SIZE_T Size);
typedef VOID (WINAPI *PFN_CSP_FREE)(LPVOID Address);

typedef DWORD (WINAPI *PFN_CSP_CACHE_ADD_FILE)(
  PVOID pvCacheContext,
  LPWSTR wszTag,
  DWORD dwFlags,
  PBYTE pbData,
  DWORD cbData
);

typedef DWORD (WINAPI *PFN_CSP_CACHE_LOOKUP_FILE)(
  PVOID pvCacheContext,
  LPWSTR wszTag,
  DWORD dwFlags,
  PBYTE *ppbData,
  PDWORD pcbData
);

typedef DWORD (WINAPI *PFN_CSP_CACHE_DELETE_FILE)(
  PVOID pvCacheContext,
  LPWSTR wszTag,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CSP_PAD_DATA)(
  PCARD_SIGNING_INFO pSigningInfo,
  DWORD cbMaxWidth,
  DWORD *pcbPaddedBuffer,
  PBYTE *ppbPaddedBuffer
);

typedef DWORD (WINAPI *PFN_CARD_ACQUIRE_CONTEXT)(
  PCARD_DATA pCardData,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_DELETE_CONTEXT)(
  PCARD_DATA pCardData
);

typedef DWORD (WINAPI *PFN_CARD_QUERY_CAPABILITIES)(
  PCARD_DATA pCardData,
  PCARD_CAPABILITIES pCardCapabilities
);

typedef DWORD (WINAPI *PFN_CARD_DELETE_CONTAINER)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwReserved
);

typedef DWORD (WINAPI *PFN_CARD_CREATE_CONTAINER)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  DWORD dwKeySpec,
  DWORD dwKeySize,
  PBYTE pbKeyData
);

typedef DWORD (WINAPI *PFN_CARD_GET_CONTAINER_INFO)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  PCONTAINER_INFO pContainerInfo
);

typedef DWORD (WINAPI *PFN_CARD_AUTHENTICATE_PIN)(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbPin,
  DWORD cbPin,
  PDWORD pcAttemptsRemaining
);

typedef DWORD (WINAPI *PFN_CARD_GET_CHALLENGE)(
  PCARD_DATA pCardData,
  PBYTE *ppbChallengeData,
  PDWORD pcbChallengeData
);

typedef DWORD (WINAPI *PFN_CARD_AUTHENTICATE_CHALLENGE)(
  PCARD_DATA pCardData,
  PBYTE pbResponseData,
  DWORD cbResponseData,
  PDWORD pcAttemptsRemaining
);

typedef DWORD (WINAPI *PFN_CARD_UNBLOCK_PIN)(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbAuthenticationData,
  DWORD cbAuthenticationData,
  PBYTE pbNewPinData,
  DWORD cbNewPinData,
  DWORD cRetryCount,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_CHANGE_AUTHENTICATOR)(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbCurrentAuthenticator,
  DWORD cbCurrentAuthenticator,
  PBYTE pbNewAuthenticator,
  DWORD cbNewAuthenticator,
  DWORD cRetryCount,
  DWORD dwFlags,
  PDWORD pcAttemptsRemaining
);

typedef DWORD (WINAPI *PFN_CARD_DEAUTHENTICATE)(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_CREATE_DIRECTORY)(
  PCARD_DATA pCardData,
  LPSTR pszDirectory,
  CARD_DIRECTORY_ACCESS_CONDITION AccessCondition
);

typedef DWORD (WINAPI *PFN_CARD_DELETE_DIRECTORY)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName
);

typedef DWORD (WINAPI *PFN_CARD_CREATE_FILE)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD cbInitialCreationSize,
  CARD_FILE_ACCESS_CONDITION AccessCondition
);

typedef DWORD (WINAPI *PFN_CARD_READ_FILE)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags,
  PBYTE *ppbData,
  PDWORD pcbData
);

typedef DWORD (WINAPI *PFN_CARD_WRITE_FILE)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags,
  PBYTE pbData,
  DWORD cbData
);

typedef DWORD (WINAPI *PFN_CARD_DELETE_FILE)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_ENUM_FILES)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR *pmszFileNames,
  LPDWORD pdwcbFileName,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_FILE_INFO)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  PCARD_FILE_INFO pCardFileInfo
);

typedef DWORD (WINAPI *PFN_CARD_QUERY_FREE_SPACE)(
  PCARD_DATA pCardData,
  DWORD dwFlags,
  PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo
);

typedef DWORD (WINAPI *PFN_CARD_QUERY_KEY_SIZES)(
  PCARD_DATA pCardData,
  DWORD dwKeySpec,
  DWORD dwFlags,
  PCARD_KEY_SIZES pKeySizes
);

typedef DWORD (WINAPI *PFN_CARD_SIGN_DATA)(
  PCARD_DATA pCardData,
  PCARD_SIGNING_INFO pInfo
);

typedef DWORD (WINAPI *PFN_CARD_RSA_DECRYPT)(
  PCARD_DATA pCardData,
  PCARD_RSA_DECRYPT_INFO pInfo
);

typedef DWORD (WINAPI *PFN_CARD_CONSTRUCT_DH_AGREEMENT)(
  PCARD_DATA pCardData,
  PCARD_DH_AGREEMENT_INFO pAgreementInfo
);

#if (_WIN32_WINNT >= 0x0600)
typedef DWORD (WINAPI *PFN_CARD_DERIVE_KEY)(
  PCARD_DATA pCardData,
  PCARD_DERIVE_KEY pAgreementInfo
);

typedef DWORD (WINAPI *PFN_CARD_DESTROY_DH_AGREEMENT)(
  PCARD_DATA pCardData,
  BYTE bSecretAgreementIndex,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CSP_GET_DH_AGREEMENT)(
  PCARD_DATA pCardData,
  PVOID hSecretAgreement,
  BYTE *pbSecretAgreementIndex,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_CHALLENGE_EX)(
  PCARD_DATA pCardData,
  PIN_ID PinId,
  PBYTE *ppbChallengeData,
  PDWORD pcbChallengeData,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_AUTHENTICATE_EX)(
  PCARD_DATA pCardData,
  PIN_ID PinId,
  DWORD dwFlags,
  PBYTE pbPinData,
  DWORD cbPinData,
  PBYTE *ppbSessionPin,
  PDWORD pcbSessionPin,
  PDWORD pcAttemptsRemaining
);

typedef DWORD (WINAPI *PFN_CARD_CHANGE_AUTHENTICATOR_EX)(
  PCARD_DATA pCardData,
  DWORD dwFlags,
  PIN_ID dwAuthenticatingPinId,
  PBYTE pbAuthenticatingPinData,
  DWORD cbAuthenticatingPinData,
  PIN_ID dwTargetPinId,
  PBYTE pbTargetData,
  DWORD cbTargetData,
  DWORD cRetryCount,
  PDWORD pcAttemptsRemaining
);

typedef DWORD (WINAPI *PFN_CARD_DEAUTHENTICATE_EX)(
  PCARD_DATA pCardData,
  PIN_SET PinId,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_CONTAINER_PROPERTY)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_SET_CONTAINER_PROPERTY)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbDataLen,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_PROPERTY)(
  PCARD_DATA pCardData,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_SET_PROPERTY)(
  PCARD_DATA pCardData,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbDataLen,
  DWORD dwFlags
);
#else
typedef LPVOID PFN_CARD_DERIVE_KEY;
typedef LPVOID PFN_CARD_DESTROY_DH_AGREEMENT;
typedef LPVOID PFN_CSP_GET_DH_AGREEMENT;
typedef LPVOID PFN_CARD_GET_CHALLENGE_EX;
typedef LPVOID PFN_CARD_AUTHENTICATE_EX;
typedef LPVOID PFN_CARD_CHANGE_AUTHENTICATOR_EX;
typedef LPVOID PFN_CARD_DEAUTHENTICATE_EX;
typedef LPVOID PFN_CARD_GET_CONTAINER_PROPERTY;
typedef LPVOID PFN_CARD_SET_CONTAINER_PROPERTY;
typedef LPVOID PFN_CARD_GET_PROPERTY;
typedef LPVOID PFN_CARD_SET_PROPERTY;
#endif /*(_WIN32_WINNT >= 0x0600)*/

#if (_WIN32_WINNT >= 0x0601)
typedef DWORD (WINAPI *PFN_CSP_UNPAD_DATA)(
  PCARD_RSA_DECRYPT_INFO pRSADecryptInfo,
  DWORD *pcbUnpaddedData,
  PBYTE *ppbUnpaddedData
);

typedef DWORD (WINAPI *PFN_MD_IMPORT_SESSION_KEY)(
  PCARD_DATA pCardData,
  LPCWSTR pwszBlobType,
  LPCWSTR pwszAlgId,
  PCARD_KEY_HANDLE phKey,
  PBYTE pbInput,
  DWORD cbInput
);

typedef DWORD (WINAPI *PFN_MD_ENCRYPT_DATA)(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszSecureFunction,
  PBYTE pbInput,
  DWORD cbInput,
  DWORD dwFlags,
  PCARD_ENCRYPTED_DATA *ppEncryptedData,
  PDWORD pcEncryptedData
);

typedef DWORD (WINAPI *PFN_CARD_IMPORT_SESSION_KEY)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPVOID pPaddingInfo,
  LPCWSTR pwszBlobType,
  LPCWSTR pwszAlgId,
  PCARD_KEY_HANDLE phKey,
  PBYTE pbInput,
  DWORD cbInput,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_SHARED_KEY_HANDLE)(
  PCARD_DATA pCardData,
  PBYTE pbInput,
  DWORD cbInput,
  PBYTE *ppbOutput,
  PDWORD pcbOutput,
  PCARD_KEY_HANDLE phKey
);

typedef DWORD (WINAPI *PFN_CARD_GET_ALGORITHM_PROPERTY)(
  PCARD_DATA pCardData,
  LPCWSTR pwszAlgId,
  LPCWSTR pwszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen, 
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_KEY_PROPERTY)(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_SET_KEY_PROPERTY)(
   PCARD_DATA pCardData,
   CARD_KEY_HANDLE hKey,
   LPCWSTR pwszProperty,
   PBYTE pbInput,
   DWORD cbInput,
   DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_DESTROY_KEY)(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey
);

typedef DWORD (WINAPI *PFN_CARD_PROCESS_ENCRYPTED_DATA)(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszSecureFunction,
  PCARD_ENCRYPTED_DATA pEncryptedData,
  DWORD cEncryptedData,
  PBYTE pbOutput,
  DWORD cbOutput,
  PDWORD pdwOutputLen,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_CREATE_CONTAINER_EX)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  DWORD dwKeySpec,
  DWORD dwKeySize,
  PBYTE pbKeyData,
  PIN_ID PinId
);
#else
typedef LPVOID PFN_CSP_UNPAD_DATA;
typedef LPVOID PFN_MD_IMPORT_SESSION_KEY;
typedef LPVOID PFN_MD_ENCRYPT_DATA;
typedef LPVOID PFN_CARD_IMPORT_SESSION_KEY;
typedef LPVOID PFN_CARD_GET_SHARED_KEY_HANDLE;
typedef LPVOID PFN_CARD_GET_ALGORITHM_PROPERTY;
typedef LPVOID PFN_CARD_GET_KEY_PROPERTY;
typedef LPVOID PFN_CARD_SET_KEY_PROPERTY;
typedef LPVOID PFN_CARD_DESTROY_KEY;
typedef LPVOID PFN_CARD_PROCESS_ENCRYPTED_DATA;
typedef LPVOID PFN_CARD_CREATE_CONTAINER_EX;
#endif /*(_WIN32_WINNT >= 0x0601)*/

typedef struct _CARD_DATA {
  DWORD                            dwVersion;
  PBYTE                            pbAtr;
  DWORD                            cbAtr;
  LPWSTR                           pwszCardName;
  PFN_CSP_ALLOC                    pfnCspAlloc;
  PFN_CSP_REALLOC                  pfnCspReAlloc;
  PFN_CSP_FREE                     pfnCspFree;
  PFN_CSP_CACHE_ADD_FILE           pfnCspCacheAddFile;
  PFN_CSP_CACHE_LOOKUP_FILE        pfnCspCacheLookupFile;
  PFN_CSP_CACHE_DELETE_FILE        pfnCspCacheDeleteFile;
  PVOID                            pvCacheContext;
  PFN_CSP_PAD_DATA                 pfnCspPadData;
  SCARDCONTEXT                     hSCardCtx;
  SCARDHANDLE                      hScard;
  PVOID                            pvVendorSpecific;
  PFN_CARD_DELETE_CONTEXT          pfnCardDeleteContext;
  PFN_CARD_QUERY_CAPABILITIES      pfnCardQueryCapabilities;
  PFN_CARD_DELETE_CONTAINER        pfnCardDeleteContainer;
  PFN_CARD_CREATE_CONTAINER        pfnCardCreateContainer;
  PFN_CARD_GET_CONTAINER_INFO      pfnCardGetContainerInfo;
  PFN_CARD_AUTHENTICATE_PIN        pfnCardAuthenticatePin;
  PFN_CARD_GET_CHALLENGE           pfnCardGetChallenge;
  PFN_CARD_AUTHENTICATE_CHALLENGE  pfnCardAuthenticateChallenge;
  PFN_CARD_UNBLOCK_PIN             pfnCardUnblockPin;
  PFN_CARD_CHANGE_AUTHENTICATOR    pfnCardChangeAuthenticator;
  PFN_CARD_DEAUTHENTICATE          pfnCardDeauthenticate;
  PFN_CARD_CREATE_DIRECTORY        pfnCardCreateDirectory;
  PFN_CARD_DELETE_DIRECTORY        pfnCardDeleteDirectory;
  LPVOID                           pvUnused3;
  LPVOID                           pvUnused4;
  PFN_CARD_CREATE_FILE             pfnCardCreateFile;
  PFN_CARD_READ_FILE               pfnCardReadFile;
  PFN_CARD_WRITE_FILE              pfnCardWriteFile;
  PFN_CARD_DELETE_FILE             pfnCardDeleteFile;
  PFN_CARD_ENUM_FILES              pfnCardEnumFiles;
  PFN_CARD_GET_FILE_INFO           pfnCardGetFileInfo;
  PFN_CARD_QUERY_FREE_SPACE        pfnCardQueryFreeSpace;
  PFN_CARD_QUERY_KEY_SIZES         pfnCardQueryKeySizes;
  PFN_CARD_SIGN_DATA               pfnCardSignData;
  PFN_CARD_RSA_DECRYPT             pfnCardRSADecrypt;
  PFN_CARD_CONSTRUCT_DH_AGREEMENT  pfnCardConstructDHAgreement;
  PFN_CARD_DERIVE_KEY              pfnCardDeriveKey;
  PFN_CARD_DESTROY_DH_AGREEMENT    pfnCardDestroyDHAgreement;
  PFN_CSP_GET_DH_AGREEMENT         pfnCspGetDHAgreement;
  PFN_CARD_GET_CHALLENGE_EX        pfnCardGetChallengeEx;
  PFN_CARD_AUTHENTICATE_EX         pfnCardAuthenticateEx;
  PFN_CARD_CHANGE_AUTHENTICATOR_EX pfnCardChangeAuthenticatorEx;
  PFN_CARD_DEAUTHENTICATE_EX       pfnCardDeauthenticateEx;
  PFN_CARD_GET_CONTAINER_PROPERTY  pfnCardGetContainerProperty;
  PFN_CARD_SET_CONTAINER_PROPERTY  pfnCardSetContainerProperty;
  PFN_CARD_GET_PROPERTY            pfnCardGetProperty;
  PFN_CARD_SET_PROPERTY            pfnCardSetProperty;
  PFN_CSP_UNPAD_DATA               pfnCspUnpadData;
  PFN_MD_IMPORT_SESSION_KEY        pfnMDImportSessionKey;
  PFN_MD_ENCRYPT_DATA              pfnMDEncryptData;
  PFN_CARD_IMPORT_SESSION_KEY      pfnCardImportSessionKey;
  PFN_CARD_GET_SHARED_KEY_HANDLE   pfnCardGetSharedKeyHandle;
  PFN_CARD_GET_ALGORITHM_PROPERTY  pfnCardGetAlgorithmProperty;
  PFN_CARD_GET_KEY_PROPERTY        pfnCardGetKeyProperty;
  PFN_CARD_SET_KEY_PROPERTY        pfnCardSetKeyProperty;
  PFN_CARD_DESTROY_KEY             pfnCardDestroyKey;
  PFN_CARD_PROCESS_ENCRYPTED_DATA  pfnCardProcessEncryptedData;
  PFN_CARD_CREATE_CONTAINER_EX     pfnCardCreateContainerEx;
} CARD_DATA, *PCARD_DATA;

DWORD WINAPI I_CardConvertFileNameToAnsi(
  PCARD_DATA pCardData,
  LPWSTR wszUnicodeName,
  LPSTR *ppszAnsiName
);

DWORD WINAPI CardAcquireContext(
  PCARD_DATA pCardData,
  DWORD dwFlags
);

DWORD WINAPI CardDeleteContext(
  PCARD_DATA pCardData
);

DWORD WINAPI CardQueryCapabilities(
  PCARD_DATA pCardData,
  PCARD_CAPABILITIES pCardCapabilities
);

DWORD WINAPI CardDeleteContainer(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwReserved
);

DWORD WINAPI CardCreateContainer(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  DWORD dwKeySpec,
  DWORD dwKeySize,
  PBYTE pbKeyData
);

DWORD WINAPI CardGetContainerInfo(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  PCONTAINER_INFO pContainerInfo
);

DWORD WINAPI CardAuthenticatePin(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbPin,
  DWORD cbPin,
  PDWORD pcAttemptsRemaining
);

DWORD WINAPI CardGetChallenge(
  PCARD_DATA pCardData,
  PBYTE *ppbChallengeData,
  PDWORD pcbChallengeData
);

DWORD WINAPI CardAuthenticateChallenge(
  PCARD_DATA pCardData,
  PBYTE pbResponseData,
  DWORD cbResponseData,
  PDWORD pcAttemptsRemaining
);

DWORD WINAPI CardUnblockPin(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbAuthenticationData,
  DWORD cbAuthenticationData,
  PBYTE pbNewPinData,
  DWORD cbNewPinData,
  DWORD cRetryCount,
  DWORD dwFlags
);

DWORD WINAPI CardChangeAuthenticator(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbCurrentAuthenticator,
  DWORD cbCurrentAuthenticator,
  PBYTE pbNewAuthenticator,
  DWORD cbNewAuthenticator,
  DWORD cRetryCount,
  DWORD dwFlags,
  PDWORD pcAttemptsRemaining
);

DWORD WINAPI CardDeauthenticate(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  DWORD dwFlags
);

DWORD WINAPI CardCreateDirectory(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  CARD_DIRECTORY_ACCESS_CONDITION AccessCondition
);

DWORD WINAPI CardDeleteDirectory(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName
);

DWORD WINAPI CardCreateFile(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD cbInitialCreationSize,
  CARD_FILE_ACCESS_CONDITION AccessCondition
);

DWORD WINAPI CardReadFile(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags,
  PBYTE *ppbData,
  PDWORD pcbData
);

DWORD WINAPI CardWriteFile(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags,
  PBYTE pbData,
  DWORD cbData
);

DWORD WINAPI CardDeleteFile(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags
);

DWORD WINAPI CardEnumFiles(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR *pmszFileNames,
  LPDWORD pdwcbFileName,
  DWORD dwFlags
);

DWORD WINAPI CardGetFileInfo(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  PCARD_FILE_INFO pCardFileInfo
);

DWORD WINAPI CardQueryFreeSpace(
  PCARD_DATA pCardData,
  DWORD dwFlags,
  PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo
);

DWORD WINAPI CardQueryKeySizes(
  PCARD_DATA pCardData,
  DWORD dwKeySpec,
  DWORD dwFlags,
  PCARD_KEY_SIZES pKeySizes
);

DWORD WINAPI CardSignData(
  PCARD_DATA pCardData,
  PCARD_SIGNING_INFO pInfo
);

DWORD WINAPI CardRSADecrypt(
  PCARD_DATA pCardData,
  PCARD_RSA_DECRYPT_INFO pInfo
);

DWORD WINAPI CardConstructDHAgreement(
  PCARD_DATA pCardData,
  PCARD_DH_AGREEMENT_INFO pAgreementInfo
);

DWORD WINAPI CardDeriveKey(
  PCARD_DATA pCardData,
  PCARD_DERIVE_KEY pAgreementInfo
);

DWORD WINAPI CardDestroyDHAgreement(
  PCARD_DATA pCardData,
  BYTE bSecretAgreementIndex,
  DWORD dwFlags
);

DWORD WINAPI CspGetDHAgreement(
  PCARD_DATA pCardData,
  PVOID hSecretAgreement,
  BYTE *pbSecretAgreementIndex,
  DWORD dwFlags
);

DWORD WINAPI CardGetChallengeEx(
  PCARD_DATA pCardData,
  PIN_ID PinId,
  PBYTE *ppbChallengeData,
  PDWORD pcbChallengeData,
  DWORD dwFlags
);

DWORD WINAPI CardAuthenticateEx(
  PCARD_DATA pCardData,
  PIN_ID PinId,
  DWORD dwFlags,
  PBYTE pbPinData,
  DWORD cbPinData,
  PBYTE *ppbSessionPin,
  PDWORD pcbSessionPin,
  PDWORD pcAttemptsRemaining
);

DWORD WINAPI CardChangeAuthenticatorEx(
  PCARD_DATA pCardData,
  DWORD dwFlags,
  PIN_ID dwAuthenticatingPinId,
  PBYTE pbAuthenticatingPinData,
  DWORD cbAuthenticatingPinData,
  PIN_ID dwTargetPinId,
  PBYTE pbTargetData,
  DWORD cbTargetData,
  DWORD cRetryCount,
  PDWORD pcAttemptsRemaining
);

DWORD WINAPI CardDeauthenticateEx(
  PCARD_DATA pCardData,
  PIN_SET PinId,
  DWORD dwFlags
);

DWORD WINAPI CardGetContainerProperty(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

DWORD WINAPI CardSetContainerProperty(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbDataLen,
  DWORD dwFlags
);

DWORD WINAPI CardGetProperty(
  PCARD_DATA pCardData,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

DWORD WINAPI CardSetProperty(
  PCARD_DATA pCardData,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbDataLen,
  DWORD dwFlags
);

DWORD WINAPI MDImportSessionKey(
  PCARD_DATA pCardData,
  LPCWSTR pwszBlobType,
  LPCWSTR pwszAlgId,
  PCARD_KEY_HANDLE phKey,
  PBYTE pbInput,
  DWORD cbInput
);

DWORD WINAPI MDEncryptData(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszSecureFunction,
  PBYTE pbInput,
  DWORD cbInput,
  DWORD dwFlags,
  PCARD_ENCRYPTED_DATA *ppEncryptedData,
  PDWORD pcEncryptedData
);

DWORD WINAPI CardImportSessionKey(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPVOID pPaddingInfo,
  LPCWSTR pwszBlobType,
  LPCWSTR pwszAlgId,
  PCARD_KEY_HANDLE phKey,
  PBYTE pbInput,
  DWORD cbInput,
  DWORD dwFlags
);

DWORD WINAPI CardGetSharedKeyHandle(
  PCARD_DATA pCardData,
  PBYTE pbInput,
  DWORD cbInput,
  PBYTE *ppbOutput,
  PDWORD pcbOutput,
  PCARD_KEY_HANDLE phKey
);

DWORD WINAPI CardGetAlgorithmProperty(
  PCARD_DATA pCardData,
  LPCWSTR pwszAlgId,
  LPCWSTR pwszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen, 
  DWORD dwFlags
);

DWORD WINAPI CardGetKeyProperty(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

DWORD WINAPI CardSetKeyProperty(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszProperty,
  PBYTE pbInput,
  DWORD cbInput,
  DWORD dwFlags
);

DWORD WINAPI CardDestroyKey(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey
);

DWORD WINAPI CardProcessEncryptedData(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszSecureFunction,
  PCARD_ENCRYPTED_DATA pEncryptedData,
  DWORD cEncryptedData,
  PBYTE pbOutput,
  DWORD cbOutput,
  PDWORD pdwOutputLen,
  DWORD dwFlags
);

DWORD WINAPI CardCreateContainerEx(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  DWORD dwKeySpec,
  DWORD dwKeySize,
  PBYTE pbKeyData,
  PIN_ID PinId
);

#ifdef __cplusplus
}
#endif
#endif /*_INC_CARDMOD*/
_EOF
	patch -p0 <<'_PATCH' >>"${LOG}" 2>&1 || error "Failed to patch ${BUILD}/include/winscard.h."
--- include/winscard.h	2025-04-26 00:05:19.000000000 +0200
+++ include/winscard.h	2025-04-26 10:04:23.614927900 +0200
@@ -63,6 +63,8 @@
 
 #define SCARD_PROVIDER_PRIMARY 1
 #define SCARD_PROVIDER_CSP 2
+#define SCARD_PROVIDER_KSP 3
+#define SCARD_PROVIDER_CARD_MODULE 0x80000001
 
 #define SCardListReaderGroups __MINGW_NAME_AW(SCardListReaderGroups)
 #define SCardListReaders __MINGW_NAME_AW(SCardListReaders)
_PATCH
	# patch required for Python
	sed -i 's/void) PathQuoteSpaces/WINBOOL) PathQuoteSpaces/g' 'include/shlwapi.h' || error "Failed to patch ${MINGW}/include/shlwapi.h."
fi

if step "build cross compiler - ${ZLIB}"; then
	mkdir -p "${BUILD}/cross-zlib" || error "Failed to create ${BUILD}/cross-zlib."
	cd "${BUILD}/cross-zlib"
	"${SRC}/${ZLIB}/configure" --static "--prefix=${HOST}/host" >>"${LOG}" 2>&1 || error "Failed to configure ${ZLIB}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${ZLIB}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${ZLIB}."
fi

if step "build cross compiler - ${GMP}"; then
	mkdir -p "${BUILD}/cross-gmp" || error "Failed to create ${BUILD}/cross-gmp."
	cd "${BUILD}/cross-gmp"
	"${SRC}/${GMP}/configure" --enable-shared --disable-static --disable-cxx "--prefix=${HOST}/host" >>"${LOG}" 2>&1 || error "Failed to configure ${GMP}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${GMP}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${GMP}."
fi

if step "build cross compiler - ${MPFR}"; then
	mkdir -p "${BUILD}/cross-mpfr" || error "Failed to create ${BUILD}/cross-mpfr."
	cd "${BUILD}/cross-mpfr"
	"${SRC}/${MPFR}/configure" --enable-shared --disable-static "--with-gmp=${HOST}/host" "--prefix=${HOST}/host" >>"${LOG}" 2>&1 || error "Failed to configure ${MPFR}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MPFR}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${MPFR}."
fi

if step "build cross compiler - ${MPC}"; then
	mkdir -p "${BUILD}/cross-mpc" || error "Failed to create ${BUILD}/cross-mpc."
	cd "${BUILD}/cross-mpc"
	"${SRC}/${MPC}/configure" --enable-shared --disable-static "--with-gmp=${HOST}/host" "--with-mpfr=${HOST}/host" "--prefix=${HOST}/host" >>"${LOG}" 2>&1 || error "Failed to configure ${MPC}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MPC}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${MPC}."
fi

if step "build cross compiler - ${ISL}"; then
	mkdir -p "${BUILD}/cross-isl" || error "Failed to create ${BUILD}/cross-isl."
	cd "${BUILD}/cross-isl"
	"${SRC}/${ISL}/configure" --enable-shared --disable-static --enable-portable-binary "--with-gmp-prefix=${HOST}/host" "--prefix=${HOST}/host" >>"${LOG}" 2>&1 || error "Failed to configure ${ISL}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${ISL}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${ISL}."
fi

if step "build cross compiler - ${CLOOG_ISL}"; then
	mkdir -p "${BUILD}/cross-cloog" || error "Failed to create ${BUILD}/cross-cloog."
	cd "${BUILD}/cross-cloog"
	"${SRC}/${CLOOG_ISL}/configure" --enable-shared --disable-static --enable-portable-binary --with-osl=no "--with-gmp-prefix=${HOST}/host" "--with-isl-prefix=${HOST}/host" "--prefix=${HOST}/host" >>"${LOG}" 2>&1 || error "Failed to configure ${CLOOG_ISL}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${CLOOG_ISL}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${CLOOG_ISL}."
fi

if step "build cross compiler - ${BINUTILS}"; then
	mkdir -p "${BUILD}/cross-binutils" || error "Failed to create ${BUILD}/cross-binutils."
	cd "${BUILD}/cross-binutils"
	"${SRC}/${BINUTILS}/configure" --target=x86_64-w64-mingw32 --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32 --enable-lto --enable-plugins --disable-nls "--with-system-zlib=${HOST}/host" "--prefix=${HOST}" "--with-sysroot=${HOST}" "--libdir=${HOST}/x86_64-w64-mingw32/lib" >>"${LOG}" 2>&1 || error "Failed to configure ${BINUTILS}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${BINUTILS}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${BINUTILS}."
fi

if step "build cross compiler - ${MINGW} - C headers"; then
	mkdir -p "${BUILD}/cross-mingw-headers" || error "Failed to create ${BUILD}/cross-mingw-headers."
	cd "${BUILD}/cross-mingw-headers"
	"${BUILD}/mingw-w64-headers/configure" --host=x86_64-w64-mingw32 "--with-default-msvcrt=${MCRTDLL}" --enable-sdk=all "--prefix=${HOST}" "--with-sysroot=${HOST}" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - C headers."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - C headers."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - C headers."
fi

if step "build cross compiler - ${GCC}"; then
	mkdir -p "${BUILD}/cross-gcc" || error "Failed to create ${BUILD}/cross-gcc."
	cd "${BUILD}/cross-gcc"
	"../gcc-src/configure" --target=x86_64-w64-mingw32 --enable-targets=all "--enable-languages=c,c++" $GCC_HOST_CONFIG "--with-gmp=${HOST}/host" "--with-mpfr=${HOST}/host" "--with-mpc=${HOST}/host" "--with-isl=${HOST}/host" "--with-cloog=${HOST}/host" "--with-system-zlib=${HOST}/host" "LDFLAGS=-Wl,-rpath,${HOST}/host/lib" "--prefix=${HOST}" "--with-sysroot=${HOST}" "--libdir=${HOST}/x86_64-w64-mingw32/lib" "--libexecdir=${HOST}/x86_64-w64-mingw32/lib" "--with-native-system-header-dir=/x86_64-w64-mingw32/include" >>"${LOG}" 2>&1 || error "Failed to configure ${GCC}."
	sed -i '/^FLAGS_FOR_TARGET =/s|mingw|i686-w64-mingw32|g' Makefile || error "Failed to patch Makefile."
	sed -i '/^FLAGS_FOR_TARGET =/s|i686-w64-mingw32/lib |i686-w64-mingw32/lib -isystem ${prefix}/include |g' Makefile || error "Failed to patch Makefile."
	make -j $THREADS all-gcc >>"${LOG}" 2>&1 || error "Failed to build ${GCC}."
	make install-gcc >>"${LOG}" 2>&1 || error "Failed to install ${GCC}."
fi

# setup cross environment
export PATH="${HOST}/bin:${PATH}"

if step "build cross compiler - ${MINGW} - C runtime"; then
	mkdir -p "${BUILD}/cross-mingw-crt" || error "Failed to create ${BUILD}/cross-mingw-crt."
	cd "${BUILD}/cross-mingw-crt"
	"${SRC}/${MINGW}/mingw-w64-crt/configure" --host=x86_64-w64-mingw32 "--with-default-msvcrt=${MCRTDLL}" --enable-lib32 --enable-lib64 --disable-dependency-tracking "--prefix=${HOST}" "--with-sysroot=${HOST}" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - C runtime."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - C runtime."
	make install "lib32dir=${HOST}/i686-w64-mingw32/lib" "lib64dir=${HOST}/x86_64-w64-mingw32/lib" >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - C runtime."
fi

if step "build cross compiler - ${MINGW} - pthreads - 32-bit"; then
	mkdir -p "${BUILD}/cross-mingw-pthread-32" || error "Failed to create ${BUILD}/cross-mingw-pthread-32."
	cd "${BUILD}/cross-mingw-pthread-32"
	"${SRC}/${MINGW}/mingw-w64-libraries/winpthreads/configure" --build=x86_64-w64-mingw32 --host=i686-w64-mingw32 --disable-shared --disable-dependency-tracking  "CC=x86_64-w64-mingw32-gcc -m32" "CXX=x86_64-w64-mingw32-g++ -m32" "STRIP=x86_64-w64-mingw32-strip" "AR=x86_64-w64-mingw32-gcc-ar" "RC=x86_64-w64-mingw32-windres -F pe-i386" "--prefix=${HOST}/i686-w64-mingw32" "--libdir=${HOST}/i686-w64-mingw32/lib" "--includedir=${HOST}/include" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - pthreads - 32-bit."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - pthreads - 32-bit."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - pthreads - 32-bit."
fi

if step "build cross compiler - ${MINGW} - pthreads - 64-bit"; then
	mkdir -p "${BUILD}/cross-mingw-pthread-64" || error "Failed to create ${BUILD}/cross-mingw-pthread-64."
	cd "${BUILD}/cross-mingw-pthread-64"
	"${SRC}/${MINGW}/mingw-w64-libraries/winpthreads/configure" --build=x86_64-w64-mingw32 --host=x86_64-w64-mingw32 --disable-shared --disable-dependency-tracking "AR=x86_64-w64-mingw32-gcc-ar" "--prefix=${HOST}/x86_64-w64-mingw32" "--with-sysroot=${HOST}/x86_64-w64-mingw32" "--includedir=${HOST}/include" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - pthreads - 64-bit."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - pthreads - 64-bit."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - pthreads - 64-bit."
	# fix static build
	find "${HOST}" -type f -name "pthread.h" -exec sed -i 's/ DLL_EXPORT/ WINPTHREAD_DLL_EXPORT/g' '{}' ';'
fi

if step "build cross compiler - finalize ${GCC}"; then
	mkdir -p "${BUILD}/cross-final-gcc" || error "Failed to create ${BUILD}/cross-final-gcc."
	cd "${BUILD}/cross-final-gcc"
	"../gcc-src/configure" --target=x86_64-w64-mingw32 --disable-bootstrap --enable-targets=all "--enable-languages=${GCC_LANGS}" $GCC_HOST_CONFIG --disable-cloog-version-check --enable-cloog-backend=isl "--with-gmp=${HOST}/host" "--with-mpfr=${HOST}/host" "--with-mpc=${HOST}/host" "--with-isl=${HOST}/host" "--with-cloog=${HOST}/host" "--with-system-zlib=${HOST}/host" "LDFLAGS=-Wl,-rpath,${HOST}/host/lib" "--prefix=${HOST}" "--with-sysroot=${HOST}" "--libdir=${HOST}/x86_64-w64-mingw32/lib" "--libexecdir=${HOST}/x86_64-w64-mingw32/lib" "--with-native-system-header-dir=/x86_64-w64-mingw32/include" >>"${LOG}" 2>&1 || error "Failed to configure ${GCC}."
	sed -i '/^FLAGS_FOR_TARGET =/s|mingw|i686-w64-mingw32|g' Makefile || error "Failed to patch Makefile."
	sed -i '/^FLAGS_FOR_TARGET =/s|i686-w64-mingw32/lib |i686-w64-mingw32/lib -isystem ${prefix}/include |g' Makefile || error "Failed to patch Makefile."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${GCC}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${GCC}."
fi

if step 'build cross compiler - fix lto plugin'; then
	ln -s "${HOST}/x86_64-w64-mingw32/lib/gcc/x86_64-w64-mingw32/${GCC#gcc-}/liblto_plugin.so" "${HOST}/i686-w64-mingw32/lib/bfd-plugins/liblto_plugin.so" || error "Failed to create link ${HOST}/i686-w64-mingw32/lib/bfd-plugins/liblto_plugin.so."
	ln -s "${HOST}/x86_64-w64-mingw32/lib/gcc/x86_64-w64-mingw32/${GCC#gcc-}/liblto_plugin.so" "${HOST}/x86_64-w64-mingw32/lib/bfd-plugins/liblto_plugin.so" || error "Failed to create link ${HOST}/x86_64-w64-mingw32/lib/bfd-plugins/liblto_plugin.so."
fi

# build final (host == target) toolchain

if step "build ${ZLIB:-zlib}"; then
	rm -rf "${BUILD}/zlib"
	rcp -r "${SRC}/${ZLIB}" "${BUILD}/zlib" || error "Failed to copy zlib source to ${BUILD}/zlib."
	cd "${BUILD}/zlib"
	make -j $THREADS -f win32/Makefile.gcc PREFIX=x86_64-w64-mingw32- AR=x86_64-w64-mingw32-gcc-ar "CFLAGS=${CFLAGS}" "LDFLAGS=${LDFLAGS}" >>"${LOG}" 2>&1 || error "Failed to build ${ZLIB}."
	make -j $THREADS -f win32/Makefile.gcc install PREFIX=x86_64-w64-mingw32- AR=x86_64-w64-mingw32-gcc-ar "CFLAGS=${CFLAGS}" "LDFLAGS=${LDFLAGS}" "prefix=${HOST}/x86_64-w64-mingw32" "BINARY_PATH=${HOST}/x86_64-w64-mingw32/bin" "INCLUDE_PATH=${HOST}/x86_64-w64-mingw32/include" "LIBRARY_PATH=${HOST}/x86_64-w64-mingw32/lib" >>"${LOG}" 2>&1 || error "Failed to build ${ZLIB}."
fi

if step "build ${ZSTD:-zstd}"; then
	if [ "x${ZSTD}" != 'x' ]; then
		rm -rf "${BUILD}/zstd"
		rcp -r "${SRC}/${ZSTD}" "${BUILD}/zstd" || error "Failed to copy zstd source to ${BUILD}/zstd."
		cd "${BUILD}/zstd"
		make -j $THREADS -C lib lib-release TARGET_SYSTEM=Windows_NT CC=x86_64-w64-mingw32-gcc WINDRES=x86_64-w64-mingw32-windres AR=x86_64-w64-mingw32-ar "CFLAGS=${CFLAGS}" "LDFLAGS=${LDFLAGS}" >>"${LOG}" 2>&1 || error "Failed to build ${ZSTD}."
		make -j $THREADS -C lib install-static install-includes TARGET_SYSTEM=Windows_NT CC=x86_64-w64-mingw32-gcc WINDRES=x86_64-w64-mingw32-windres AR=x86_64-w64-mingw32-ar "CFLAGS=${CFLAGS}" "LDFLAGS=${LDFLAGS}" "prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to build ${ZSTD}."
		sed -i '/Dependencies/a \#define ZSTD_STATIC_LINKING_ONLY' "${HOST}/x86_64-w64-mingw32/include/zstd.h"
		WITH_ZSTD='--with-zstd'
		ZIP_OPT='zstd'
	else
		WITH_ZSTD=''
		ZIP_OPT='zlib'
		echo 'Skipped. Not configured.'
	fi
fi

if step "build ${GMP:-gmp}"; then
	mkdir -p "${BUILD}/gmp" || error "Failed to create ${BUILD}/gmp."
	cd "${BUILD}/gmp"
	CPPFLAGS="-fexceptions" "${SRC}/${GMP}/configure" --host=x86_64-w64-mingw32 --enable-static --disable-shared --disable-cxx "--prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to configure ${GMP}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${GMP}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${GMP}."
fi

if step "build ${MPFR:-mpfr}"; then
	mkdir -p "${BUILD}/mpfr" || error "Failed to create ${BUILD}/mpfr."
	cd "${BUILD}/mpfr"
	"${SRC}/${MPFR}/configure" --host=x86_64-w64-mingw32 --enable-static --disable-shared "--with-gmp=${HOST}/x86_64-w64-mingw32" "--prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to configure ${MPFR}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MPFR}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${MPFR}."
fi

if step "build ${MPC:-mpc}"; then
	mkdir -p "${BUILD}/mpc" || error "Failed to create ${BUILD}/mpc."
	cd "${BUILD}/mpc"
	"${SRC}/${MPC}/configure" --host=x86_64-w64-mingw32 --enable-static --disable-shared "--with-gmp=${HOST}/x86_64-w64-mingw32" "--with-mpfr=${HOST}/x86_64-w64-mingw32" "--prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to configure ${MPC}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MPC}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${MPC}."
fi

if step "build ${ISL:-isl}"; then
	mkdir -p "${BUILD}/isl" || error "Failed to create ${BUILD}/isl."
	cd "${BUILD}/isl"
	"${SRC}/${ISL}/configure" --host=x86_64-w64-mingw32 --enable-static --disable-shared --enable-portable-binary "--with-gmp-prefix=${HOST}/x86_64-w64-mingw32" "--prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to configure ${ISL}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${ISL}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${ISL}."
fi

if step "build ${CLOOG_ISL:-cloog-isl}"; then
	mkdir -p "${BUILD}/cloog" || error "Failed to create ${BUILD}/cloog."
	cd "${BUILD}/cloog"
	"${SRC}/${CLOOG_ISL}/configure" --host=x86_64-w64-mingw32 --enable-static --disable-shared --enable-portable-binary --with-osl=no "--with-gmp-prefix=${HOST}/x86_64-w64-mingw32" "--with-isl-prefix=${HOST}/x86_64-w64-mingw32" "--prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to configure ${CLOOG_ISL}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${CLOOG_ISL}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${CLOOG_ISL}."
fi

if step "build ${BINUTILS:-binutils}"; then
	mkdir -p "${BUILD}/binutils" || error "Failed to create ${BUILD}/binutils."
	cd "${BUILD}/binutils"
	"${SRC}/${BINUTILS}/configure" --host=x86_64-w64-mingw32 --target=x86_64-w64-mingw32 --enable-targets=x86_64-w64-mingw32,i686-w64-mingw32 --enable-lto --enable-plugins --disable-nls "--with-system-zlib=${HOST}/x86_64-w64-mingw32" "--with-sysroot=${PREFIX}" "--prefix=${PREFIX}" "--with-sysroot=${PREFIX}" "--libdir=${PREFIX}/x86_64-w64-mingw32/lib" >>"${LOG}" 2>&1 || error "Failed to configure ${BINUTILS}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${BINUTILS}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${BINUTILS}."
fi

if step "build ${MINGW:-mingw} - C headers"; then
	mkdir -p "${BUILD}/mingw-headers" || error "Failed to create ${BUILD}/mingw-headers."
	cd "${BUILD}/mingw-headers"
	"${BUILD}/mingw-w64-headers/configure" --host=x86_64-w64-mingw32 "--with-default-msvcrt=${MCRTDLL}" --enable-sdk=all "--prefix=${PREFIX}" "--with-sysroot=${PREFIX}" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - C headers."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - C headers."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - C headers."
fi

if step "build ${MINGW:-mingw} - C runtime"; then
	mkdir -p "${BUILD}/mingw-crt" || error "Failed to create ${BUILD}/mingw-crt."
	cd "${BUILD}/mingw-crt"
	"${SRC}/${MINGW}/mingw-w64-crt/configure" --host=x86_64-w64-mingw32 "--with-default-msvcrt=${MCRTDLL}" --enable-lib32 --enable-lib64 --disable-dependency-tracking "--with-sysroot=${PREFIX}" "--prefix=${PREFIX}" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - C runtime."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - C runtime."
	make install "lib32dir=${PREFIX}/i686-w64-mingw32/lib" "lib64dir=${PREFIX}/x86_64-w64-mingw32/lib" >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - C runtime."
fi

if step "build ${MINGW:-mingw} - pthreads - 32-bit"; then
	mkdir -p "${BUILD}/mingw-pthread-32" || error "Failed to create ${BUILD}/mingw-pthread-32."
	cd "${BUILD}/mingw-pthread-32"
	"${SRC}/${MINGW}/mingw-w64-libraries/winpthreads/configure" --host=i686-w64-mingw32 --disable-shared --disable-dependency-tracking "CC=x86_64-w64-mingw32-gcc -m32" "CXX=x86_64-w64-mingw32-g++ -m32" "STRIP=x86_64-w64-mingw32-strip" "AR=x86_64-w64-mingw32-gcc-ar" "RC=x86_64-w64-mingw32-windres -F pe-i386" "--prefix=${PREFIX}/i686-w64-mingw32" "--with-sysroot=${PREFIX}/i686-w64-mingw32" "--includedir=${PREFIX}/include" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - pthreads - 32-bit."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - pthreads - 32-bit."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - pthreads - 32-bit."
	# fix static build
	find "${PREFIX}" -type f -name "pthread.h" -exec sed -i 's/ DLL_EXPORT/ WINPTHREAD_DLL_EXPORT/g' '{}' ';'
fi

if step "build ${MINGW:-mingw} - pthreads - 64-bit"; then
	mkdir -p "${BUILD}/mingw-pthread-64" || error "Failed to create ${BUILD}/mingw-pthread-64."
	cd "${BUILD}/mingw-pthread-64"
	"${SRC}/${MINGW}/mingw-w64-libraries/winpthreads/configure" --host=x86_64-w64-mingw32 --disable-shared --disable-dependency-tracking "--prefix=${PREFIX}/x86_64-w64-mingw32" "--with-sysroot=${PREFIX}/x86_64-w64-mingw32" "--includedir=${PREFIX}/include" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - pthreads - 64-bit."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - pthreads - 64-bit."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - pthreads - 64-bit."
	# fix static build
	find "${PREFIX}" -type f -name "pthread.h" -exec sed -i 's/ DLL_EXPORT/ WINPTHREAD_DLL_EXPORT/g' '{}' ';'
fi

if step "build ${MINGW:-mingw} - gendef"; then
	if test -f "${SRC}/${MINGW}/mingw-w64-tools/gendef/configure"; then
		mkdir -p "${BUILD}/mingw-gendef" || error "Failed to create ${BUILD}/mingw-gendef."
		cd "${BUILD}/mingw-gendef"
		"${SRC}/${MINGW}/mingw-w64-tools/gendef/configure" --host=x86_64-w64-mingw32 --disable-dependency-tracking "--prefix=${PREFIX}" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - gendef."
		make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - gendef."
		make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - gendef."
	else
		echo 'Skipped. Not found.'
	fi
fi

if step "build ${MINGW:-mingw} - genidl"; then
	if test -f "${SRC}/${MINGW}/mingw-w64-tools/genidl/configure"; then
		mkdir -p "${BUILD}/mingw-genidl" || error "Failed to create ${BUILD}/mingw-genidl."
		cd "${BUILD}/mingw-genidl"
		"${SRC}/${MINGW}/mingw-w64-tools/genidl/configure" --host=x86_64-w64-mingw32 --disable-dependency-tracking "--prefix=${PREFIX}" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - genidl."
		make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - genidl."
		make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - genidl."
	else
		echo 'Skipped. Not found.'
	fi
fi

if step "build ${MINGW:-mingw} - genlib"; then
	if test -f "${SRC}/${MINGW}/mingw-w64-tools/genlib/configure"; then
		mkdir -p "${BUILD}/mingw-genlib" || error "Failed to create ${BUILD}/mingw-genlib."
		cd "${BUILD}/mingw-genlib"
		"${SRC}/${MINGW}/mingw-w64-tools/genlib/configure" --host=x86_64-w64-mingw32 --disable-dependency-tracking "--prefix=${PREFIX}" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - genlib."
		make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - genlib."
		make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - genlib."
	else
		echo 'Skipped. Not found.'
	fi
fi

if step "build ${MINGW:-mingw} - genpeimg"; then
	if test -f "${SRC}/${MINGW}/mingw-w64-tools/genpeimg/configure"; then
		mkdir -p "${BUILD}/mingw-genpeimg" || error "Failed to create ${BUILD}/mingw-genpeimg."
		cd "${BUILD}/mingw-genpeimg"
		"${SRC}/${MINGW}/mingw-w64-tools/genpeimg/configure" --host=x86_64-w64-mingw32 --disable-dependency-tracking "--prefix=${PREFIX}" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - genpeimg."
		make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - genpeimg."
		make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - genpeimg."
	else
		echo 'Skipped. Not found.'
	fi
fi

if step "build ${MINGW:-mingw} - widl"; then
	if test -f "${SRC}/${MINGW}/mingw-w64-tools/widl/configure"; then
		mkdir -p "${BUILD}/mingw-widl" || error "Failed to create ${BUILD}/mingw-widl."
		cd "${BUILD}/mingw-widl"
		"${SRC}/${MINGW}/mingw-w64-tools/widl/configure" --host=x86_64-w64-mingw32 --disable-dependency-tracking "--prefix=${PREFIX}" >>"${LOG}" 2>&1 || error "Failed to configure ${MINGW} - widl."
		make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${MINGW} - widl."
		make install >>"${LOG}" 2>&1 || error "Failed to install ${MINGW} - widl."
	else
		echo 'Skipped. Not found.'
	fi
fi

if step 'build OpenCL'; then
	if [ "x${OCL_SDK}" != 'x' ]; then
		# install headers
		mkdir -p "${PREFIX}/include/CL" || error "Failed to create ${PREFIX}/include/CL."
		install -m 644 "${SRC}/${OCL_SDK}/external/OpenCL-Headers/CL/"* "${PREFIX}/include/CL/" || error "Failed to install OpenCL headers."
		# build and install import library
		"${HOST}/bin/x86_64-w64-mingw32-dlltool" --as-flags=--32 -d "${SRC}/${OCL_SDK}/external/OpenCL-ICD-Loader/loader/windows/OpenCL-mingw-i686.def" -D OpenCL.dll -m i386 -l "${PREFIX}/i686-w64-mingw32/lib/libopencl.a" || error "Failed to build OpenCL 32-bit import library."
		"${HOST}/bin/x86_64-w64-mingw32-dlltool" --as-flags=--64 -d "${SRC}/${OCL_SDK}/external/OpenCL-ICD-Loader/loader/windows/OpenCL.def" -D OpenCL.dll -m i386:x86-64 -l "${PREFIX}/x86_64-w64-mingw32/lib/libopencl.a" || error "Failed to build OpenCL 64-bit import library."
	else
		echo 'Skipped. Not configured.'
	fi
fi

if step "build final ${GCC}"; then
	mkdir -p "${BUILD}/gcc" || error "Failed to create ${BUILD}/gcc."
	cd "${BUILD}/gcc"
	"../gcc-src/configure" --host=x86_64-w64-mingw32 --target=x86_64-w64-mingw32 --disable-bootstrap --enable-targets=all "--enable-languages=${GCC_LANGS}" $GCC_TARGET_CONFIG "--enable-default-compressed-debug-sections-algorithm=${ZIP_OPT}" --disable-cloog-version-check --enable-cloog-backend=isl "--with-gmp=${HOST}/x86_64-w64-mingw32" "--with-mpfr=${HOST}/x86_64-w64-mingw32" "--with-mpc=${HOST}/x86_64-w64-mingw32" "--with-isl=${HOST}/x86_64-w64-mingw32" "--with-cloog=${HOST}/x86_64-w64-mingw32" "--with-system-zlib=${HOST}/x86_64-w64-mingw32" "${WITH_ZSTD}" "--prefix=${PREFIX}" "--libdir=${PREFIX}/x86_64-w64-mingw32/lib" "--libexecdir=${PREFIX}/x86_64-w64-mingw32/lib" "--with-native-system-header-dir=/x86_64-w64-mingw32/include" >>"${LOG}" 2>&1 || error "Failed to configure ${GCC}."
	sed -i '/^FLAGS_FOR_TARGET =/s|mingw|i686-w64-mingw32|g' Makefile || error "Failed to patch Makefile."
	sed -i '/^FLAGS_FOR_TARGET =/s|i686-w64-mingw32/lib |i686-w64-mingw32/lib -isystem ${prefix}/include |g' Makefile || error "Failed to patch Makefile."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${GCC}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${GCC}."
fi

if step "final adjustments for ${GCC}"; then
	# correct LTO plugin paths
	cd "${PREFIX}/bin" && ln -s "../x86_64-w64-mingw32/lib/gcc/x86_64-w64-mingw32/${GCC#gcc-}/liblto_plugin.dll" "liblto_plugin.dll" || error "Failed to create link ${PREFIX}/i686-w64-mingw32/lib/bfd-plugins/liblto_plugin.dll."
	cd "${PREFIX}/i686-w64-mingw32/lib/bfd-plugins/" && ln -s "../../../x86_64-w64-mingw32/lib/gcc/x86_64-w64-mingw32/${GCC#gcc-}/liblto_plugin.dll" "liblto_plugin.dll" || error "Failed to create link ${PREFIX}/i686-w64-mingw32/lib/bfd-plugins/liblto_plugin.dll."
	cd "${PREFIX}/x86_64-w64-mingw32/lib/bfd-plugins/" && ln -s "../../../x86_64-w64-mingw32/lib/gcc/x86_64-w64-mingw32/${GCC#gcc-}/liblto_plugin.dll" "liblto_plugin.dll" || error "Failed to create link ${PREFIX}/x86_64-w64-mingw32/lib/bfd-plugins/liblto_plugin.dll."
	# install missing libstdc++ DLLs
	if [ "$(ls -1 "${BUILD}/gcc/x86_64-w64-mingw32/libstdc++-v3/src/.libs/" 2>/dev/null | wc -l)" -gt 0 ]; then
		install -m 644 "${BUILD}/gcc/x86_64-w64-mingw32/libstdc++-v3/src/.libs/"*.dll "${PREFIX}/x86_64-w64-mingw32/lib/gcc/x86_64-w64-mingw32/${GCC#gcc-}/" || error "Failed to install GCC x64 DLLs."
	fi
	if [ "$(ls -1 "${BUILD}/gcc/x86_64-w64-mingw32/32/libstdc++-v3/src/.libs/" 2>/dev/null | wc -l)" -gt 0 ]; then
		install -m 644 "${BUILD}/gcc/x86_64-w64-mingw32/32/libstdc++-v3/src/.libs/"*.dll "${PREFIX}/x86_64-w64-mingw32/lib/gcc/x86_64-w64-mingw32/${GCC#gcc-}/32" || error "Failed to install GCC x86 DLLs."
	fi
	# remove unused host libstdc++ DLL if found (all executable have been linked statically)
	rm -f "${PREFIX}/bin/libstdc++"*.dll 2>/dev/null
fi

# build target gdb

if step "build ${EXPAT:-expat}"; then
	mkdir -p "${BUILD}/expat" || error "Failed to create ${BUILD}/expat."
	cd "${BUILD}/expat"
	"${SRC}/${EXPAT}/configure" --host=x86_64-w64-mingw32 --enable-static --disable-shared --disable-dependency-tracking --without-examples --without-tests --without-docbook "--prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to configure ${EXPAT}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${EXPAT}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${EXPAT}."
fi

if step "build ${BOOST:-boost}"; then
	rm -rf "${BUILD}/boost"
	rcp -r "${SRC}/${BOOST}" "${BUILD}/boost" || error "Failed to copy Boost source to ${BUILD}/boost."
	cd "${BUILD}/boost"
	echo "using gcc : mingw : ${HOST}/bin/x86_64-w64-mingw32-g++ ;" >'tools/build/src/user-config.jam' || error "Failed to create ${BUILD}/boost/tools/build/src/user-config.jam."
	sed -i 's/B2_CXXFLAGS_RELEASE="-O/B2_CXXFLAGS_RELEASE="-static -O/g' 'tools/build/src/engine/build.sh' || error "Failed to patch ${BUILD}/boost/tools/build/src/engine/build.sh."
	./bootstrap.sh >>"${LOG}" 2>&1
	sed -i 's/_MSC_VER/_WIN32/' 'libs/stacktrace/src/from_exception.cpp' || error "Failed to patch ${BUILD}/boost/libs/stacktrace/src/from_exception.cpp."
	./b2 pch=off -a -d 1 -j $THREADS --build-dir=build --with-regex toolset=gcc-mingw target-os=windows architecture=x86 address-model=64 abi=ms binary-format=pe link=static runtime-link=static boost.locale.iconv=off define=BOOST_USE_WINDOWS_H cflags="${CFLAGS}" cxxflags="${CXXFLAGS}" variant=release --layout=system stage >>"${LOG}" 2>&1 || error "Failed to build ${BOOST}."
	ln -sf "${PWD}/boost" "${HOST}/x86_64-w64-mingw32/include/boost" || error "Failed to create link ${HOST}/x86_64-w64-mingw32/include/boost."
	cp -f stage/lib/*.a "${HOST}/x86_64-w64-mingw32/lib" || error "Failed to install ${BOOST}."
fi

if step "build host ${NCURSES:-ncurses}"; then
	mkdir -p "${BUILD}/host-ncurses" || error "Failed to create ${BUILD}/host-ncurses."
	cd "${BUILD}/host-ncurses"
	"${SRC}/${NCURSES}/configure" --enable-static --disable-shared --disable-getcap --disable-hard-tabs --disable-home-terminfo --disable-lib-suffixes --disable-mixed-case --disable-overwrite --disable-rpath --disable-symlinks --disable-termcap --enable-assertions --enable-colorfgbg --enable-database --enable-ext-colors --enable-ext-funcs --enable-ext-mouse --enable-interop --enable-opaque-curses --enable-opaque-form --enable-opaque-menu --enable-opaque-panel --enable-sigwinch --enable-sp-funcs --enable-term-driver --with-cxx --without-ada --without-debug --without-libtool --without-pthread --without-tests "--prefix=${HOST}/host" >>"${LOG}" 2>&1 || error "Failed to configure host ${NCURSES}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build host ${NCURSES}."
	make install >>"${LOG}" 2>&1 || error "Failed to install host ${NCURSES}."
	test -d "${PREFIX}/share/tabset" -o "x${i}" != 'x' || rcp -rf "${HOST}/host/share/tabset" "${PREFIX}/share/"
	test -d "${PREFIX}/share/terminfo" -o "x${i}" != 'x' || rcp -rf "${HOST}/host/share/terminfo" "${PREFIX}/share/"
fi

if step "build ${NCURSES:-ncurses}"; then
	rm -rf "${BUILD}/ncurses"
	rcp -r "${SRC}/${NCURSES}" "${BUILD}/ncurses" || error "Failed to copy ${NCURSES} source to ${BUILD}/ncurses."
	cd "${BUILD}/ncurses"
	# fix NULL pointer dereference and exp-win32 driver
	patch -p1 <<'_PATCH' >>"${LOG}" 2>&1 || error "Failed to patch ${BUILD}/ncurses."
diff -uar ncurses-6.5-org/include/nc_win32.h ncurses-6.5/include/nc_win32.h
--- ncurses-6.5-org/include/nc_win32.h	2023-02-25 21:09:23.000000000 +0100
+++ ncurses-6.5/include/nc_win32.h	2025-02-11 09:29:27.178870200 +0100
@@ -105,6 +105,7 @@
 extern NCURSES_EXPORT(int)    _nc_console_keyok(int keycode,int flag);
 extern NCURSES_EXPORT(bool)   _nc_console_keyExist(int keycode);
 extern NCURSES_EXPORT(bool)   _nc_console_checkinit(bool initFlag, bool assumeTermInfo);
+extern NCURSES_EXPORT(bool)   _nc_console_restore(void);
 extern NCURSES_EXPORT(int)    _nc_console_vt_supported(void);
 
 #ifdef _NC_CHECK_MINTTY
diff -uar ncurses-6.5-org/ncurses/base/lib_mouse.c ncurses-6.5/ncurses/base/lib_mouse.c
--- ncurses-6.5-org/ncurses/base/lib_mouse.c	2024-02-17 22:13:01.000000000 +0100
+++ ncurses-6.5/ncurses/base/lib_mouse.c	2025-02-06 13:51:15.881387800 +0100
@@ -646,7 +646,7 @@
     /* OS/2 VIO */
 #if USE_EMX_MOUSE
     if (!sp->_emxmouse_thread
-	&& strstr(SP_TERMTYPE term_names, "xterm") == 0
+	&& SP_TERMTYPE term_names && strstr(SP_TERMTYPE term_names, "xterm") == 0
 	&& NonEmpty(key_mouse)) {
 	int handles[2];
 
@@ -761,7 +761,7 @@
     /* we know how to recognize mouse events under "xterm" */
     if (NonEmpty(key_mouse)) {
 	init_xterm_mouse(sp);
-    } else if (strstr(SP_TERMTYPE term_names, "xterm") != 0) {
+    } else if (SP_TERMTYPE term_names && strstr(SP_TERMTYPE term_names, "xterm") != 0) {
 	if (_nc_add_to_try(&(sp->_keytry), xterm_kmous, KEY_MOUSE) == OK)
 	    init_xterm_mouse(sp);
     }
diff -uar ncurses-6.5-org/ncurses/tinfo/lib_win32con.c ncurses-6.5/ncurses/tinfo/lib_win32con.c
--- ncurses-6.5-org/ncurses/tinfo/lib_win32con.c	2023-08-05 22:44:38.000000000 +0200
+++ ncurses-6.5/ncurses/tinfo/lib_win32con.c	2025-02-11 10:35:36.143421200 +0100
@@ -259,36 +259,20 @@
 	T(("lib_win32con:_nc_console_setmode %s", _nc_trace_ttymode(arg)));
 	if (hdl == WINCONSOLE.inp) {
 	    dwFlag = arg->dwFlagIn | ENABLE_MOUSE_INPUT | VT_FLAG_IN;
-	    if (WINCONSOLE.isTermInfoConsole)
-		dwFlag |= (VT_FLAG_IN);
-	    else
-		dwFlag &= (DWORD) ~ (VT_FLAG_IN);
 	    TRCTTYIN(dwFlag);
 	    SetConsoleMode(hdl, dwFlag);
 
 	    alt = OutHandle();
 	    dwFlag = arg->dwFlagOut;
-	    if (WINCONSOLE.isTermInfoConsole)
-		dwFlag |= (VT_FLAG_OUT);
-	    else
-		dwFlag |= (VT_FLAG_OUT);
 	    TRCTTYOUT(dwFlag);
 	    SetConsoleMode(alt, dwFlag);
 	} else {
 	    dwFlag = arg->dwFlagOut;
-	    if (WINCONSOLE.isTermInfoConsole)
-		dwFlag |= (VT_FLAG_OUT);
-	    else
-		dwFlag |= (VT_FLAG_OUT);
 	    TRCTTYOUT(dwFlag);
 	    SetConsoleMode(hdl, dwFlag);
 
 	    alt = WINCONSOLE.inp;
 	    dwFlag = arg->dwFlagIn | ENABLE_MOUSE_INPUT;
-	    if (WINCONSOLE.isTermInfoConsole)
-		dwFlag |= (VT_FLAG_IN);
-	    else
-		dwFlag &= (DWORD) ~ (VT_FLAG_IN);
 	    TRCTTYIN(dwFlag);
 	    SetConsoleMode(alt, dwFlag);
 	    T(("effective mode set %s", _nc_trace_ttymode(&TRCTTY)));
@@ -404,7 +388,6 @@
     return result;
 }
 
-#if 0
 static bool
 restore_original_screen(void)
 {
@@ -426,7 +409,7 @@
 		     bufferCoord,
 		     &save_region)) {
 	result = TRUE;
-	mvcur(-1, -1, LINES - 2, 0);
+	SetConsoleCursorPosition(WINCONSOLE.hdl, WINCONSOLE.save_SBI.dwCursorPosition);
 	T(("... restore original screen contents ok %dx%d (%d,%d - %d,%d)",
 	   WINCONSOLE.save_size.Y,
 	   WINCONSOLE.save_size.X,
@@ -439,7 +422,6 @@
     }
     return result;
 }
-#endif
 
 static bool
 read_screen_data(void)
@@ -1248,5 +1230,21 @@
     }
     returnBool(res);
 }
+
+NCURSES_EXPORT(bool)
+_nc_console_restore(void)
+{
+    bool res = FALSE;
+    if (WINCONSOLE.hdl != INVALID_HANDLE_VALUE) {
+	res = TRUE;
+	if (!WINCONSOLE.buffered) {
+	    _nc_console_set_scrollback(TRUE, &WINCONSOLE.save_SBI);
+	    if (!restore_original_screen())
+		res = FALSE;
+	}
+	SetConsoleCursorInfo(WINCONSOLE.hdl, &WINCONSOLE.save_CI);
+    }
+    returnBool(res);
+}
 
 #endif // _NC_WINDOWS
diff -uar ncurses-6.5-org/ncurses/tinfo/tinfo_driver.c ncurses-6.5/ncurses/tinfo/tinfo_driver.c
--- ncurses-6.5-org/ncurses/tinfo/tinfo_driver.c	2023-09-16 12:44:33.000000000 +0200
+++ ncurses-6.5/ncurses/tinfo/tinfo_driver.c	2025-02-11 09:29:18.474169700 +0100
@@ -628,6 +628,11 @@
 		    if (sp->_keypad_on)
 			_nc_keypad(sp, TRUE);
 		}
+#if defined(EXP_WIN32_DRIVER)
+		if (!WINCONSOLE.buffered) {
+		    _nc_console_set_scrollback(FALSE, &WINCONSOLE.SBI);
+		}
+#endif
 		code = OK;
 	    }
 	}
@@ -656,6 +661,10 @@
 		NCURSES_SP_NAME(_nc_flush) (sp);
 	    }
 	    code = drv_sgmode(TCB, TRUE, &(_term->Ottyb));
+#if defined(EXP_WIN32_DRIVER)
+	    if (!_nc_console_restore())
+		code = ERR;
+#endif
 	}
     }
     return (code);
_PATCH
	./configure --host=x86_64-w64-mingw32 --target=x86_64-w64-mingw32 --enable-static --disable-shared --disable-getcap --disable-hard-tabs --disable-home-terminfo --disable-lib-suffixes --disable-mixed-case --disable-overwrite --disable-rpath --disable-symlinks --disable-termcap --enable-assertions --enable-colorfgbg --enable-database --enable-exp-win32 --enable-ext-colors --enable-ext-funcs --enable-ext-mouse --enable-interop --enable-opaque-curses --enable-opaque-form --enable-opaque-menu --enable-opaque-panel --enable-sigwinch --enable-sp-funcs --enable-term-driver --enable-widec --with-cxx --with-fallbacks=ms-terminal --without-ada --without-debug --without-libtool --without-pthread --without-tests "--prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to configure ${NCURSES}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${NCURSES}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${NCURSES}."
	sed -i '/if defined(NCURSES_STATIC)/i # define NCURSES_STATIC' "${HOST}/x86_64-w64-mingw32/include/ncurses"*"/ncurses_dll.h"
fi

if step "build ${HIGHLIGHT:-src-highlight}"; then
	rm -rf "${BUILD}/src-highlight"
	rcp -r "${SRC}/${HIGHLIGHT}" "${BUILD}/src-highlight" || error "Failed to copy src-highlight source to ${BUILD}/src-highlight."
	cd "${BUILD}/src-highlight"
	# enable C++17 support
	for i in cc h; do sed -i 's/ throw (IOException)//g' "lib/srchilite/fileutil.${i}" || error "Failed to patch ${HIGHLIGHT}/lib/srchilite/fileutil.${i}"; done
	# ensure static build
	find . -type f -name "Makefile.in" -exec sed -i 's/@LDFLAGS@/@LDFLAGS@ -all-static/g' '{}' ';' || error "Failed to patch ${HIGHLIGHT}/**/Makefile.in."
	./configure --host=x86_64-w64-mingw32 --enable-static --disable-shared --disable-dependency-tracking --with-boost "--with-boost-libdir=${HOST}/x86_64-w64-mingw32/lib" "--prefix=${HOST}/x86_64-w64-mingw32" "--datarootdir=${PREFIX}/share" "LDFLAGS=${LDFLAGS} -Wl,--allow-multiple-definition" "LIBS=-lpthread" >>"${LOG}" 2>&1 || error "Failed to configure ${HIGHLIGHT}."
	# do not build doc (cannot run source-highlight.exe on Linux)
	sed -i '/^SUBDIRS =/s/ doc//g' Makefile || error "Failed to patch ${HIGHLIGHT}/Makefile."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${HIGHLIGHT}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${HIGHLIGHT}."
	# prevent incorrect linking with libstdc++.dll.a
	rm -f "${HOST}/x86_64-w64-mingw32/lib/libsource-highlight.la"
fi

if step "build ${IPT:-ipt}"; then
	rm -rf "${BUILD}/ipt"
	rcp -r "${SRC}/${IPT}" "${BUILD}/ipt" || error "Failed to copy ipt source to ${BUILD}/ipt."
	cd "${BUILD}/ipt"
	sed -i 's/CMAKE_HOST_WIN32/TRUE/g;s/CMAKE_HOST_UNIX/FALSE/g' 'CMakeLists.txt' || error "Failed to patch ${IPT}/CMakeLists.txt."
	sed -i 's/CMAKE_HOST_WIN32/TRUE/g;s/CMAKE_HOST_UNIX/FALSE/g' 'libipt/CMakeLists.txt' || error "Failed to patch ${IPT}/libipt/CMakeLists.txt."
	cmake --install-prefix "${HOST}/x86_64-w64-mingw32" -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY -DBUILD_SHARED_LIBS=OFF "-DCMAKE_C_COMPILER=${HOST}/bin/x86_64-w64-mingw32-gcc" "-DCMAKE_C_FLAGS=${CFLAGS}" "-DCMAKE_AR=${HOST}/bin/x86_64-w64-mingw32-gcc-ar" "-DCMAKE_RANLIB=${HOST}/bin/x86_64-w64-mingw32-gcc-ranlib" "-DCMAKE_EXE_LINKER_FLAGS=${LDFLAGS}" -DCMAKE_BUILD_TYPE=Release -DMAN=OFF -DPTUNIT=OFF -DPTDUMP=OFF -DPTXED=OFF -DPTTC=OFF -DSIDEBAND=OFF -DPEVENT=OFF -DFEATURE_THREADS=OFF . >>"${LOG}" 2>&1 || error "Failed create build scripts for ${IPT}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${IPT}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${IPT}."
fi

if step "build ${WINIPT:-winipt}"; then
	rm -rf "${BUILD}/winipt"
	rcp -r "${SRC}/${WINIPT}" "${BUILD}/winipt" || error "Failed to copy ipt source to ${BUILD}/winipt."
	cd "${BUILD}/winipt"
	sed -i 's/Windows/windows/g' 'libipt/win32.c' || error "Failed to patch ${WINIPT}/win32.c."
	"${HOST}/bin/x86_64-w64-mingw32-gcc" ${CFLAGS} '-I./inc' -DUNICODE -DERROR_IMPLEMENTATION_LIMIT=1292 -DUFIELD_OFFSET=FIELD_OFFSET -c 'libipt/win32.c' -o win32.o >>"${LOG}" 2>&1 || error "Failed to compile ${WINIPT}/win32.o."
	"${HOST}/bin/x86_64-w64-mingw32-gcc-ar" rcs libwinipt.a win32.o >>"${LOG}" 2>&1 || error "Failed to build archive ${WINIPT}/libwinipt.a."
	install -m 644 libwinipt.a "${HOST}/x86_64-w64-mingw32/lib/" || error "Failed to install ${WINIPT}/libwinipt.a."
	install -m 644 inc/libipt.h "${HOST}/x86_64-w64-mingw32/include/" || error "Failed to install ${WINIPT}/libipt.h."
fi

if step "build ${XXHASH:-xxhash}"; then
	rm -rf "${BUILD}/xxhash"
	rcp -r "${SRC}/${XXHASH}" "${BUILD}/xxhash" || error "Failed to copy xxhash source to ${BUILD}/xxhash."
	cd "${BUILD}/xxhash"
	make -j $THREADS DISPATCH=1 "CC=${HOST}/bin/x86_64-w64-mingw32-gcc" "AR=${HOST}/bin/x86_64-w64-mingw32-gcc-ar" "CFLAGS=${CFLAGS} -DXXH_STATIC_LINKING_ONLY=1 -DXXH_CPU_LITTLE_ENDIAN=1 -DXXH_ENABLE_AUTOVECTORIZE=1" "OS=Windows" >>"${LOG}" 2>&1 || error "Failed to build ${XXHASH}."
	install -m 644 libxxhash.a "${HOST}/x86_64-w64-mingw32/lib/" || error "Failed to install ${XXHASH}/libxxhash.a."
	for i in xxhash.h xxh3.h xxh_x86dispatch.h; do install -m 644 "${i}" "${HOST}/x86_64-w64-mingw32/include/" || error "Failed to install ${XXHASH}/${i}."; done
fi

if step "build host ${PYTHON:-python}"; then
	(
		unset CFLAGS
		unset CXXFLAGS
		unset LDFLAGS
		mkdir -p "${BUILD}/host-python" || error "Failed to create ${BUILD}/host-python."
		cd "${BUILD}/host-python"
		"${SRC}/${PYTHON}/configure" "--prefix=${HOST}/host" >>"${LOG}" 2>&1 || error "Failed to configure ${PYTHON}."
		make -j $THREADS "Programs/_freeze_module" >>"${LOG}" 2>&1 || error "Failed to build ${PYTHON}."
	)
fi

if step "build ${FFI:-ffi}"; then
	mkdir -p "${BUILD}/ffi" || error "Failed to create ${BUILD}/ffi."
	cd "${BUILD}/ffi"
	"${SRC}/${FFI}/configure" --host=x86_64-w64-mingw32 --enable-static --disable-shared --disable-dependency-tracking "--prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to configure ${FFI}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${FFI}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${FFI}."
fi

if step "build ${ICONV:-libiconv}"; then
	rm -rf "${BUILD}/iconv"
	rcp -r "${SRC}/${ICONV}" "${BUILD}/iconv" || error "Failed to copy libiconv source to ${BUILD}/iconv."
	cd "${BUILD}/iconv"
	sed -i 's|/\*"CP65001",|"CP65001",/\*|g' 'lib/encodings.def' || error "Failed to patch ${ICONV}/lib/encodings.def."
	sed -i 's/"w")/"w" BINARY_MODE)/g' 'lib/genaliases.c' || error "Failed to patch ${ICONV}/lib/genaliases.c."
	./configure --host=x86_64-w64-mingw32 --enable-static --disable-shared --disable-dependency-tracking "--prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to configure ${ICONV}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${ICONV}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${ICONV}."
fi

if step "patch ${PYTHON:-python} source"; then
	rm -rf "${BUILD}/python"
	rcp -r "${SRC}/${PYTHON}" "${BUILD}/python" || error "Failed to copy Python source to ${BUILD}/python."
	cd "${BUILD}/python"
	patch -p1 <<'_PATCH' >>"${LOG}" 2>&1 || error "Failed to patch ${BUILD}/python."
diff -uarN Python-3.13.7-org/Include/internal/pycore_fileutils.h Python-3.13.7/Include/internal/pycore_fileutils.h
--- Python-3.13.7-org/Include/internal/pycore_fileutils.h	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Include/internal/pycore_fileutils.h	2025-09-01 19:08:51.317997500 +0200
@@ -12,7 +12,7 @@
 
 
 /* A routine to check if a file descriptor can be select()-ed. */
-#ifdef _MSC_VER
+#if defined(_MSC_VER) || defined(__MINGW32__)
     /* On Windows, any socket fd can be select()-ed, no matter how high */
     #define _PyIsSelectable_fd(FD) (1)
 #else
diff -uarN Python-3.13.7-org/Include/internal/pycore_time.h Python-3.13.7/Include/internal/pycore_time.h
--- Python-3.13.7-org/Include/internal/pycore_time.h	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Include/internal/pycore_time.h	2025-09-01 19:08:51.327287300 +0200
@@ -58,7 +58,7 @@
 #endif
 
 
-#ifdef __clang__
+#if defined(__clang__) || defined(__MINGW32__)
 struct timeval;
 #endif
 
diff -uarN Python-3.13.7-org/Include/pymacro.h Python-3.13.7/Include/pymacro.h
--- Python-3.13.7-org/Include/pymacro.h	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Include/pymacro.h	2025-09-01 19:08:51.335086400 +0200
@@ -92,7 +92,7 @@
    Written by Rusty Russell, public domain, http://ccodearchive.net/
 
    Requires at GCC 3.1+ */
-#if (defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
+#if (defined(__GNUC__) && !defined(__MINGW32__) && !defined(__STRICT_ANSI__) && \
     (((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1)) || (__GNUC__ >= 4)))
 /* Two gcc extensions.
    &a[0] degrades to a pointer: a different type from an array */
diff -uarN Python-3.13.7-org/Modules/_blake2/impl/blake2b.c Python-3.13.7/Modules/_blake2/impl/blake2b.c
--- Python-3.13.7-org/Modules/_blake2/impl/blake2b.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/_blake2/impl/blake2b.c	2025-09-01 19:08:51.343797600 +0200
@@ -20,7 +20,7 @@
 
 #include "blake2-config.h"
 
-#if defined(_MSC_VER)
+#if defined(_MSC_VER) || defined(__MINGW32__)
 #include <intrin.h>
 #endif
 
@@ -44,7 +44,7 @@
 #if defined(HAVE_AVX)
 #include <immintrin.h>
 #endif
-#if defined(HAVE_XOP) && !defined(_MSC_VER)
+#if defined(HAVE_XOP) && !defined(_MSC_VER) && !defined(__MINGW32__)
 #include <x86intrin.h>
 #endif
 
diff -uarN Python-3.13.7-org/Modules/_blake2/impl/blake2s.c Python-3.13.7/Modules/_blake2/impl/blake2s.c
--- Python-3.13.7-org/Modules/_blake2/impl/blake2s.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/_blake2/impl/blake2s.c	2025-09-01 19:08:51.352185600 +0200
@@ -20,7 +20,7 @@
 
 #include "blake2-config.h"
 
-#if defined(_MSC_VER)
+#if defined(_MSC_VER) || defined(__MINGW32__)
 #include <intrin.h>
 #endif
 
@@ -45,7 +45,7 @@
 #if defined(HAVE_AVX)
 #include <immintrin.h>
 #endif
-#if defined(HAVE_XOP) && !defined(_MSC_VER)
+#if defined(HAVE_XOP) && !defined(_MSC_VER) && !defined(__MINGW32__)
 #include <x86intrin.h>
 #endif
 
diff -uarN Python-3.13.7-org/Modules/_ctypes/_ctypes_test.c Python-3.13.7/Modules/_ctypes/_ctypes_test.c
--- Python-3.13.7-org/Modules/_ctypes/_ctypes_test.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/_ctypes/_ctypes_test.c	2025-09-01 19:08:51.361504000 +0200
@@ -21,6 +21,11 @@
 #endif
 
 #define EXPORT(x) Py_EXPORTED_SYMBOL x
+#if defined(__MINGW32__) && !defined(__x86_64__)
+#  define DECORATE(x) _ ## x
+#else
+#  define DECORATE(x) x
+#endif
 
 /* some functions handy for testing */
 
@@ -761,19 +766,19 @@
 EXPORT(long double) tf_D(long double c) { S; return c/3; }
 
 #ifdef MS_WIN32
-EXPORT(signed char) __stdcall s_tf_b(signed char c) { S; return c/3; }
-EXPORT(unsigned char) __stdcall s_tf_B(unsigned char c) { U; return c/3; }
-EXPORT(short) __stdcall s_tf_h(short c) { S; return c/3; }
-EXPORT(unsigned short) __stdcall s_tf_H(unsigned short c) { U; return c/3; }
-EXPORT(int) __stdcall s_tf_i(int c) { S; return c/3; }
-EXPORT(unsigned int) __stdcall s_tf_I(unsigned int c) { U; return c/3; }
-EXPORT(long) __stdcall s_tf_l(long c) { S; return c/3; }
-EXPORT(unsigned long) __stdcall s_tf_L(unsigned long c) { U; return c/3; }
-EXPORT(long long) __stdcall s_tf_q(long long c) { S; return c/3; }
-EXPORT(unsigned long long) __stdcall s_tf_Q(unsigned long long c) { U; return c/3; }
-EXPORT(float) __stdcall s_tf_f(float c) { S; return c/3; }
-EXPORT(double) __stdcall s_tf_d(double c) { S; return c/3; }
-EXPORT(long double) __stdcall s_tf_D(long double c) { S; return c/3; }
+EXPORT(signed char) __stdcall DECORATE(s_tf_b)(signed char c) { S; return c/3; }
+EXPORT(unsigned char) __stdcall DECORATE(s_tf_B)(unsigned char c) { U; return c/3; }
+EXPORT(short) __stdcall DECORATE(s_tf_h)(short c) { S; return c/3; }
+EXPORT(unsigned short) __stdcall DECORATE(s_tf_H)(unsigned short c) { U; return c/3; }
+EXPORT(int) __stdcall DECORATE(s_tf_i)(int c) { S; return c/3; }
+EXPORT(unsigned int) __stdcall DECORATE(s_tf_I)(unsigned int c) { U; return c/3; }
+EXPORT(long) __stdcall DECORATE(s_tf_l)(long c) { S; return c/3; }
+EXPORT(unsigned long) __stdcall DECORATE(s_tf_L)(unsigned long c) { U; return c/3; }
+EXPORT(long long) __stdcall DECORATE(s_tf_q)(long long c) { S; return c/3; }
+EXPORT(unsigned long long) __stdcall DECORATE(s_tf_Q)(unsigned long long c) { U; return c/3; }
+EXPORT(float) __stdcall DECORATE(s_tf_f)(float c) { S; return c/3; }
+EXPORT(double) __stdcall DECORATE(s_tf_d)(double c) { S; return c/3; }
+EXPORT(long double) __stdcall DECORATE(s_tf_D)(long double c) { S; return c/3; }
 #endif
 /*******/
 
@@ -793,20 +798,20 @@
 EXPORT(void) tv_i(int c) { S; return; }
 
 #ifdef MS_WIN32
-EXPORT(signed char) __stdcall s_tf_bb(signed char x, signed char c) { S; return c/3; }
-EXPORT(unsigned char) __stdcall s_tf_bB(signed char x, unsigned char c) { U; return c/3; }
-EXPORT(short) __stdcall s_tf_bh(signed char x, short c) { S; return c/3; }
-EXPORT(unsigned short) __stdcall s_tf_bH(signed char x, unsigned short c) { U; return c/3; }
-EXPORT(int) __stdcall s_tf_bi(signed char x, int c) { S; return c/3; }
-EXPORT(unsigned int) __stdcall s_tf_bI(signed char x, unsigned int c) { U; return c/3; }
-EXPORT(long) __stdcall s_tf_bl(signed char x, long c) { S; return c/3; }
-EXPORT(unsigned long) __stdcall s_tf_bL(signed char x, unsigned long c) { U; return c/3; }
-EXPORT(long long) __stdcall s_tf_bq(signed char x, long long c) { S; return c/3; }
-EXPORT(unsigned long long) __stdcall s_tf_bQ(signed char x, unsigned long long c) { U; return c/3; }
-EXPORT(float) __stdcall s_tf_bf(signed char x, float c) { S; return c/3; }
-EXPORT(double) __stdcall s_tf_bd(signed char x, double c) { S; return c/3; }
-EXPORT(long double) __stdcall s_tf_bD(signed char x, long double c) { S; return c/3; }
-EXPORT(void) __stdcall s_tv_i(int c) { S; return; }
+EXPORT(signed char) __stdcall DECORATE(s_tf_bb)(signed char x, signed char c) { S; return c/3; }
+EXPORT(unsigned char) __stdcall DECORATE(s_tf_bB)(signed char x, unsigned char c) { U; return c/3; }
+EXPORT(short) __stdcall DECORATE(s_tf_bh)(signed char x, short c) { S; return c/3; }
+EXPORT(unsigned short) __stdcall DECORATE(s_tf_bH)(signed char x, unsigned short c) { U; return c/3; }
+EXPORT(int) __stdcall DECORATE(s_tf_bi)(signed char x, int c) { S; return c/3; }
+EXPORT(unsigned int) __stdcall DECORATE(s_tf_bI)(signed char x, unsigned int c) { U; return c/3; }
+EXPORT(long) __stdcall DECORATE(s_tf_bl)(signed char x, long c) { S; return c/3; }
+EXPORT(unsigned long) __stdcall DECORATE(s_tf_bL)(signed char x, unsigned long c) { U; return c/3; }
+EXPORT(long long) __stdcall DECORATE(s_tf_bq)(signed char x, long long c) { S; return c/3; }
+EXPORT(unsigned long long) __stdcall DECORATE(s_tf_bQ)(signed char x, unsigned long long c) { U; return c/3; }
+EXPORT(float) __stdcall DECORATE(s_tf_bf)(signed char x, float c) { S; return c/3; }
+EXPORT(double) __stdcall DECORATE(s_tf_bd)(signed char x, double c) { S; return c/3; }
+EXPORT(long double) __stdcall DECORATE(s_tf_bD)(signed char x, long double c) { S; return c/3; }
+EXPORT(void) __stdcall DECORATE(s_tv_i)(int c) { S; return; }
 #endif
 
 /********/
@@ -1124,8 +1129,8 @@
 #endif
 
 #ifdef MS_WIN32
-EXPORT(S2H) __stdcall s_ret_2h_func(S2H inp) { return ret_2h_func(inp); }
-EXPORT(S8I) __stdcall s_ret_8i_func(S8I inp) { return ret_8i_func(inp); }
+EXPORT(S2H) __stdcall DECORATE(s_ret_2h_func)(S2H inp) { return ret_2h_func(inp); }
+EXPORT(S8I) __stdcall DECORATE(s_ret_8i_func)(S8I inp) { return ret_8i_func(inp); }
 #endif
 
 #ifdef MS_WIN32
diff -uarN Python-3.13.7-org/Modules/_ctypes/ctypes.h Python-3.13.7/Modules/_ctypes/ctypes.h
--- Python-3.13.7-org/Modules/_ctypes/ctypes.h	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/_ctypes/ctypes.h	2025-09-01 19:08:51.369185700 +0200
@@ -36,7 +36,7 @@
 #endif
 
 #ifdef MS_WIN32
-#include <Unknwn.h> // for IUnknown interface
+#include <unknwn.h> // for IUnknown interface
 #endif
 
 typedef struct {
diff -uarN Python-3.13.7-org/Modules/_decimal/libmpdec/mpdecimal.h Python-3.13.7/Modules/_decimal/libmpdec/mpdecimal.h
--- Python-3.13.7-org/Modules/_decimal/libmpdec/mpdecimal.h	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/_decimal/libmpdec/mpdecimal.h	2025-09-01 19:08:51.376836100 +0200
@@ -30,7 +30,7 @@
 #define LIBMPDEC_MPDECIMAL_H_
 
 
-#ifndef _MSC_VER
+#if !defined(_MSC_VER) && !defined(__MINGW32__)
   #include "pyconfig.h"
 #endif
 
diff -uarN Python-3.13.7-org/Modules/_ssl.c Python-3.13.7/Modules/_ssl.c
--- Python-3.13.7-org/Modules/_ssl.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/_ssl.c	2025-09-01 19:08:51.385791800 +0200
@@ -5888,7 +5888,7 @@
     return result;
 }
 
-#ifdef _MSC_VER
+#if defined(_MSC_VER) || defined(__MINGW32__)
 
 static PyObject*
 certEncodingType(DWORD encodingType)
diff -uarN Python-3.13.7-org/Modules/_winapi.c Python-3.13.7/Modules/_winapi.c
--- Python-3.13.7-org/Modules/_winapi.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/_winapi.c	2025-09-01 19:08:51.395763000 +0200
@@ -2995,7 +2995,9 @@
     _WINAPI_GETFILETYPE_METHODDEF
     _WINAPI__MIMETYPES_READ_WINDOWS_REGISTRY_METHODDEF
     _WINAPI_NEEDCURRENTDIRECTORYFOREXEPATH_METHODDEF
+#if Py_WINVER >= 0x0603
     _WINAPI_COPYFILE2_METHODDEF
+#endif /* Py_WINVER >= 0x0603 */
     {NULL, NULL}
 };
 
@@ -3167,6 +3169,7 @@
 #endif
     WINAPI_CONSTANT(F_DWORD, COPY_FILE_REQUEST_COMPRESSED_TRAFFIC);
 
+#if Py_WINVER >= 0x0603
     WINAPI_CONSTANT(F_DWORD, COPYFILE2_CALLBACK_CHUNK_STARTED);
     WINAPI_CONSTANT(F_DWORD, COPYFILE2_CALLBACK_CHUNK_FINISHED);
     WINAPI_CONSTANT(F_DWORD, COPYFILE2_CALLBACK_STREAM_STARTED);
@@ -3179,6 +3182,7 @@
     WINAPI_CONSTANT(F_DWORD, COPYFILE2_PROGRESS_STOP);
     WINAPI_CONSTANT(F_DWORD, COPYFILE2_PROGRESS_QUIET);
     WINAPI_CONSTANT(F_DWORD, COPYFILE2_PROGRESS_PAUSE);
+#endif /* Py_WINVER >= 0x0603 */
 
     WINAPI_CONSTANT("i", NULL);
 
diff -uarN Python-3.13.7-org/Modules/clinic/_ssl.c.h Python-3.13.7/Modules/clinic/_ssl.c.h
--- Python-3.13.7-org/Modules/clinic/_ssl.c.h	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/clinic/_ssl.c.h	2025-09-01 19:08:51.405143700 +0200
@@ -2703,7 +2703,7 @@
     return return_value;
 }
 
-#if defined(_MSC_VER)
+#if defined(_MSC_VER) || defined(__MINGW32__)
 
 PyDoc_STRVAR(_ssl_enum_certificates__doc__,
 "enum_certificates($module, /, store_name)\n"
@@ -2782,7 +2782,7 @@
 
 #endif /* defined(_MSC_VER) */
 
-#if defined(_MSC_VER)
+#if defined(_MSC_VER) || defined(__MINGW32__)
 
 PyDoc_STRVAR(_ssl_enum_crls__doc__,
 "enum_crls($module, /, store_name)\n"
diff -uarN Python-3.13.7-org/Modules/faulthandler.c Python-3.13.7/Modules/faulthandler.c
--- Python-3.13.7-org/Modules/faulthandler.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/faulthandler.c	2025-09-01 19:08:51.412212500 +0200
@@ -999,7 +999,7 @@
     }
 #endif
 
-#ifdef _MSC_VER
+#if defined(_MSC_VER) || defined(__MINGW32__)
     /* Visual Studio: configure abort() to not display an error message nor
        open a popup asking to report the fault. */
     _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
diff -uarN Python-3.13.7-org/Modules/mathmodule.c Python-3.13.7/Modules/mathmodule.c
--- Python-3.13.7-org/Modules/mathmodule.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/mathmodule.c	2025-09-01 19:08:51.421229600 +0200
@@ -2404,7 +2404,7 @@
         return PyFloat_FromDouble(x);
     errno = 0;
     r = fmod(x, y);
-#ifdef _MSC_VER
+#if defined(_MSC_VER) || defined(__MINGW32__)
     /* Windows (e.g. Windows 10 with MSC v.1916) loose sign
        for zero result.  But C99+ says: "if y is nonzero, the result
        has the same sign as x".
diff -uarN Python-3.13.7-org/Modules/posixmodule.c Python-3.13.7/Modules/posixmodule.c
--- Python-3.13.7-org/Modules/posixmodule.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/posixmodule.c	2025-09-01 19:08:51.432222400 +0200
@@ -43,6 +43,10 @@
 #  if defined(MS_WINDOWS_DESKTOP) || defined(MS_WINDOWS_SYSTEM)
 #    define HAVE_SYMLINK
 #  endif /* MS_WINDOWS_DESKTOP | MS_WINDOWS_SYSTEM */
+#  if Py_WINVER < 0x0603
+extern HRESULT WINAPI py_PathCchSkipRoot(const WCHAR *path, const WCHAR **root_end);
+#define PathCchSkipRoot py_PathCchSkipRoot
+#  endif /* Py_WINVER < 0x0603 */
 #endif
 
 #ifndef MS_WINDOWS
@@ -374,7 +378,7 @@
 #  define HAVE_OPENDIR    1
 #  define HAVE_SYSTEM     1
 #  include <process.h>
-#elif defined( _MSC_VER)
+#elif defined( _MSC_VER) || defined(__MINGW32__)
   /* Microsoft compiler */
 #  if defined(MS_WINDOWS_DESKTOP) || defined(MS_WINDOWS_APP) || defined(MS_WINDOWS_SYSTEM)
 #    define HAVE_GETPPID    1
@@ -401,7 +405,7 @@
 [clinic start generated code]*/
 /*[clinic end generated code: output=da39a3ee5e6b4b0d input=94a0f0f978acae17]*/
 
-#ifndef _MSC_VER
+#if !defined(_MSC_VER) && !defined(__MINGW32__)
 
 #if defined(__sgi)&&_COMPILER_VERSION>=700
 /* declare ctermid_r if compiling with MIPSPro 7.x in ANSI C mode
@@ -470,7 +474,7 @@
 #  endif
 #endif
 
-#ifdef _MSC_VER
+#if defined(_MSC_VER) || defined(__MINGW32__)
 #  ifdef HAVE_DIRECT_H
 #    include <direct.h>
 #  endif
@@ -1653,7 +1657,7 @@
 */
 #include <crt_externs.h>
 #define USE_DARWIN_NS_GET_ENVIRON 1
-#elif !defined(_MSC_VER) && (!defined(__WATCOMC__) || defined(__QNX__) || defined(__VXWORKS__))
+#elif !defined(_MSC_VER) && !defined(__MINGW32__) && (!defined(__WATCOMC__) || defined(__QNX__) || defined(__VXWORKS__))
 extern char **environ;
 #endif /* !_MSC_VER */
 
@@ -2127,7 +2131,11 @@
                 /* Volumes and physical disks are block devices, e.g.
                    \\.\C: and \\.\PhysicalDrive0. */
                 memset(result, 0, sizeof(*result));
+#ifdef S_IFBLK
+                result->st_mode = S_IFBLK;
+#else
                 result->st_mode = 0x6000; /* S_IFBLK */
+#endif /* S_IFBLK */
                 goto cleanup;
             }
             retval = -1;
@@ -9308,7 +9316,7 @@
 
 #ifdef MS_WINDOWS
 #include <winternl.h>
-#include <ProcessSnapshot.h>
+#include <processsnapshot.h>
 
 // The structure definition in winternl.h may be incomplete.
 // This structure is the full version from the MSDN documentation.
@@ -9383,6 +9391,47 @@
     return cached_ppid;
 }
 
+#if Py_WINVER < 0x603
+#include <tlhelp32.h>
+
+static PyObject*
+win32_getppid(void)
+{
+    HANDLE snapshot;
+    pid_t mypid;
+    PyObject* result = NULL;
+    BOOL have_record;
+    PROCESSENTRY32 pe;
+
+    mypid = getpid(); /* This function never fails */
+
+    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
+    if (snapshot == INVALID_HANDLE_VALUE)
+        return PyErr_SetFromWindowsErr(GetLastError());
+
+    pe.dwSize = sizeof(pe);
+    have_record = Process32First(snapshot, &pe);
+    while (have_record) {
+        if (mypid == (pid_t)pe.th32ProcessID) {
+            /* We could cache the ulong value in a static variable. */
+            result = PyLong_FromPid((pid_t)pe.th32ParentProcessID);
+            break;
+        }
+
+        have_record = Process32Next(snapshot, &pe);
+    }
+
+    /* If our loop exits and our pid was not found (result will be NULL)
+     * then GetLastError will return ERROR_NO_MORE_FILES. This is an
+     * error anyway, so let's raise it. */
+    if (!result)
+        result = PyErr_SetFromWindowsErr(GetLastError());
+
+    CloseHandle(snapshot);
+
+    return result;
+}
+#else /* Py_WINVER < 0x603 */
 static PyObject*
 win32_getppid(void)
 {
@@ -9417,6 +9466,7 @@
     PssFreeSnapshot(process, snapshot);
     return result;
 }
+#endif /* Py_WINVER < 0x603 */
 #endif /*MS_WINDOWS*/
 
 
diff -uarN Python-3.13.7-org/Modules/selectmodule.c Python-3.13.7/Modules/selectmodule.c
--- Python-3.13.7-org/Modules/selectmodule.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/selectmodule.c	2025-09-01 19:08:51.441846100 +0200
@@ -168,7 +168,7 @@
         v = PyObject_AsFileDescriptor( o );
         if (v == -1) goto finally;
 
-#if defined(_MSC_VER)
+#if defined(_MSC_VER) || defined(__MINGW32__)
         max = 0;                             /* not used for Win32 */
 #else  /* !_MSC_VER */
         if (!_PyIsSelectable_fd(v)) {
diff -uarN Python-3.13.7-org/Modules/socketmodule.c Python-3.13.7/Modules/socketmodule.c
--- Python-3.13.7-org/Modules/socketmodule.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/socketmodule.c	2025-09-01 19:08:51.451251200 +0200
@@ -279,8 +279,9 @@
 # endif
 
 /* Helpers needed for AF_HYPERV */
-# include <Rpc.h>
+# include <rpc.h>
 
+#ifndef __MINGW32__
 /* Macros based on the IPPROTO enum, see: https://bugs.python.org/issue29515 */
 #define IPPROTO_ICMP IPPROTO_ICMP
 #define IPPROTO_IGMP IPPROTO_IGMP
@@ -312,6 +313,7 @@
 #define IPPROTO_PGM IPPROTO_PGM  // WinSock2 only
 #define IPPROTO_L2TP IPPROTO_L2TP  // WinSock2 only
 #define IPPROTO_SCTP IPPROTO_SCTP  // WinSock2 only
+#endif /* !__MINGW32__ */
 
 /* Provides the IsWindows7SP1OrGreater() function */
 #include <versionhelpers.h>
diff -uarN Python-3.13.7-org/Modules/timemodule.c Python-3.13.7/Modules/timemodule.c
--- Python-3.13.7-org/Modules/timemodule.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Modules/timemodule.c	2025-09-01 19:08:51.459934100 +0200
@@ -41,7 +41,7 @@
 #  include <sanitizer/msan_interface.h>
 #endif
 
-#ifdef _MSC_VER
+#if defined(_MSC_VER) || defined(__MINGW32__)
 #  define _Py_timezone _timezone
 #  define _Py_daylight _daylight
 #  define _Py_tzname _tzname
@@ -830,13 +830,13 @@
             PyErr_NoMemory();
             return NULL;
         }
-#if defined _MSC_VER && _MSC_VER >= 1400 && defined(__STDC_SECURE_LIB__)
+#if (defined(_MSC_VER) && _MSC_VER >= 1400 && defined(__STDC_SECURE_LIB__)) || defined(__MINGW32__)
         errno = 0;
 #endif
         _Py_BEGIN_SUPPRESS_IPH
         buflen = format_time(*outbuf, *bufsize, format, tm);
         _Py_END_SUPPRESS_IPH
-#if defined _MSC_VER && _MSC_VER >= 1400 && defined(__STDC_SECURE_LIB__)
+#if (defined(_MSC_VER) && _MSC_VER >= 1400 && defined(__STDC_SECURE_LIB__)) || defined(__MINGW32__)
         /* VisualStudio .NET 2005 does this properly */
         if (buflen == 0 && errno == EINVAL) {
             PyErr_SetString(PyExc_ValueError, "Invalid format string");
@@ -892,7 +892,7 @@
 //
 // Android works with negative years on the emulator, but fails on some
 // physical devices (#123017).
-#if defined(_MSC_VER) || (defined(__sun) && defined(__SVR4)) || defined(_AIX) \
+#if defined(_MSC_VER) || defined(__MINGW32__) || (defined(__sun) && defined(__SVR4)) || defined(_AIX) \
     || defined(__VXWORKS__) || defined(__ANDROID__)
     if (buf.tm_year + 1900 < 1 || 9999 < buf.tm_year + 1900) {
         PyErr_SetString(PyExc_ValueError,
diff -uarN Python-3.13.7-org/Objects/dictobject.c Python-3.13.7/Objects/dictobject.c
--- Python-3.13.7-org/Objects/dictobject.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Objects/dictobject.c	2025-09-01 19:08:51.468320300 +0200
@@ -582,7 +582,7 @@
 #if SIZEOF_LONG == SIZEOF_SIZE_T
     minsize = Py_MAX(minsize, PyDict_MINSIZE);
     return _Py_bit_length(minsize - 1);
-#elif defined(_MSC_VER)
+#elif defined(_MSC_VER) || defined(__MINGW32__)
     // On 64bit Windows, sizeof(long) == 4. We cannot use _Py_bit_length.
     minsize = Py_MAX(minsize, PyDict_MINSIZE);
     unsigned long msb;
diff -uarN Python-3.13.7-org/PC/_testconsole.c Python-3.13.7/PC/_testconsole.c
--- Python-3.13.7-org/PC/_testconsole.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/PC/_testconsole.c	2025-09-01 19:08:51.476174000 +0200
@@ -140,7 +140,7 @@
 }
 
 
-#include "clinic\_testconsole.c.h"
+#include "clinic/_testconsole.c.h"
 
 PyMethodDef testconsole_methods[] = {
     _TESTCONSOLE_WRITE_INPUT_METHODDEF
diff -uarN Python-3.13.7-org/PC/_wmimodule.cpp Python-3.13.7/PC/_wmimodule.cpp
--- Python-3.13.7-org/PC/_wmimodule.cpp	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/PC/_wmimodule.cpp	2025-09-01 19:08:51.484667900 +0200
@@ -14,9 +14,9 @@
 #endif
 
 #define _WIN32_DCOM
-#include <Windows.h>
+#include <windows.h>
 #include <comdef.h>
-#include <Wbemidl.h>
+#include <wbemidl.h>
 #include <propvarutil.h>
 
 #include <Python.h>
diff -uarN Python-3.13.7-org/PC/comsuppw.cpp Python-3.13.7/PC/comsuppw.cpp
--- Python-3.13.7-org/PC/comsuppw.cpp	1970-01-01 01:00:00.000000000 +0100
+++ Python-3.13.7/PC/comsuppw.cpp	2025-09-01 19:08:51.489705100 +0200
@@ -0,0 +1,30 @@
+#include <stdlib.h>
+#include <strsafe.h>
+#include <comutil.h>
+#include <windows.h>
+
+
+char * WINAPI _com_util::ConvertBSTRToString(BSTR bstr) {
+	if (bstr == NULL) {
+		return NULL;
+	}
+	const unsigned int len = lstrlenW(bstr);
+	char * const ascii = new char [len + 1];
+	if (ascii != NULL) {
+		wcstombs(ascii, bstr, len + 1);
+	}
+	return ascii;
+}
+
+
+BSTR WINAPI _com_util::ConvertStringToBSTR(const char * ascii) {
+	if (ascii == NULL) {
+		return NULL;
+	}
+	const unsigned int len = lstrlenA(ascii);
+	BSTR bstr = SysAllocStringLen(NULL, len);
+	if (bstr != NULL) {
+		mbstowcs(bstr, ascii, len + 1);
+	}
+	return bstr;
+}
diff -uarN Python-3.13.7-org/PC/pyconfig.h.in Python-3.13.7/PC/pyconfig.h.in
--- Python-3.13.7-org/PC/pyconfig.h.in	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/PC/pyconfig.h.in	2025-09-01 19:08:51.496852500 +0200
@@ -170,8 +170,8 @@
 
 /* set the version macros for the windows headers */
 /* Python 3.12+ requires Windows 8.1 or greater */
-#define Py_WINVER 0x0603 /* _WIN32_WINNT_WINBLUE (8.1) */
-#define Py_NTDDI NTDDI_WINBLUE
+#define Py_WINVER 0x0601 /* _WIN32_WINNT_WIN7 (7) */
+#define Py_NTDDI NTDDI_WIN7
 
 /* We only set these values when building Python - we don't want to force
    these values on extensions, as that will affect the prototypes and
@@ -233,7 +233,7 @@
 typedef int pid_t;
 
 /* define some ANSI types that are not defined in earlier Win headers */
-#if _MSC_VER >= 1200
+#if _MSC_VER >= 1200 || defined(__MINGW32__)
 /* This file only exists in VC 6.0 or higher */
 #include <basetsd.h>
 #endif
@@ -263,7 +263,19 @@
 #warning "Please use an up-to-date version of gcc! (>2.91 recommended)"
 #endif
 
-#define COMPILER "[gcc]"
+#define _Py_PASTE_VERSION(SUFFIX) \
+        ("[gcc v." _Py_STRINGIZE(__GNUC__) "." _Py_STRINGIZE(__GNUC_MINOR__) "." _Py_STRINGIZE(__GNUC_PATCHLEVEL__) " " SUFFIX "]")
+#define _Py_STRINGIZE(X) _Py_STRINGIZE1(X)
+#define _Py_STRINGIZE1(X) #X
+
+#ifdef MS_WIN64
+#define COMPILER _Py_PASTE_VERSION("64 bit (AMD64)")
+#define PYD_PLATFORM_TAG "win_amd64"
+#else
+#define COMPILER _Py_PASTE_VERSION("32 bit")
+#define PYD_PLATFORM_TAG "win32"
+#endif /* MS_WIN64 */
+
 #define PY_LONG_LONG long long
 #define PY_LLONG_MIN LLONG_MIN
 #define PY_LLONG_MAX LLONG_MAX
@@ -347,7 +359,11 @@
 #       define SIZEOF_HKEY 8
 #       define SIZEOF_SIZE_T 8
 #       define ALIGNOF_SIZE_T 8
+#       ifdef __MINGW32__
+#       define ALIGNOF_MAX_ALIGN_T 16
+#       else
 #       define ALIGNOF_MAX_ALIGN_T 8
+#       endif
 /* configure.ac defines HAVE_LARGEFILE_SUPPORT iff
    sizeof(off_t) > sizeof(long), and sizeof(long long) >= sizeof(off_t).
    On Win64 the second condition is not true, but if fpos_t replaces off_t
@@ -364,7 +380,7 @@
 #       define SIZEOF_SIZE_T 4
 #       define ALIGNOF_SIZE_T 4
         /* MS VS2005 changes time_t to a 64-bit type on all platforms */
-#       if defined(_MSC_VER) && _MSC_VER >= 1400
+#       if (defined(_MSC_VER) && _MSC_VER >= 1400) || defined(__MINGW32__)
 #       define SIZEOF_TIME_T 8
 #       else
 #       define SIZEOF_TIME_T 4
@@ -391,8 +407,8 @@
    Microsoft eMbedded Visual C++ 4.0 has a version number of 1201 and doesn't
    define these.
    If some compiler does not provide them, modify the #if appropriately. */
-#if defined(_MSC_VER)
-#if _MSC_VER > 1300
+#if defined(_MSC_VER) || defined(__MINGW32__)
+#if _MSC_VER > 1300 || defined(__MINGW32__)
 #define HAVE_UINTPTR_T 1
 #define HAVE_INTPTR_T 1
 #else
@@ -610,7 +626,7 @@
 /* #undef HAVE_WAITPID */
 
 /* Define to 1 if you have the `wcsftime' function. */
-#if defined(_MSC_VER) && _MSC_VER >= 1310
+#if (defined(_MSC_VER) && _MSC_VER >= 1310) || defined(__MINGW32__)
 #define HAVE_WCSFTIME 1
 #endif
 
diff -uarN Python-3.13.7-org/PC/pylauncher.rc Python-3.13.7/PC/pylauncher.rc
--- Python-3.13.7-org/PC/pylauncher.rc	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/PC/pylauncher.rc	2025-09-01 19:08:51.503497800 +0200
@@ -12,17 +12,17 @@
 1 RT_MANIFEST "python.manifest"
 
 #if defined(PY_ICON)
-1 ICON DISCARDABLE "icons\python.ico"
+1 ICON DISCARDABLE "icons/python.ico"
 #elif defined(PYW_ICON)
-1 ICON DISCARDABLE "icons\pythonw.ico"
+1 ICON DISCARDABLE "icons/pythonw.ico"
 #else
-1 ICON DISCARDABLE "icons\launcher.ico" 
-2 ICON DISCARDABLE "icons\py.ico" 
-3 ICON DISCARDABLE "icons\pyc.ico" 
-4 ICON DISCARDABLE "icons\pyd.ico" 
-5 ICON DISCARDABLE "icons\python.ico"
-6 ICON DISCARDABLE "icons\pythonw.ico"
-7 ICON DISCARDABLE "icons\setup.ico" 
+1 ICON DISCARDABLE "icons/launcher.ico" 
+2 ICON DISCARDABLE "icons/py.ico" 
+3 ICON DISCARDABLE "icons/pyc.ico" 
+4 ICON DISCARDABLE "icons/pyd.ico" 
+5 ICON DISCARDABLE "icons/python.ico"
+6 ICON DISCARDABLE "icons/pythonw.ico"
+7 ICON DISCARDABLE "icons/setup.ico" 
 #endif
 
 1 USAGE "launcher-usage.txt"
diff -uarN Python-3.13.7-org/PC/pyshellext.cpp Python-3.13.7/PC/pyshellext.cpp
--- Python-3.13.7-org/PC/pyshellext.cpp	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/PC/pyshellext.cpp	2025-09-01 19:08:51.511528400 +0200
@@ -1,17 +1,13 @@
 // Support back to Vista
 #define _WIN32_WINNT _WIN32_WINNT_VISTA
-#include <sdkddkver.h>
-
-// Use WRL to define a classic COM class
-#define __WRL_CLASSIC_COM__
-#include <wrl.h>
-
 #include <windows.h>
 #include <shlobj.h>
 #include <shlwapi.h>
 #include <olectl.h>
 #include <strsafe.h>
 
+#include <new>
+
 #define DDWM_UPDATEWINDOW (WM_USER+3)
 
 static HINSTANCE hModule;
@@ -19,11 +15,10 @@
 static CLIPFORMAT cfDragWindow;
 
 #define CLASS_GUID "{BEA218D2-6950-497B-9434-61683EC065FE}"
+static CLSID CLASS_ID;
 static const LPCWSTR CLASS_SUBKEY = L"Software\\Classes\\CLSID\\" CLASS_GUID;
 static const LPCWSTR DRAG_MESSAGE = L"Open with %1";
 
-using namespace Microsoft::WRL;
-
 HRESULT FilenameListCchLengthA(LPCSTR pszSource, size_t cchMax, size_t *pcchLength, size_t *pcchCount) {
     HRESULT hr = S_OK;
     size_t count = 0;
@@ -120,23 +115,20 @@
     return hr;
 }
 
-class DECLSPEC_UUID(CLASS_GUID) PyShellExt : public RuntimeClass<
-    RuntimeClassFlags<ClassicCom>,
-    IDropTarget,
-    IPersistFile
->
+class PyShellExt : public IDropTarget, public IPersistFile
 {
+    ULONG ref_count;
     LPOLESTR target, target_dir;
     DWORD target_mode;
 
     IDataObject *data_obj;
 
 public:
-    PyShellExt() : target(NULL), target_dir(NULL), target_mode(0), data_obj(NULL) {
+    PyShellExt() : ref_count(1), target(NULL), target_dir(NULL), target_mode(0), data_obj(NULL) {
         OutputDebugString(L"PyShellExt::PyShellExt");
     }
 
-    ~PyShellExt() {
+    virtual ~PyShellExt() {
         if (target) {
             CoTaskMemFree(target);
         }
@@ -147,7 +139,6 @@
             data_obj->Release();
         }
     }
-
 private:
     HRESULT UpdateDropDescription(IDataObject *pDataObj) {
         STGMEDIUM medium;
@@ -315,7 +306,7 @@
             return S_FALSE;
         }
 
-        res = SendMessage(hwnd, DDWM_UPDATEWINDOW, 0, NULL);
+        res = SendMessage(hwnd, DDWM_UPDATEWINDOW, 0, 0);
 
         if (res) {
             OutputDebugString(L"PyShellExt::NotifyDragWindow - failed to post DDWM_UPDATEWINDOW");
@@ -326,6 +317,42 @@
     }
 
 public:
+
+    // IUnknown implementation
+
+    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) {
+        if (ppv == NULL) {
+            return E_POINTER;
+        }
+        if (riid == IID_IUnknown) {
+            *ppv = static_cast<IUnknown *>(static_cast<IDropTarget *>(this));
+            AddRef();
+            return S_OK;
+        } else if (riid == IID_IDropTarget) {
+            *ppv = static_cast<IDropTarget *>(this);
+            AddRef();
+            return S_OK;
+        } else if (riid == IID_IPersistFile) {
+            *ppv = static_cast<IPersistFile *>(this);
+            AddRef();
+            return S_OK;
+        }
+        *ppv = NULL;
+        return E_NOINTERFACE;
+    }
+
+    ULONG STDMETHODCALLTYPE AddRef() {
+        return InterlockedIncrement(&ref_count);
+    }
+
+    ULONG STDMETHODCALLTYPE Release() {
+        const ULONG count = InterlockedDecrement(&ref_count);
+        if (count == 0) {
+            delete this;
+        }
+        return count;
+    }
+
     // IDropTarget implementation
 
     STDMETHODIMP DragEnter(IDataObject *pDataObj, DWORD grfKeyState, POINTL pt, DWORD *pdwEffect) {
@@ -481,19 +508,88 @@
     }
 
     STDMETHODIMP GetClassID(CLSID *pClassID) {
-        *pClassID = __uuidof(PyShellExt);
+        *pClassID = CLASS_ID;
         return S_OK;
     }
 };
 
-CoCreatableClass(PyShellExt);
+class PyShellExtClassFactory : public IClassFactory
+{
+    ULONG ref_count;
+public:
+    PyShellExtClassFactory() : ref_count(1) { }
+
+    // IUnknown implementation
+
+    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) {
+        if (ppv == NULL) {
+            return E_POINTER;
+        }
+        if (riid == IID_IUnknown) {
+            *ppv = static_cast<IUnknown *>(this);
+            AddRef();
+            return S_OK;
+        } else if (riid == IID_IClassFactory) {
+            *ppv = static_cast<IClassFactory *>(this);
+            AddRef();
+            return S_OK;
+        }
+        *ppv = NULL;
+        return E_NOINTERFACE;
+    }
+
+    ULONG STDMETHODCALLTYPE AddRef() {
+        return InterlockedIncrement(&ref_count);
+    }
 
-STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, _COM_Outptr_ void** ppv) {
-    return Module<InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
+    ULONG STDMETHODCALLTYPE Release() {
+        const ULONG count = InterlockedDecrement(&ref_count);
+        if (count == 0) {
+            delete this;
+        }
+        return count;
+    }
+
+    // IClassFactory implementation
+
+    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppv) {
+        if (pUnkOuter != NULL) {
+            return CLASS_E_NOAGGREGATION;
+        }
+        PyShellExt *pObj = new (std::nothrow) PyShellExt();
+        if (pObj == NULL) {
+            return E_OUTOFMEMORY;
+        }
+        const HRESULT hr = pObj->QueryInterface(riid, ppv);
+        pObj->Release();
+        return hr;
+    }
+
+    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) {
+        if (fLock) {
+            InterlockedIncrement(&ref_count);
+        } else {
+            InterlockedDecrement(&ref_count);
+        }
+        return S_OK;
+    }
+};
+
+STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, _COM_Outptr_ void **ppv) {
+    if (rclsid == CLASS_ID) {
+        PyShellExtClassFactory *pFactory = new (std::nothrow) PyShellExtClassFactory();
+        if (pFactory == NULL) {
+            return E_OUTOFMEMORY;
+        }
+        const HRESULT hr = pFactory->QueryInterface(riid, ppv);
+        pFactory->Release();
+        return hr;
+    }
+    return CLASS_E_CLASSNOTAVAILABLE;
 }
 
 STDAPI DllCanUnloadNow() {
-    return Module<InProc>::GetModule().Terminate() ? S_OK : S_FALSE;
+    return S_OK;
 }
 
 STDAPI DllRegisterServer() {
@@ -591,6 +687,7 @@
 
 STDAPI_(BOOL) DllMain(_In_opt_ HINSTANCE hinst, DWORD reason, _In_opt_ void*) {
     if (reason == DLL_PROCESS_ATTACH) {
+                CLSIDFromString(L"" CLASS_GUID, &CLASS_ID);
         hModule = hinst;
 
         cfDropDescription = RegisterClipboardFormat(CFSTR_DROPDESCRIPTION);
diff -uarN Python-3.13.7-org/PC/python_exe.rc Python-3.13.7/PC/python_exe.rc
--- Python-3.13.7-org/PC/python_exe.rc	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/PC/python_exe.rc	2025-09-01 19:08:51.518762000 +0200
@@ -12,7 +12,7 @@
 // current versions of Windows.
 1 RT_MANIFEST "python.manifest"
 
-1 ICON DISCARDABLE "icons\python.ico" 
+1 ICON DISCARDABLE "icons/python.ico" 
 
 
 /////////////////////////////////////////////////////////////////////////////
diff -uarN Python-3.13.7-org/PC/pythonw_exe.rc Python-3.13.7/PC/pythonw_exe.rc
--- Python-3.13.7-org/PC/pythonw_exe.rc	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/PC/pythonw_exe.rc	2025-09-01 19:08:51.526424000 +0200
@@ -12,7 +12,7 @@
 // current versions of Windows.
 1 RT_MANIFEST "python.manifest"
 
-1 ICON DISCARDABLE "icons\pythonw.ico" 
+1 ICON DISCARDABLE "icons/pythonw.ico" 
 
 
 /////////////////////////////////////////////////////////////////////////////
diff -uarN Python-3.13.7-org/PCbuild/Makefile Python-3.13.7/PCbuild/Makefile
--- Python-3.13.7-org/PCbuild/Makefile	1970-01-01 01:00:00.000000000 +0100
+++ Python-3.13.7/PCbuild/Makefile	2025-09-01 19:08:51.531811900 +0200
@@ -0,0 +1,663 @@
+# user configuration
+BASE = .
+DST = $(BASE)/mingw
+HOST_DST = $(BASE)/host
+
+CC = gcc
+CXX = g++
+RC = windres
+CPPFLAGS =
+CFLAGS = -O2
+CXXFLAGS = $(CFLAGS)
+LD = $(CXX)
+LDFLAGS = -s -static -fuse-linker-plugin
+LDSHAREDFLAGS = -shared -Wl,--enable-auto-image-base
+LDSTDCALLFLAGS = -Wl,--enable-stdcall-fixup
+LDREDIRECTFLAGS = -nostartfiles -nodefaultlibs
+PGO_PROF_GEN_FLAG = -fprofile-generate
+PGO_PROF_USE_FLAG = -fprofile-use -fprofile-correction
+
+PREFIX=NULL
+EXEC_PREFIX=NULL
+VERSION=NULL
+PYDEBUGEXT=""
+VPATH="..\\.."
+PLATLIBDIR="DLLs"
+
+HAVE_BZ2 = 0
+HAVE_EXPAT = 0
+HAVE_FFI = 0
+HAVE_OPENSSL = 0
+HAVE_LZMA = 0
+HAVE_SQLITE3 = 0
+HAVE_TK = 0
+HAVE_CURSES = 0
+HAVE_CURSES_PANEL = 0
+
+HOST_CC = $(CC)
+HOST_CPPFLAGS = $(CPPFLAGS)
+HOST_CFLAGS = $(CFLAGS)
+HOST_LD = $(HOST_CC)
+HOST_LDFLAGS = $(LDFLAGS)
+HOST_LIBS = -lversion -lws2_32 -lpathcch -lbcrypt
+# path that contains the pyconfig.h
+HOST_PYCONFIG = ../PC
+
+PY_FREEZE_CMD = $(HOST_DST)/Programs/_freeze_module.exe
+PY_FREEZE_ARGS = 
+
+# internals
+PY_PYD = .pyd
+PY_DLL = python$(PY_MAJOR)$(PY_MINOR).dll
+PY3_DLL = python3.dll
+PY_SYSWINVER = $(PY_MAJOR).$(PY_MINOR)$(PY_ARCHEXT)
+PY_BASE_CPPFLAGS = -I../Include -I../Include/internal -I../Include/internal/mimalloc -I../Modules/_hacl/include -D__USE_MINGW_ANSI_STDIO=0 -DUSE_ZLIB_CRC32 -D_Py_HAVE_ZLIB -DDONT_USE_SEH -D_FILE_OFFSET_BITS=64 '-DMS_DLL_ID="$(PY_SYSWINVER)"' '-DPY3_DLLNAME=L"$(PY_DLL)"' '-DVPATH=$(VPATH)'
+# host configuration
+PY_REQUIRED_CFLAGS = -fno-semantic-interposition -fno-strict-overflow -mfpmath=sse -Wno-incompatible-pointer-types
+PY_HOST_CPPFLAGS = $(PY_BASE_CPPFLAGS) -I$(HOST_PYCONFIG) -I$(HOST_DST) -DPy_NO_ENABLE_SHARED $(HOST_CPPFLAGS)
+PY_HOST_CFLAGS = $(HOST_CFLAGS) $(PY_HOST_CPPFLAGS) $(PY_REQUIRED_CFLAGS)
+PY_HOST_LDFLAGS = $(HOST_LDFLAGS) -L$(HOST_DST) $(HOST_LIBS)
+# target configuration
+PY_CPPFLAGS = $(PY_BASE_CPPFLAGS) -I../PC -I$(DST) -I$(DST)/Python -DPy_ENABLE_SHARED $(CPPFLAGS)
+PY_CFLAGS = $(CFLAGS) $(PY_CPPFLAGS) $(PY_REQUIRED_CFLAGS)
+PY_CXXFLAGS = $(CXXFLAGS) $(PY_CPPFLAGS)
+PY_LDFLAGS = $(LDFLAGS) -L$(DST) $(LIB)
+PY_TARGETS = \
+	pythoncore \
+	python3dll \
+	pyshellext \
+	gdbhooks \
+	python \
+	pythonw \
+	py \
+	pyw \
+	venvlauncher \
+	venvwlauncher \
+	_asyncio \
+	_decimal \
+	_elementtree \
+	_multiprocessing \
+	_overlapped \
+	_queue \
+	_socket \
+	_testbuffer \
+	_testcapi \
+	_testclinic \
+	_testclinic_limited \
+	_testconsole \
+	_testembed \
+	_testimportmultiple \
+	_testinternalcapi \
+	_testlimitedcapi \
+	_testmultiphase \
+	_testsinglephase \
+	_uuid \
+	_wmi \
+	_zoneinfo \
+	unicodedata \
+	select \
+	winsound \
+	xxlimited \
+	xxlimited_35 \
+
+ifeq ($(strip $(HAVE_BZ2)),1)
+LIB_BZ2 = -lbz2
+PY_TARGETS += _bz2
+endif
+
+ifeq ($(strip $(HAVE_EXPAT)),1)
+LIB_EXPAT = -lexpat
+PY_TARGETS += pyexpat
+endif
+
+ifeq ($(strip $(HAVE_FFI)),1)
+LIB_FFI = -lffi
+PY_TARGETS += _ctypes _ctypes_test
+endif
+
+ifeq ($(strip $(HAVE_OPENSSL)),1)
+LIB_CRYPTO = -lcrypto
+LIB_SSL = -lssl
+PY_TARGETS += _hashlib _ssl
+endif
+
+ifeq ($(strip $(HAVE_LZMA)),1)
+LIB_LZMA = -llzma
+PY_TARGETS += _lzma
+endif
+
+ifeq ($(strip $(HAVE_SQLITE3)),1)
+LIB_SQLITE3 = -lsqlite3
+PY_TARGETS += _sqlite3
+endif
+
+ifeq ($(strip $(HAVE_TK)),1)
+LIB_TK = -ltk
+LIB_TCL = -ltcl -ltclstub
+TCL_LIBRARY=
+TK_LIBRARY=
+PY_TARGETS += _tkinter
+endif
+
+ifeq ($(strip $(HAVE_CURSES)),1)
+LIB_CURSES = -lncurses
+CPP_CURSES = -DHAVE_TERM_H=1 -DHAVE_CURSES_FILTER=1 -DHAVE_CURSES_HAS_KEY=1 -DHAVE_CURSES_IMMEDOK=1 -DHAVE_CURSES_IS_PAD=1 -DHAVE_CURSES_IS_TERM_RESIZED=1 -DHAVE_CURSES_RESIZETERM=1 -DHAVE_CURSES_RESIZE_TERM=1 -DHAVE_CURSES_SYNCOK=1 -DHAVE_CURSES_TYPEAHEAD=1 -DHAVE_CURSES_USE_ENV=1 -DHAVE_CURSES_WCHGAT=1 -DHAVE_CURSES_H=1 -DHAVE_NCURSES_H=1
+PY_TARGETS += _curses
+ifeq ($(strip $(HAVE_CURSES_PANEL)),1)
+LIB_CURSES_PANEL = -lpanel $(LIB_CURSES)
+CPP_CURSES_PANEL = $(CPP_CURSES) -DHAVE_PANEL_H=1
+PY_TARGETS += _curses_panel
+endif
+endif
+
+LIB_Z = -lz
+LIBS = $(LIB_Z) -lbcrypt -lgdi32 -lmswsock -lnetapi32 -lole32 -loleaut32 -lpathcch -lversion -lws2_32
+
+all: $(PY_TARGETS)
+
+pgo: profile-use-stamp
+
+.PHONY: clean
+clean: base-clean
+	rm -rf $(HOST_DST)
+	rm -f Makefile.obj.mk Makefile.params.mk Makefile.freeze.mk
+
+.PHONY: base-clean
+base-clean:
+	rm -rf $(DST)
+	-rm -rf ../build
+	-find .. -depth -type d -name '__pycache__' -exec rm -rf {} ';'
+	-find .. -name '*.py[co]' -exec rm -f {} ';'
+	rm -f profile-gen-stamp profile-clean-stamp profile-run-stamp profile-use-stamp
+
+profile-gen-stamp: profile-clean-stamp
+	$(MAKE) "HOST_CFLAGS=$(HOST_CFLAGS)" "HOST_LDFLAGS=$(HOST_LDFLAGS)" "CFLAGS=$(CFLAGS) $(PGO_PROF_GEN_FLAG)" "CXXFLAGS=$(CXXFLAGS) $(PGO_PROF_GEN_FLAG)" "LDFLAGS=$(LDFLAGS) $(PGO_PROF_GEN_FLAG) -Wl,--stack,12582912"
+	touch $@
+
+profile-clean-stamp:
+	$(MAKE) base-clean
+	touch $@
+
+profile-run-stamp:
+	$(MAKE) profile-gen-stamp
+	TCL_LIBRARY="$(TCL_LIBRARY)" TK_LIBRARY="$(TK_LIBRARY)" $(DST)/python.exe -m test --timeout= --pgo
+	-find $(DST) -type f -name '*.o' -exec rm -f {} ';'
+	touch $@
+
+profile-use-stamp: profile-run-stamp
+	$(MAKE) "CFLAGS=$(CFLAGS) $(PGO_PROF_USE_FLAG)" "CXXFLAGS=$(CXXFLAGS) $(PGO_PROF_USE_FLAG)" "LDFLAGS=$(LDFLAGS) $(PGO_PROF_USE_FLAG)"
+	touch $@
+
+-include Makefile.obj.mk
+Makefile.obj.mk: $(wildcard *.vcxproj)
+	for file in $+; do \
+	  echo "OBJ_$${file%.vcxproj} = $$(awk 'BEGIN { FS="\""; ORS=" " } /ClCompile Include=/ && !/\$$\(/ { gsub(/\.c(pp)?/, ".o"); gsub(/\\/, "/"); print $$2 }' < $$file)" ; \
+	  echo "RC_$${file%.vcxproj} = $$(awk 'BEGIN { FS="\""; ORS=" " } /ResourceCompile Include=/ { gsub(/\\/, "/"); print $$2 }' < $$file)" ; \
+	done > $@
+OBJ_libmpdec = libmpdec/basearith.o libmpdec/constants.o libmpdec/context.o libmpdec/convolute.o libmpdec/crt.o libmpdec/difradix2.o libmpdec/fnt.o libmpdec/fourstep.o libmpdec/io.o libmpdec/mpalloc.o libmpdec/mpdecimal.o libmpdec/numbertheory.o libmpdec/sixstep.o libmpdec/transpose.o
+OBJ_pyexpat = ../Modules/pyexpat.o
+OBJ__curses = ../Modules/_cursesmodule.o
+RC__curses = ../PC/python_nt.rc
+OBJ__curses_panel = ../Modules/_curses_panel.o
+RC__curses_panel = ../PC/python_nt.rc
+
+-include Makefile.params.mk
+Makefile.params.mk: ../Include/patchlevel.h
+	( \
+		sed -e 's/PY_RELEASE_LEVEL_ALPHA/10/g' \
+			-e 's/PY_RELEASE_LEVEL_BETA/11/g' \
+			-e 's/PY_RELEASE_LEVEL_GAMMA/12/g' \
+			-e 's/PY_RELEASE_LEVEL_FINAL/15/g' < $< \
+		| awk ' \
+			$$2 == "PY_MICRO_VERSION" { micron = $$3 } \
+			$$2 == "PY_RELEASE_LEVEL" { level = $$3 } \
+			$$2 == "PY_RELEASE_SERIAL" { serial = $$3 } \
+			END { print "PY_FIELD3 = " (micron * 1000 + level * 10 + serial) } \
+		'; \
+		echo | $(CC) -dM -E - | grep __x86_64__ && echo "PY_ARCHNAME = amd64" || echo "PY_ARCHNAME = win32"; \
+		awk '$$2 == "PY_VERSION" { print $$3 }' < ../Include/patchlevel.h | awk 'BEGIN { FS = "." } /\./ { gsub(/"/, ""); print "PY_MAJOR = " $$1; print "PY_MINOR = " $$2; print "PY_PATCH = " $$3 }'; \
+	) >$@
+
+ifeq ($(strip $(PY_ARCHNAME)),win32)
+PY_ARCHEXT = -32
+MPD_CONFIG = CONFIG_32
+else
+PY_ARCHEXT = 
+MPD_CONFIG = CONFIG_64
+endif
+
+-include Makefile.freeze.mk
+# the following is parsed by the freeze.mk target:
+##freeze: getpath ../Modules/getpath.py Python/frozen_modules/getpath.h
+##freeze: importlib._bootstrap ../Lib/importlib/_bootstrap.py Python/frozen_modules/importlib._bootstrap.h
+##freeze: importlib._bootstrap_external ../Lib/importlib/_bootstrap_external.py Python/frozen_modules/importlib._bootstrap_external.h
+##freeze: zipimport ../Lib/zipimport.py Python/frozen_modules/zipimport.h
+##freeze: abc ../Lib/abc.py Python/frozen_modules/abc.h
+##freeze: codecs ../Lib/codecs.py Python/frozen_modules/codecs.h
+##freeze: io ../Lib/io.py Python/frozen_modules/io.h
+##freeze: _collections_abc ../Lib/_collections_abc.py Python/frozen_modules/_collections_abc.h
+##freeze: _sitebuiltins ../Lib/_sitebuiltins.py Python/frozen_modules/_sitebuiltins.h
+##freeze: genericpath ../Lib/genericpath.py Python/frozen_modules/genericpath.h
+##freeze: ntpath ../Lib/ntpath.py Python/frozen_modules/ntpath.h
+##freeze: posixpath ../Lib/posixpath.py Python/frozen_modules/posixpath.h
+##freeze: os ../Lib/os.py Python/frozen_modules/os.h
+##freeze: site ../Lib/site.py Python/frozen_modules/site.h
+##freeze: stat ../Lib/stat.py Python/frozen_modules/stat.h
+##freeze: importlib.util ../Lib/importlib/util.py Python/frozen_modules/importlib.util.h
+##freeze: importlib.machinery ../Lib/importlib/machinery.py Python/frozen_modules/importlib.machinery.h
+##freeze: runpy ../Lib/runpy.py Python/frozen_modules/runpy.h
+##freeze: __hello__ ../Lib/__hello__.py Python/frozen_modules/__hello__.h
+##freeze: __phello__ ../Lib/__phello__/__init__.py Python/frozen_modules/__phello__.h
+##freeze: __phello__.ham ../Lib/__phello__/ham/__init__.py Python/frozen_modules/__phello__.ham.h
+##freeze: __phello__.ham.eggs ../Lib/__phello__/ham/eggs.py Python/frozen_modules/__phello__.ham.eggs.h
+##freeze: __phello__.spam ../Lib/__phello__/spam.py Python/frozen_modules/__phello__.spam.h
+##freeze: frozen_only ../Tools/freeze/flag.py Python/frozen_modules/frozen_only.h
+Makefile.freeze.mk:
+	awk '/^##freeze:/ { \
+		print "$$(DST)/" $$4 ": " $$3 " |freeze"; \
+		print "\tmkdir -p $$(dir $$@)"; \
+		print "\t$$(PY_FREEZE_CMD) $$(PY_FREEZE_ARGS) " $$2 " $$< $$@"; \
+		arr[i++] = $$4 \
+	} \
+	END { \
+		print "PY_FROZEN = \\"; \
+		for (k in arr) { \
+			print "\t" arr[k] " \\" \
+		} \
+	}' <Makefile >$@
+
+$(DST)/PCbuild/%.o: %.c
+	$(CC) $(PY_CFLAGS) -c -o $@ $<
+$(DST)/PCbuild/%.o: %.cpp
+	$(CXX) $(PY_CXXFLAGS) -c -o $@ $<
+$(HOST_DST)/PCbuild/%.o: %.c
+	$(HOST_CC) $(PY_HOST_CFLAGS) -c -o $@ $<
+
+$(DST)/PCbuild/../Modules/getpath.o: ../Modules/getpath.c |$(DST)/Python/frozen_modules/getpath.h
+	$(CC) $(PY_CFLAGS) '-DPREFIX=$(PREFIX)' '-DEXEC_PREFIX=$(EXEC_PREFIX)' '-DVERSION=$(VERSION)' '-DPYDEBUGEXT=$(PYDEBUGEXT)' '-DPLATLIBDIR=$(PLATLIBDIR)' -c -o $@ $<
+
+$(HOST_DST)/pyconfig.h: ../PC/pyconfig.h.in
+	mkdir -p $(dir $@)
+	cp -f $< $@
+$(DST)/pyconfig.h: ../PC/pyconfig.h.in
+	mkdir -p $(dir $@)
+	cp -f $< $@
+
+# GDB hooks
+.PHONY: gdbhooks
+gdbhooks: $(DST)/python.exe-gdb.py
+
+SRC_GDB_HOOKS = ../Tools/gdb/libpython.py
+$(DST)/python.exe-gdb.py: $(SRC_GDB_HOOKS)
+	cp -f $(SRC_GDB_HOOKS) $(DST)/python.exe-gdb.py
+
+# _freeze_module
+freeze: $(HOST_DST)/pyconfig.h $(PY_FREEZE_CMD)
+$(addprefix $(HOST_DST)/PCbuild/,$(OBJ__freeze_module)): PY_HOST_CPPFLAGS := $(PY_HOST_CPPFLAGS) -DPy_BUILD_CORE -DPy_BUILD_CORE_BUILTIN
+$(DST)/PCbuild/../Python/frozen.o: $(addprefix $(DST)/,$(PY_FROZEN))
+$(HOST_DST)/Programs/_freeze_module.exe: $(addprefix $(HOST_DST)/PCbuild/,$(OBJ__freeze_module))
+	$(LD) -o $@ $+ $(PY_HOST_LDFLAGS)
+
+# pythoncore
+pythoncore: $(DST)/pyconfig.h $(DST)/$(PY_DLL)
+$(addprefix $(DST)/PCbuild/,$(OBJ_pythoncore)): PY_CPPFLAGS := $(PY_CPPFLAGS) -DPy_BUILD_CORE -DPy_BUILD_CORE_BUILTIN
+$(DST)/$(PY_DLL).rc.o: $(RC_pythoncore)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"$(PY_DLL)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/$(PY_DLL): $(addprefix $(DST)/PCbuild/,$(OBJ_pythoncore)) $(DST)/$(PY_DLL).rc.o
+	$(LD) -Wl,--out-implib,$(dir $@)lib$(notdir $(@:%.dll=%.a)) -o $@ $+ $(PY_LDFLAGS) $(LIBS) $(LDSHAREDFLAGS)
+
+# python3dll
+python3dll: $(DST)/pyconfig.h $(DST)/python3dll.def $(DST)/$(PY3_DLL)
+$(addprefix $(DST)/PCbuild/,$(OBJ_python3dll)): PY_CPPFLAGS := $(PY_CPPFLAGS) '-DPYTHON_DLL_NAME="$(PY_DLL)"'
+$(DST)/$(PY3_DLL).rc.o: $(RC_python3dll)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"$(PY3_DLL)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/python3dll.def: ../PC/python3dll.c
+	( \
+		echo 'LIBRARY "$(PY3_DLL)"'; \
+		echo 'EXPORTS'; \
+		awk 'BEGIN { FS ="[()]" } /^EXPORT_FUNC/ { print $$2 " = $(basename $(PY_DLL))." $$2 }' < $<; \
+		awk 'BEGIN { FS ="[()]" } /^EXPORT_DATA/ { print $$2 " = $(basename $(PY_DLL))." $$2 " DATA" }' < $<; \
+	) >$@
+$(DST)/$(PY3_DLL): $(DST)/python3dll.def $(DST)/$(PY3_DLL).rc.o
+	$(LD) $(LDREDIRECTFLAGS) -Wl,--out-implib,$(dir $@)lib$(notdir $(@:%.dll=%.a)) -o $@ $+ $(PY_LDFLAGS) $(LDSHAREDFLAGS)
+
+# pyshellext
+pyshellext: pythoncore $(DST)/pyshellext.dll
+$(DST)/PCbuild/../PC/pyshellext.o: PY_CXXFLAGS:=$(PY_CXXFLAGS) -municode -D_CONSOLE
+$(DST)/pyshellext.dll.rc.o: $(RC_pyshellext)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"pyshellext.dll\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/pyshellext.dll: $(addprefix $(DST)/PCbuild/,$(OBJ_pyshellext)) $(DST)/pyshellext.dll.rc.o ../PC/pyshellext.def |$(DST)/$(PY_DLL)
+	$(LD) $(LDSTDCALLFLAGS) -municode -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) -lshlwapi -luuid $(LDSHAREDFLAGS)
+
+# python
+python: pythoncore $(DST)/python.exe
+$(DST)/PCbuild/../Programs/python.o: PY_CFLAGS:=$(PY_CFLAGS) -municode -DPy_BUILD_CORE -D_CONSOLE
+$(DST)/python.exe.rc.o: $(RC_python)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"python.exe\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/python.exe: $(addprefix $(DST)/PCbuild/,$(OBJ_python)) $(DST)/python.exe.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -municode -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS)
+	echo -ne '\r\n' >$(dir $@)/pybuilddir.txt
+
+# pythonw
+pythonw: pythoncore $(DST)/pythonw.exe
+$(DST)/PCbuild/../PC/WinMain.o: PY_CFLAGS:=$(PY_CFLAGS) -municode
+$(DST)/pythonw.exe.rc.o: $(RC_pythonw)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"pythonw.exe\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/pythonw.exe: $(addprefix $(DST)/PCbuild/,$(OBJ_pythonw)) $(DST)/pythonw.exe.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -municode -mwindows -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS)
+
+# py
+py: pythoncore $(DST)/py.exe
+$(DST)/PCbuild/../PC/launcher2.o: PY_CFLAGS:=$(PY_CFLAGS) -municode -D_CONSOLE
+$(DST)/py.exe.rc.o: $(RC_pylauncher)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"py.exe\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/py.exe: $(addprefix $(DST)/PCbuild/,$(OBJ_pylauncher)) $(DST)/py.exe.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -municode -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS)
+
+# pyw
+pyw: pythoncore $(DST)/pyw.exe
+$(DST)/PCbuild/../PC/launcher2.o: PY_CFLAGS:=$(PY_CFLAGS) -municode -D_WINDOWS
+$(DST)/pyw.exe.rc.o: $(RC_pywlauncher)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"pyw.exe\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/pyw.exe: $(addprefix $(DST)/PCbuild/,$(OBJ_pywlauncher)) $(DST)/pyw.exe.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -municode -mwindows -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS)
+
+# venvlauncher
+venvlauncher: pythoncore $(DST)/venvlauncher.exe
+$(DST)/venvlauncher.o: $(patsubst %.o,%.c,$(OBJ_venvlauncher))
+	$(CC) $(PY_CFLAGS) -municode -D_CONSOLE -DPY_ICON '-DEXENAME=L"python.exe"' -c -o $@ $+
+$(DST)/venvlauncher.exe.rc.o: $(RC_venvlauncher)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"venvlauncher.exe\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/venvlauncher.exe: $(DST)/venvlauncher.o $(DST)/venvlauncher.exe.rc.o |$(DST)/$(PY_DLL) $(DST)/python.exe
+	$(LD) -municode -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS)
+
+# venvwlauncher
+venvwlauncher: pythoncore $(DST)/venvwlauncher.exe
+$(DST)/venvwlauncher.o: $(patsubst %.o,%.c,$(OBJ_venvwlauncher))
+	$(CC) $(PY_CFLAGS) -municode -D_WINDOWS -DPYW_ICON '-DEXENAME=L"pythonw.exe"' -c -o $@ $+
+$(DST)/venvwlauncher.exe.rc.o: $(RC_venvwlauncher)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"venvwlauncher.exe\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/venvwlauncher.exe: $(DST)/venvwlauncher.o $(DST)/venvwlauncher.exe.rc.o |$(DST)/$(PY_DLL) $(DST)/pythonw.exe
+	$(LD) -municode -mwindows -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS)
+
+# _asyncio
+_asyncio: $(DST)/pyconfig.h $(DST)/_asyncio$(PY_PYD)
+$(DST)/_asyncio.rc.o: $(RC__asyncio)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_asyncio$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_asyncio$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__asyncio)) $(DST)/_asyncio.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _bz2
+_bz2: $(DST)/pyconfig.h $(DST)/_bz2$(PY_PYD)
+$(DST)/_bz2.rc.o: $(RC__bz2)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_bz2$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_bz2$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__bz2)) $(DST)/_bz2.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIB_BZ2) $(LIBS) $(LDSHAREDFLAGS)
+
+# _ctypes
+_ctypes: $(DST)/pyconfig.h $(DST)/_ctypes$(PY_PYD)
+$(addprefix $(DST)/PCbuild/,$(OBJ__ctypes)): PY_CPPFLAGS := $(PY_CPPFLAGS) -DUSING_MALLOC_CLOSURE_DOT_C=1
+$(DST)/_ctypes.rc.o: $(RC__ctypes)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_ctypes$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_ctypes$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__ctypes)) $(DST)/_ctypes.rc.o |$(DST)/$(PY_DLL)
+	( \
+		echo 'EXPORTS'; \
+		echo 'DllGetClassObject'; \
+		echo 'DllCanUnloadNow PRIVATE'; \
+	) >$(DST)/_ctypes_exports.def
+	$(LD) $(LDSTDCALLFLAGS) -o $@ $+ $(DST)/_ctypes_exports.def $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIB_FFI) $(LIBS) -luuid $(LDSHAREDFLAGS)
+
+# _ctypes_test
+_ctypes_test: $(DST)/pyconfig.h $(DST)/_ctypes_test$(PY_PYD)
+$(DST)/_ctypes_test.rc.o: $(RC__ctypes_test)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_ctypes_test$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_ctypes_test$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__ctypes_test)) $(DST)/_ctypes_test.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _curses
+_curses: $(DST)/pyconfig.h $(DST)/_curses$(PY_PYD)
+$(addprefix $(DST)/PCbuild/,$(OBJ__curses)): PY_CPPFLAGS := $(PY_CPPFLAGS) $(CPP_CURSES)
+$(DST)/_curses.rc.o: $(RC__curses)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_curses$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_curses$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__curses)) $(DST)/_curses.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIB_CURSES) $(LIBS) $(LDSHAREDFLAGS)
+
+# _curses_panel
+_curses_panel: $(DST)/pyconfig.h $(DST)/_curses_panel$(PY_PYD)
+$(addprefix $(DST)/PCbuild/,$(OBJ__curses_panel)): PY_CPPFLAGS := $(PY_CPPFLAGS) $(CPP_CURSES_PANEL)
+$(DST)/_curses_panel.rc.o: $(RC__curses_panel)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_curses_panel$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_curses_panel$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__curses_panel)) $(DST)/_curses_panel.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIB_CURSES_PANEL) $(LIBS) $(LDSHAREDFLAGS)
+
+# _decimal
+_decimal: $(DST)/pyconfig.h $(DST)/mpdecimal.h $(DST)/_decimal$(PY_PYD)
+ifeq ($(strip $(MPD_CONFIG)),CONFIG_32)
+$(addprefix $(DST)/PCbuild/../Modules/_decimal/,$(OBJ_libmpdec)): PY_CPPFLAGS := $(PY_CPPFLAGS) -D$(MPD_CONFIG) -DPPRO -DASM
+else
+$(addprefix $(DST)/PCbuild/../Modules/_decimal/,$(OBJ_libmpdec)): PY_CPPFLAGS := $(PY_CPPFLAGS) -D$(MPD_CONFIG) -DASM
+endif
+$(addprefix $(DST)/PCbuild/,$(OBJ__decimal)): PY_CPPFLAGS := $(PY_CPPFLAGS) -D$(MPD_CONFIG)
+$(DST)/mpdecimal.h: ../Modules/_decimal/libmpdec/mpdecimal.h
+	cp -f $< $@
+$(DST)/_decimal.rc.o: $(RC__decimal)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_decimal$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_decimal$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__decimal)) $(addprefix $(DST)/PCbuild/../Modules/_decimal/,$(OBJ_libmpdec)) $(DST)/_decimal.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _elementtree
+_elementtree: $(DST)/pyconfig.h $(DST)/_elementtree$(PY_PYD)
+$(DST)/_elementtree.rc.o: $(RC__elementtree)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_elementtree$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_elementtree$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__elementtree)) $(DST)/_elementtree.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _hashlib
+_hashlib: $(DST)/pyconfig.h $(DST)/_hashlib$(PY_PYD)
+$(DST)/_hashlib.rc.o: $(RC__hashlib)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_hashlib$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_hashlib$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__hashlib)) $(DST)/_hashlib.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIB_CRYPTO) $(LIBS) -lcrypt32 $(LDSHAREDFLAGS)
+
+# _lzma
+_lzma: $(DST)/pyconfig.h $(DST)/_lzma$(PY_PYD)
+$(DST)/_lzma.rc.o: $(RC__lzma)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_lzma$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_lzma$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__lzma)) $(DST)/_lzma.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIB_LZMA) $(LIBS) $(LDSHAREDFLAGS)
+
+# _multiprocessing
+_multiprocessing: $(DST)/pyconfig.h $(DST)/_multiprocessing$(PY_PYD)
+$(DST)/_multiprocessing.rc.o: $(RC__multiprocessing)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_multiprocessing$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_multiprocessing$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__multiprocessing)) $(DST)/_multiprocessing.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _overlapped
+_overlapped: $(DST)/pyconfig.h $(DST)/_overlapped$(PY_PYD)
+$(DST)/_overlapped.rc.o: $(RC__overlapped)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_overlapped$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_overlapped$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__overlapped)) $(DST)/_overlapped.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _queue
+_queue: $(DST)/pyconfig.h $(DST)/_queue$(PY_PYD)
+$(DST)/_queue.rc.o: $(RC__queue)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_queue$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_queue$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__queue)) $(DST)/_queue.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _socket
+_socket: $(DST)/pyconfig.h $(DST)/_socket$(PY_PYD)
+$(DST)/_socket.rc.o: $(RC__socket)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_socket$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_socket$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__socket)) $(DST)/_socket.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) -liphlpapi -lrpcrt4 $(LDSHAREDFLAGS)
+
+# _sqlite3
+_sqlite3: $(DST)/pyconfig.h $(DST)/_sqlite3$(PY_PYD)
+$(DST)/_sqlite3.rc.o: $(RC__sqlite3)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_sqlite3$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_sqlite3$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__sqlite3)) $(DST)/_sqlite3.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIB_SQLITE3) $(LIBS) $(LDSHAREDFLAGS)
+
+# _ssl
+_ssl: $(DST)/pyconfig.h $(DST)/_ssl$(PY_PYD)
+$(DST)/_ssl.rc.o: $(RC__ssl)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_ssl$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_ssl$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__ssl)) $(DST)/_ssl.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIB_SSL) $(LIB_CRYPTO) $(LIBS) -lcrypt32 $(LDSHAREDFLAGS)
+
+# _testbuffer
+_testbuffer: $(DST)/pyconfig.h $(DST)/_testbuffer$(PY_PYD)
+$(DST)/_testbuffer.rc.o: $(RC__testbuffer)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testbuffer$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testbuffer$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__testbuffer)) $(DST)/_testbuffer.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _testcapi
+_testcapi: $(DST)/pyconfig.h $(DST)/_testcapi$(PY_PYD)
+$(DST)/_testcapi.rc.o: $(RC__testcapi)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testcapi$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testcapi$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__testcapi)) $(DST)/_testcapi.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _testclinic
+_testclinic: $(DST)/pyconfig.h $(DST)/_testclinic$(PY_PYD)
+$(DST)/_testclinic.rc.o: $(RC__testclinic)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testclinic$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testclinic$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__testclinic)) $(DST)/_testclinic.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _testclinic_limited
+_testclinic_limited: $(DST)/pyconfig.h $(DST)/_testclinic_limited$(PY_PYD)
+$(DST)/_testclinic_limited.rc.o: $(RC__testclinic_limited)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testclinic_limited$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testclinic_limited$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__testclinic_limited)) $(DST)/_testclinic_limited.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _testconsole
+_testconsole: $(DST)/pyconfig.h $(DST)/_testconsole$(PY_PYD)
+$(DST)/_testconsole.rc.o: $(RC__testconsole)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testconsole$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testconsole$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__testconsole)) $(DST)/_testconsole.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _testembed
+_testembed: pythoncore $(DST)/_testembed.exe
+$(DST)/_testembed.exe.rc.o: $(RC__testembed)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testembed.exe\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testembed.exe: $(addprefix $(DST)/PCbuild/,$(OBJ__testembed)) $(DST)/_testembed.exe.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS)
+
+# _testimportmultiple
+_testimportmultiple: $(DST)/pyconfig.h $(DST)/_testimportmultiple$(PY_PYD)
+$(DST)/_testimportmultiple.rc.o: $(RC__testimportmultiple)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testimportmultiple$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testimportmultiple$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__testimportmultiple)) $(DST)/_testimportmultiple.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _testinternalcapi
+_testinternalcapi: $(DST)/pyconfig.h $(DST)/_testinternalcapi$(PY_PYD)
+$(DST)/_testinternalcapi.rc.o: $(RC__testinternalcapi)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testinternalcapi$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testinternalcapi$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__testinternalcapi)) $(DST)/_testinternalcapi.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _testlimitedcapi
+_testlimitedcapi: $(DST)/pyconfig.h $(DST)/_testlimitedcapi$(PY_PYD)
+$(DST)/_testlimitedcapi.rc.o: $(RC__testlimitedcapi)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testlimitedcapi$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testlimitedcapi$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__testlimitedcapi)) $(DST)/_testlimitedcapi.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _testmultiphase
+_testmultiphase: $(DST)/pyconfig.h $(DST)/_testmultiphase$(PY_PYD)
+$(DST)/_testmultiphase.rc.o: $(RC__testmultiphase)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testmultiphase$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testmultiphase$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__testmultiphase)) $(DST)/_testmultiphase.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _testsinglephase
+_testsinglephase: $(DST)/pyconfig.h $(DST)/_testsinglephase$(PY_PYD)
+$(DST)/_testsinglephase.rc.o: $(RC__testsinglephase)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_testsinglephase$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_testsinglephase$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__testsinglephase)) $(DST)/_testsinglephase.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# _tkinter
+_tkinter: $(DST)/pyconfig.h $(DST)/_tkinter$(PY_PYD)
+$(addprefix $(DST)/PCbuild/,$(OBJ__tkinter)): PY_CPPFLAGS := $(PY_CPPFLAGS) -DWITH_APPINIT
+$(DST)/_tkinter.rc.o: $(RC__tkinter)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_tkinter$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_tkinter$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__tkinter)) $(DST)/_tkinter.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIB_TK) $(LIB_TCL) $(LIBS) $(LDSHAREDFLAGS)
+
+# _uuid
+_uuid: $(DST)/pyconfig.h $(DST)/_uuid$(PY_PYD)
+$(DST)/_uuid.rc.o: $(RC__uuid)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_uuid$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_uuid$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__uuid)) $(DST)/_uuid.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) -lrpcrt4 $(LDSHAREDFLAGS)
+
+# _wmi
+_wmi: $(DST)/pyconfig.h $(DST)/_wmi$(PY_PYD)
+$(DST)/_wmi.rc.o: $(RC__wmi)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_wmi$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_wmi$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__wmi) ../PC/comsuppw.o) $(DST)/_wmi.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) -lpropsys -lwbemuuid $(LDSHAREDFLAGS)
+
+# _zoneinfo
+_zoneinfo: $(DST)/pyconfig.h $(DST)/_zoneinfo$(PY_PYD)
+$(DST)/_zoneinfo.rc.o: $(RC__zoneinfo)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"_zoneinfo$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/_zoneinfo$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ__zoneinfo)) $(DST)/_zoneinfo.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# pyexpat
+pyexpat: $(DST)/pyconfig.h $(DST)/pyexpat$(PY_PYD)
+$(addprefix $(DST)/PCbuild/,$(OBJ_pyexpat)): PY_CPPFLAGS := $(PY_CPPFLAGS) -DPYEXPAT_EXPORTS -DXML_STATIC
+$(DST)/pyexpat.rc.o: $(RC_pyexpat)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"pyexpat$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/pyexpat$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ_pyexpat)) $(DST)/pyexpat.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIB_EXPAT) $(LIBS) $(LDSHAREDFLAGS)
+
+# select
+select: $(DST)/pyconfig.h $(DST)/select$(PY_PYD)
+$(DST)/select.rc.o: $(RC_select)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"select$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/select$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ_select)) $(DST)/select.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# unicodedata
+unicodedata: $(DST)/pyconfig.h $(DST)/unicodedata$(PY_PYD)
+$(DST)/unicodedata.rc.o: $(RC_unicodedata)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"unicodedata$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/unicodedata$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ_unicodedata)) $(DST)/unicodedata.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# winsound
+winsound: $(DST)/pyconfig.h $(DST)/winsound$(PY_PYD)
+$(DST)/winsound.rc.o: $(RC_winsound)
+	$(RC) $(PY_CPPFLAGS) '-DORIGINAL_FILENAME=\"winsound$(PY_PYD)\"' -DFIELD3=$(PY_FIELD3) -I../Include -o $@ -i $<
+$(DST)/winsound$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ_winsound)) $(DST)/winsound.rc.o |$(DST)/$(PY_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY_DLL:%.dll=%) $(LIBS) -lwinmm $(LDSHAREDFLAGS)
+
+# xxlimited
+xxlimited: $(DST)/pyconfig.h $(DST)/xxlimited$(PY_PYD)
+$(DST)/xxlimited$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ_xxlimited)) |$(DST)/$(PY3_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY3_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# xxlimited_35
+xxlimited_35: $(DST)/pyconfig.h $(DST)/xxlimited_35$(PY_PYD)
+$(DST)/xxlimited_35$(PY_PYD): $(addprefix $(DST)/PCbuild/,$(OBJ_xxlimited_35)) |$(DST)/$(PY3_DLL)
+	$(LD) -o $@ $+ $(PY_LDFLAGS) -l$(PY3_DLL:%.dll=%) $(LIBS) $(LDSHAREDFLAGS)
+
+# ensure output directories
+$(foreach s,$(OBJ__freeze_module), $(eval $(HOST_DST)/PCbuild/$(s): |$(HOST_DST)/PCbuild/$(dir $(s))))
+$(HOST_DST)/%/:
+	mkdir -p $@
+OBJ_ALL = $(sort $(foreach s,$(PY_TARGETS),$(OBJ_$(s))) $(addprefix ../Modules/_decimal/,$(OBJ_libmpdec)))
+$(foreach s,$(OBJ_ALL), $(eval $(DST)/PCbuild/$(s): |$(DST)/PCbuild/$(dir $(s))))
+$(DST)/%/:
+	mkdir -p $@
diff -uarN Python-3.13.7-org/Programs/_testembed.c Python-3.13.7/Programs/_testembed.c
--- Python-3.13.7-org/Programs/_testembed.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Programs/_testembed.c	2025-09-01 19:08:51.543102500 +0200
@@ -1967,7 +1967,7 @@
         wcscpy(optval, L"frozen_modules");
     }
     else if (swprintf(optval, 100,
-#if defined(_MSC_VER)
+#if defined(_MSC_VER) || defined(__MINGW32__)
         L"frozen_modules=%S",
 #else
         L"frozen_modules=%s",
diff -uarN Python-3.13.7-org/Python/dynamic_annotations.c Python-3.13.7/Python/dynamic_annotations.c
--- Python-3.13.7-org/Python/dynamic_annotations.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Python/dynamic_annotations.c	2025-09-01 19:08:51.551928600 +0200
@@ -27,7 +27,7 @@
  * Author: Kostya Serebryany
  */
 
-#ifdef _MSC_VER
+#if defined(_MSC_VER) || defined(__MINGW32__)
 # include <windows.h>
 #endif
 
@@ -119,7 +119,7 @@
   if (RUNNING_ON_VALGRIND) return 1;
 #endif
 
-#ifndef _MSC_VER
+#if !defined(_MSC_VER) && !defined(__MINGW32__)
   const char *running_on_valgrind_str = getenv("RUNNING_ON_VALGRIND");
   if (running_on_valgrind_str) {
     return strcmp(running_on_valgrind_str, "0") != 0;
diff -uarN Python-3.13.7-org/Python/dynload_win.c Python-3.13.7/Python/dynload_win.c
--- Python-3.13.7-org/Python/dynload_win.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Python/dynload_win.c	2025-09-01 19:08:51.561134900 +0200
@@ -152,7 +152,7 @@
    Return whether the DLL was found.
 */
 extern HMODULE PyWin_DLLhModule;
-static int
+int
 _Py_CheckPython3(void)
 {
     static int python3_checked = 0;
diff -uarN Python-3.13.7-org/Python/fileutils.c Python-3.13.7/Python/fileutils.c
--- Python-3.13.7-org/Python/fileutils.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Python/fileutils.c	2025-09-01 19:08:51.570184000 +0200
@@ -1185,7 +1185,11 @@
     case FILE_DEVICE_DISK_FILE_SYSTEM:
     case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
     case FILE_DEVICE_NETWORK_FILE_SYSTEM:
-        result->st_mode = (result->st_mode & ~S_IFMT) | 0x6000; /* _S_IFBLK */
+#ifdef S_IFBLK
+        result->st_mode = (result->st_mode & ~S_IFMT) | S_IFBLK;
+#else
+        result->st_mode = (result->st_mode & ~S_IFMT) | 0x6000; /* S_IFBLK */
+#endif /* S_IFBLK */
         break;
     case FILE_DEVICE_CONSOLE:
     case FILE_DEVICE_NULL:
@@ -1483,8 +1487,14 @@
         flags = HANDLE_FLAG_INHERIT;
     else
         flags = 0;
-
-    if (!SetHandleInformation(handle, HANDLE_FLAG_INHERIT, flags)) {
+#if Py_WINVER < 0x0603
+#define CONSOLE_PSEUDOHANDLE(handle) (((ULONG_PTR)(handle) & 0x3) == 0x3 && \
+            GetFileType(handle) == FILE_TYPE_CHAR)
+    if (!CONSOLE_PSEUDOHANDLE(handle) &&
+#else /* Py_WINVER < 0x0603 */
+    if (
+#endif /* Py_WINVER < 0x0603 */
+        !SetHandleInformation(handle, HANDLE_FLAG_INHERIT, flags)) {
         if (raise)
             PyErr_SetFromWindowsErr(0);
         return -1;
@@ -2136,6 +2146,189 @@
 #endif
 
 
+// The Windows Games API family implements the PathCch* APIs in the Xbox OS,
+// but does not expose them yet. Load them dynamically until
+// 1) they are officially exposed
+// 2) we stop supporting older versions of the GDK which do not expose them
+#if defined(MS_WINDOWS_GAMES) && !defined(MS_WINDOWS_DESKTOP)
+HRESULT
+PathCchSkipRoot(const wchar_t *path, const wchar_t **rootEnd)
+{
+    static int initialized = 0;
+    typedef HRESULT(__stdcall *PPathCchSkipRoot) (PCWSTR pszPath,
+                                                  PCWSTR *ppszRootEnd);
+    static PPathCchSkipRoot _PathCchSkipRoot;
+
+    if (initialized == 0) {
+        HMODULE pathapi = LoadLibraryExW(L"api-ms-win-core-path-l1-1-0.dll", NULL,
+                                         LOAD_LIBRARY_SEARCH_SYSTEM32);
+        if (pathapi) {
+            _PathCchSkipRoot = (PPathCchSkipRoot)GetProcAddress(
+                pathapi, "PathCchSkipRoot");
+        }
+        else {
+            _PathCchSkipRoot = NULL;
+        }
+        initialized = 1;
+    }
+
+    if (!_PathCchSkipRoot) {
+        return E_NOINTERFACE;
+    }
+
+    return _PathCchSkipRoot(path, rootEnd);
+}
+
+static HRESULT
+PathCchCombineEx(wchar_t *buffer, size_t bufsize, const wchar_t *dirname,
+                 const wchar_t *relfile, unsigned long flags)
+{
+    static int initialized = 0;
+    typedef HRESULT(__stdcall *PPathCchCombineEx) (PWSTR pszPathOut,
+                                                   size_t cchPathOut,
+                                                   PCWSTR pszPathIn,
+                                                   PCWSTR pszMore,
+                                                   unsigned long dwFlags);
+    static PPathCchCombineEx _PathCchCombineEx;
+
+    if (initialized == 0) {
+        HMODULE pathapi = LoadLibraryExW(L"api-ms-win-core-path-l1-1-0.dll", NULL,
+                                         LOAD_LIBRARY_SEARCH_SYSTEM32);
+        if (pathapi) {
+            _PathCchCombineEx = (PPathCchCombineEx)GetProcAddress(
+                pathapi, "PathCchCombineEx");
+        }
+        else {
+            _PathCchCombineEx = NULL;
+        }
+        initialized = 1;
+    }
+
+    if (!_PathCchCombineEx) {
+        return E_NOINTERFACE;
+    }
+
+    return _PathCchCombineEx(buffer, bufsize, dirname, relfile, flags);
+}
+#endif /* defined(MS_WINDOWS_GAMES) && !defined(MS_WINDOWS_DESKTOP) */
+
+
+#if Py_WINVER < 0x0603
+#ifndef STRSAFE_E_INSUFFICIENT_BUFFER
+#define STRSAFE_E_INSUFFICIENT_BUFFER ((HRESULT)0x8007007AL)  // 0x7A = 122L = ERROR_INSUFFICIENT_BUFFER
+#endif
+static BOOL is_prefixed_unc(const WCHAR *string)
+{
+    return !wcsnicmp(string, L"\\\\?\\UNC\\", 8 );
+}
+
+static BOOL is_drive_spec( const WCHAR *str )
+{
+    return isalpha( str[0] ) && str[1] == ':';
+}
+
+static BOOL is_prefixed_disk(const WCHAR *string)
+{
+    return !wcsncmp(string, L"\\\\?\\", 4) && is_drive_spec( string + 4 );
+}
+
+static BOOL is_prefixed_volume(const WCHAR *string)
+{
+    const WCHAR *guid;
+    INT i = 0;
+
+    if (wcsnicmp( string, L"\\\\?\\Volume", 10 )) return FALSE;
+
+    guid = string + 10;
+
+    while (i <= 37) {
+        switch (i) {
+        case 0:
+            if (guid[i] != '{') return FALSE;
+            break;
+        case 9:
+        case 14:
+        case 19:
+        case 24:
+            if (guid[i] != '-') return FALSE;
+            break;
+        case 37:
+            if (guid[i] != '}') return FALSE;
+            break;
+        default:
+            if (!isxdigit(guid[i])) return FALSE;
+            break;
+        }
+        i++;
+    }
+
+    return TRUE;
+}
+
+/* Get the next character beyond end of the segment.
+   Return TRUE if the last segment ends with a backslash */
+static BOOL get_next_segment(const WCHAR *next, const WCHAR **next_segment)
+{
+    while (*next && *next != '\\') next++;
+    if (*next == '\\') {
+        *next_segment = next + 1;
+        return TRUE;
+    } else {
+        *next_segment = next;
+        return FALSE;
+    }
+}
+
+/* Find the last character of the root in a path, if there is one, without any segments */
+static const WCHAR *get_root_end(const WCHAR *path)
+{
+    /* Find path root */
+    if (is_prefixed_volume(path))
+        return path[48] == '\\' ? path + 48 : path + 47;
+    else if (is_prefixed_unc(path))
+        return path + 7;
+    else if (is_prefixed_disk(path))
+        return path[6] == '\\' ? path + 6 : path + 5;
+    /* \\ */
+    else if (path[0] == '\\' && path[1] == '\\')
+        return path + 1;
+    /* \ */
+    else if (path[0] == '\\')
+        return path;
+    /* X:\ */
+    else if (is_drive_spec( path ))
+        return path[2] == '\\' ? path + 2 : path + 1;
+    else
+        return NULL;
+}
+
+HRESULT WINAPI py_PathCchSkipRoot(const WCHAR *path, const WCHAR **root_end)
+{
+    if (!path || !path[0] || !root_end
+        || (!wcsnicmp(path, L"\\\\?", 3) && !is_prefixed_volume(path) && !is_prefixed_unc(path)
+            && !is_prefixed_disk(path)))
+        return E_INVALIDARG;
+
+    *root_end = get_root_end(path);
+    if (*root_end) {
+        (*root_end)++;
+        if (is_prefixed_unc(path)) {
+            get_next_segment(*root_end, root_end);
+            get_next_segment(*root_end, root_end);
+        } else if (path[0] == '\\' && path[1] == '\\' && path[2] != '?') {
+            /* Skip share server */
+            get_next_segment(*root_end, root_end);
+            /* If mount point is empty, don't skip over mount point */
+            if (**root_end != '\\') get_next_segment(*root_end, root_end);
+        }
+    }
+
+    return *root_end ? S_OK : E_INVALIDARG;
+}
+#define PathCchSkipRoot py_PathCchSkipRoot
+#endif /* Py_WINVER < 0x0603 */
+
+
 int
 _Py_isabs(const wchar_t *path)
 {
@@ -2222,72 +2415,6 @@
 #endif
 }
 
-// The Windows Games API family implements the PathCch* APIs in the Xbox OS,
-// but does not expose them yet. Load them dynamically until
-// 1) they are officially exposed
-// 2) we stop supporting older versions of the GDK which do not expose them
-#if defined(MS_WINDOWS_GAMES) && !defined(MS_WINDOWS_DESKTOP)
-HRESULT
-PathCchSkipRoot(const wchar_t *path, const wchar_t **rootEnd)
-{
-    static int initialized = 0;
-    typedef HRESULT(__stdcall *PPathCchSkipRoot) (PCWSTR pszPath,
-                                                  PCWSTR *ppszRootEnd);
-    static PPathCchSkipRoot _PathCchSkipRoot;
-
-    if (initialized == 0) {
-        HMODULE pathapi = LoadLibraryExW(L"api-ms-win-core-path-l1-1-0.dll", NULL,
-                                         LOAD_LIBRARY_SEARCH_SYSTEM32);
-        if (pathapi) {
-            _PathCchSkipRoot = (PPathCchSkipRoot)GetProcAddress(
-                pathapi, "PathCchSkipRoot");
-        }
-        else {
-            _PathCchSkipRoot = NULL;
-        }
-        initialized = 1;
-    }
-
-    if (!_PathCchSkipRoot) {
-        return E_NOINTERFACE;
-    }
-
-    return _PathCchSkipRoot(path, rootEnd);
-}
-
-static HRESULT
-PathCchCombineEx(wchar_t *buffer, size_t bufsize, const wchar_t *dirname,
-                 const wchar_t *relfile, unsigned long flags)
-{
-    static int initialized = 0;
-    typedef HRESULT(__stdcall *PPathCchCombineEx) (PWSTR pszPathOut,
-                                                   size_t cchPathOut,
-                                                   PCWSTR pszPathIn,
-                                                   PCWSTR pszMore,
-                                                   unsigned long dwFlags);
-    static PPathCchCombineEx _PathCchCombineEx;
-
-    if (initialized == 0) {
-        HMODULE pathapi = LoadLibraryExW(L"api-ms-win-core-path-l1-1-0.dll", NULL,
-                                         LOAD_LIBRARY_SEARCH_SYSTEM32);
-        if (pathapi) {
-            _PathCchCombineEx = (PPathCchCombineEx)GetProcAddress(
-                pathapi, "PathCchCombineEx");
-        }
-        else {
-            _PathCchCombineEx = NULL;
-        }
-        initialized = 1;
-    }
-
-    if (!_PathCchCombineEx) {
-        return E_NOINTERFACE;
-    }
-
-    return _PathCchCombineEx(buffer, bufsize, dirname, relfile, flags);
-}
-
-#endif /* defined(MS_WINDOWS_GAMES) && !defined(MS_WINDOWS_DESKTOP) */
 
 void
 _Py_skiproot(const wchar_t *path, Py_ssize_t size, Py_ssize_t *drvsize,
@@ -2387,7 +2514,7 @@
 join_relfile(wchar_t *buffer, size_t bufsize,
              const wchar_t *dirname, const wchar_t *relfile)
 {
-#ifdef MS_WINDOWS
+#if defined(MS_WINDOWS) && Py_WINVER >= 0x0603
     if (FAILED(PathCchCombineEx(buffer, bufsize, dirname, relfile,
         PATHCCH_ALLOW_LONG_PATHS))) {
         return -1;
diff -uarN Python-3.13.7-org/Python/mysnprintf.c Python-3.13.7/Python/mysnprintf.c
--- Python-3.13.7-org/Python/mysnprintf.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Python/mysnprintf.c	2025-09-01 19:08:51.578485900 +0200
@@ -66,7 +66,7 @@
         goto Done;
     }
 
-#if defined(_MSC_VER)
+#if defined(_MSC_VER) || defined(__MINGW32__)
     len = _vsnprintf(str, size, format, va);
 #else
     len = vsnprintf(str, size, format, va);
diff -uarN Python-3.13.7-org/Python/pylifecycle.c Python-3.13.7/Python/pylifecycle.c
--- Python-3.13.7-org/Python/pylifecycle.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Python/pylifecycle.c	2025-09-01 19:08:51.586408500 +0200
@@ -3574,7 +3574,7 @@
 #else
     PyOS_sighandler_t handler;
 /* Special signal handling for the secure CRT in Visual Studio 2005 */
-#if defined(_MSC_VER) && _MSC_VER >= 1400
+#if (defined(_MSC_VER) && _MSC_VER >= 1400) || defined(__MINGW32__)
     switch (sig) {
     /* Only these signals are valid */
     case SIGINT:
diff -uarN Python-3.13.7-org/Python/pytime.c Python-3.13.7/Python/pytime.c
--- Python-3.13.7-org/Python/pytime.c	2025-08-14 13:12:11.000000000 +0200
+++ Python-3.13.7/Python/pytime.c	2025-09-01 19:08:51.593237600 +0200
@@ -893,6 +893,43 @@
 #endif
 
 
+#if defined(MS_WINDOWS) && Py_WINVER < 0x603
+static void py_GetSystemTimePreciseAsFileTime(FILETIME *lpSystemTimeAsFileTime)
+{
+    static LARGE_INTEGER frequency;
+    static BOOL initialized = FALSE;
+
+    if (!initialized) {
+        QueryPerformanceFrequency(&frequency);
+        initialized = TRUE;
+    }
+
+    LARGE_INTEGER counter;
+    QueryPerformanceCounter(&counter);
+
+    // Convert the counter to 100-nanosecond intervals
+    const int64_t time = counter.QuadPart * 10000000LL / frequency.QuadPart;
+
+    // Get the current system time in FILETIME format
+    FILETIME systemTimeAsFileTime;
+    GetSystemTimeAsFileTime(&systemTimeAsFileTime);
+
+    // Convert FILETIME to int64_t for calculations
+    ULARGE_INTEGER systemTime;
+    systemTime.LowPart = systemTimeAsFileTime.dwLowDateTime;
+    systemTime.HighPart = systemTimeAsFileTime.dwHighDateTime;
+
+    // Add the high-precision time to the system time
+    const int64_t preciseTime = systemTime.QuadPart + time;
+
+    // Convert back to FILETIME format
+    lpSystemTimeAsFileTime->dwLowDateTime = (DWORD)(preciseTime & 0xFFFFFFFF);
+    lpSystemTimeAsFileTime->dwHighDateTime = (DWORD)(preciseTime >> 32);
+}
+#define GetSystemTimePreciseAsFileTime py_GetSystemTimePreciseAsFileTime
+#endif
+
+
 // N.B. If raise_exc=0, this may be called without the GIL.
 static int
 py_get_system_clock(PyTime_t *tp, _Py_clock_info_t *info, int raise_exc)
@@ -913,7 +950,7 @@
     /* 11,644,473,600,000,000,000: number of nanoseconds between
        the 1st january 1601 and the 1st january 1970 (369 years + 89 leap
        days). */
-    PyTime_t ns = large.QuadPart * 100 - 11644473600000000000;
+    PyTime_t ns = large.QuadPart * 100 - 11644473600000000000ULL;
     *tp = ns;
     if (info) {
         // GetSystemTimePreciseAsFileTime() is implemented using
_PATCH
	# adjust python library location for GDB
	(s='\\\\'; sed -i "s/STDLIB_SUBDIR = 'Lib'/STDLIB_SUBDIR = '..${s}share${s}gdb${s}python'/g" 'Modules/getpath.py' || error "Failed to adjust ${BUILD}/python/Modules/getpath.py.")
fi

PY_MAJOR="$(echo "${PYTHON}" | awk 'BEGIN {FS = "[-.]"} { print $2}')"
PY_MINOR="$(echo "${PYTHON}" | awk 'BEGIN {FS = "[-.]"} { print $3}')"
if step "build ${PYTHON:-python}"; then
	cd "${BUILD}/python/PCbuild"
	#test ! -f Makefile.obj.mk || make clean >>"${LOG}" 2>&1
	make -j $THREADS CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ RC=x86_64-w64-mingw32-windres "CPPFLAGS=-I${HOST}/x86_64-w64-mingw32/include/ncurses" "CFLAGS=${CFLAGS}" "CXXFLAGS=${CXXFLAGS}" "LDFLAGS=${LDFLAGS} -static-libstdc++" "PY_DLL=gdb-python${PY_MAJOR}${PY_MINOR}-x64.dll" "PY_FREEZE_CMD=${BUILD}/host-python/Programs/_freeze_module" HAVE_BZ2=0 HAVE_EXPAT=1 HAVE_FFI=1 HAVE_OPENSSL=0 HAVE_LZMA=0 HAVE_SQLITE3=0 HAVE_TK=0 HAVE_CURSES=1 HAVE_CURSES_PANEL=1 >>"${LOG}" 2>&1 || error "Failed to build ${PYTHON}."
	cd mingw
	mkdir -p "${PREFIX}/share/gdb/python" || error "Failed to create ${PREFIX}/share/gdb/python."
	rcp -rf ../../Lib/* *.pyd "${PREFIX}/share/gdb/python/" || error "Failed to copy Python library files to ${PREFIX}/share/gdb/python."
	mkdir -p "${PREFIX}/bin" || error "Failed to create ${PREFIX}/bin."
	cp -f "gdb-python${PY_MAJOR}${PY_MINOR}-x64.dll" "${PREFIX}/bin/" || error "Failed to copy Python DLL to ${PREFIX}/bin."
fi

if step 'patch GDB source'; then
	rm -rf "${BUILD}/gdb-src"
	rcp -r "${SRC}/${GDB}" "${BUILD}/gdb-src" || error "Failed to copy GDB source to ${BUILD}/gdb-src."
	cd "${BUILD}/gdb-src"
	# environment variables are case-insensitive on Windows
	sed -i 's/strncmp/strncasecmp/g' 'gdbsupport/environ.cc' || error "Failed to patch ${BUILD}/gdb-src/gdbsupport/environ.cc."
	# fix missing NULL case handling
	awk -- "$(cat << '_PATCH'
/gdb_puts \(current_inferior/ {
	print "  const char *env = current_inferior ()->environment.get (path_var_name);"
	print "  if (!env)"
	print "    env = \"\";"
	print "  gdb_puts (env);"
	next
}
{
	print $0
}
_PATCH
)" 'gdb/infcmd.c' > 'gdb/infcmd.c.tmp' || error "Failed to patch ${BUILD}/gdb-src/gdb/infcmd.c."
	mv -f 'gdb/infcmd.c.tmp' 'gdb/infcmd.c' || error "Failed to replace ${BUILD}/gdb-src/gdb/infcmd.c."
	# ensure relative path for source highlight data directory
	sed -i '/HAVE_SOURCE_HIGHLIGHT/a \#define USE_RELATIVE_SRC_HIGHLIGHT 1' 'gdb/config.in' || error "Failed to patch ${BUILD}/gdb-src/gdb/config.in."
	# fix gdb/configure to support libipt
	sed -i '/linux\/perf_event.h missing or too old/s/^/pass #/g' 'gdb/configure' || error "Failed to patch ${BUILD}/gdb-src/gdb/configure."
	# fix gdbserver/configure to support libipt
	sed -i '/linux\/perf_event.h missing or too old/s/^/pass #/g' 'gdbserver/configure' || error "Failed to patch ${BUILD}/gdb-src/gdbserver/configure."
	# fix gdbsupport/configure to support libipt
	sed -i '/linux\/perf_event.h missing or too old/s/^/pass #/g' 'gdbsupport/configure' || error "Failed to patch ${BUILD}/gdb-src/gdbsupport/configure."
	# ensure relative path for terminfo database
	sed -i 's/#include <tic.h>/extern "C" NCURSES_EXPORT(const char *) _nc_tic_dir (const char *);/g' 'gdb/utils.c' || error "Failed to patch ${BUILD}/gdb-src/gdb/utils.c."
	sed -i '/HAVE_NCURSES_TERM_H/a \#define USE_RELATIVE_TERMINFO 1' 'gdb/config.in' || error "Failed to patch ${BUILD}/gdb-src/gdb/config.in."
	# default to "ms-terminal" if supported and TERM is unset
	sed -i "/NO_COLOR/r /dev/stdin" 'gdb/main.c' <<"_EOF" || error "Failed to patch ${BUILD}/gdb-src/gdb/main.c."
  const char *env_term = getenv ("TERM");
  DWORD con_mode = 0;
  if (env_term == nullptr || *env_term == 0) {
    if (GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &con_mode) && (con_mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0)
      putenv ("TERM=ms-terminal");
    else
      putenv ("TERM=#win32con");
   }
_EOF
	# default to "cmd" window when enabling TUI mode
	sed -i 's/tui_src_win/tui_cmd_win/g' 'gdb/tui/tui.c' || "Failed to patch ${BUILD}/gdb-src/gdb/tui/tui.c."
	# disable missing RTTI symbols warning
	sed -i '/RTTI symbol not found/d' 'gdb/cp-support.c' || "Failed to patch ${BUILD}/gdb-src/gdb/cp-support.c."
fi

if step "build ${GDB:-gdb}"; then
	mkdir -p "${BUILD}/gdb" || error "Failed to create ${BUILD}/gdb."
	cd "${BUILD}/gdb"
	cat <<_EOF >'python-paths.sh' || error "Failed to create ${BUILD}/gdb/python-paths.sh."
#!/bin/sh
while [ "\$#" -gt 0 ]; do
	case "\$1" in
	--includes)
		echo "-I${BUILD}/python/Include -I${BUILD}/python/PCbuild/mingw"
		;;
	--ldflags)
		echo "${BUILD}/python/PCbuild/mingw/libgdb-python${PY_MAJOR}${PY_MINOR}-x64.a"
		;;
	--exec-prefix)
		echo "${PREFIX}/share/gdb/python"
		;;
	esac
	shift
done
_EOF
	chmod 755 'python-paths.sh' || error "Failed to make ${BUILD}/python-paths.sh executable."
	gdb_cv_printf_has_long_double=yes \
	gdb_cv_printf_has_long_long=yes \
	gdb_cv_scanf_has_long_double=yes \
	PKG_CONFIG_PATH="${HOST}/x86_64-w64-mingw32/lib/pkgconfig" \
	"../gdb-src/configure" --host=x86_64-w64-mingw32 --with-static-standard-libraries --with-expat --disable-install-libbfd --disable-install-libiberty --enable-vtable-verify --disable-binutils --disable-ld --disable-gold --disable-gas --disable-sim --disable-gprof --disable-gprofng --disable-nls --disable-dependency-tracking --enable-curses --enable-tui --enable-source-highlight "--with-python=$PWD/python-paths.sh" "--with-python-libdir=${PREFIX}/share/gdb/python" --enable-lto --enable-targets=all "--enable-default-compressed-debug-sections-algorithm=${ZIP_OPT}" --with-intel-pt --with-xxhash "LDFLAGS=${LDFLAGS} -Wl,--allow-multiple-definition" "--prefix=${PREFIX}" "--with-gmp=${HOST}/x86_64-w64-mingw32" "--with-mpfr=${HOST}/x86_64-w64-mingw32" "--with-mpc=${HOST}/x86_64-w64-mingw32" "--with-isl=${HOST}/x86_64-w64-mingw32" "--with-libiconv-prefix=${HOST}/x86_64-w64-mingw32" --with-system-zlib >>"${LOG}" 2>&1 || error "Failed to configure ${GDB}."
	make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${GDB}."
	make install >>"${LOG}" 2>&1 || error "Failed to install ${GDB}."
	# reuse GDB's readline which is already properly patched for MinGW
	cd 'readline/readline'
	make install-static "prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to install readline from ${GDB}."
fi

if step "build ${OPENSSL:-openssl} path adjustment stub"; then
	mkdir -p "${BUILD}/openssl-paths" || error "Failed to create ${BUILD}/openssl-paths."
	cd "${BUILD}/openssl-paths"
	cat <<"_EOF" >'stub.c' || error "Failed to create ${BUILD}/openssl-paths/stub.c."
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>

static void _ossl_adjust_path_x(const WCHAR * param, const WCHAR * subPath) {
	const WCHAR * val = _wgetenv(param);
	if (val != NULL && *val != 0) {
		return; /* already set */
	}
	WCHAR path[MAX_PATH];
	const HMODULE hModule = GetModuleHandle(NULL);
	if (GetModuleFileNameW(hModule, path, MAX_PATH) == 0) {
		return; /* could not get executable path */
	}
	WCHAR * dir;
	for (int i = 0; i < 2; i++) {
		dir = wcsrchr(path, L'\\');
		if (dir == NULL) {
			dir = wcsrchr(path, L'/');
		}
		if (dir == NULL) {
			return; /* not a directory */
		}
		*dir = 0;
	}
	if (wcsncat_s(path, MAX_PATH, subPath, path + MAX_PATH - dir) != 0) {
		return; /* buffer overrun */
	}
	_wputenv_s(param, path);
}

void _ossl_adjust_paths(void) {
	_ossl_adjust_path_x(L"SSL_CERT_DIR", L"\\share\\ssl\\certs");
	_ossl_adjust_path_x(L"SSL_CERT_FILE", L"\\share\\ssl\\certs\\cert.pem");
	_ossl_adjust_path_x(L"OPENSSL_ENGINES", L"\\share\\ssl\\engines");
	_ossl_adjust_path_x(L"OPENSSL_MODULES", L"\\share\\ssl\\modules");
	_ossl_adjust_path_x(L"OPENSSL_CONF", L"\\share\\ssl\\openssl.cnf");
	_ossl_adjust_path_x(L"OPENSSL_CONF_INCLUDE", L"\\share\\ssl");
}
_EOF
	"${HOST}/bin/x86_64-w64-mingw32-gcc" ${CFLAGS} -c -o stub.o stub.c >>"${LOG}" 2>&1 || error "Failed to compile ${BUILD}/openssl-paths/stub.c."
	"${HOST}/bin/x86_64-w64-mingw32-gcc-ar" rc libossl-paths.a stub.o >>"${LOG}" 2>&1 || error "Failed to create ${BUILD}/openssl-paths/libossl-paths.a."
	install -m 644 libossl-paths.a "${HOST}/x86_64-w64-mingw32/lib/" || error "Failed to install ${BUILD}/openssl-paths/libossl-paths.a."
fi

if step "build ${OPENSSL:-openssl}"; then
	if [ "x${OPENSSL}" != 'x' ]; then
		rm -rf "${BUILD}/openssl"
		rcp -r "${SRC}/${OPENSSL}" "${BUILD}/openssl" || error "Failed to copy openssl source to ${BUILD}/openssl."
		cd "${BUILD}/openssl"
		if [ "x${OPENPACE}" != 'x' ]; then
			# patch OpenSSL for OpenPACE
			cat "${SRC}/${OPENPACE}/src/bsi_objects.txt" >>"crypto/objects/objects.txt" || error "Failed to patch openssl source ${BUILD}/openssl/crypto/objects/objects.txt for openpace."
		fi
		./Configure "--prefix=${HOST}/x86_64-w64-mingw32" "--openssldir=${PREFIX}/share/ssl" "--cross-compile-prefix=${HOST}/bin/x86_64-w64-mingw32-" enable-capieng shared zlib mingw64 --libdir=lib -lossl-paths >>"${LOG}" 2>&1 || error "Failed to configure ${OPENSSL}."
		sed -i -e '/ main/i extern void _ossl_adjust_paths(void);' -e '/ main/{n;a_ossl_adjust_paths();' -e '}' 'apps/openssl.c' || error "Failed to path ${BUILD}/openssl/apps/openssl.c."
		make -j $THREADS build_sw "ENGINESDIR=${PREFIX}/share/ssl/engines" "MODULESDIR=${PREFIX}/share/ssl/modules" >>"${LOG}" 2>&1 || error "Failed to build ${OPENSSL}."
		make install_dev >>"${LOG}" 2>&1 || error "Failed to install ${OPENSSL} to ${HOST}."
		make install_engines install_modules install_runtime install_ssldirs "INSTALLTOP=${PREFIX}" "ENGINESDIR=${PREFIX}/share/ssl/engines" "MODULESDIR=${PREFIX}/share/ssl/modules" >>"${LOG}" 2>&1 || error "Failed to install ${OPENSSL} to ${PREFIX}."
		mkdir -p "${PREFIX}/share/ssl/modules" || error "Failed to create ${PREFIX}/share/ssl/modules."
		rm -f "${PREFIX}/bin/c_rehash"
	else
		echo 'Skipped. Not configured.'
	fi
fi

if step "build ${P11:-p11}"; then
	if [ "x${P11}" != 'x' ]; then
		mkdir -p "${BUILD}/p11" || error "Failed to create ${BUILD}/p11."
		cd "${BUILD}/p11"
		"${SRC}/${P11}/configure" --host=x86_64-w64-mingw32 --disable-static --enable-shared --disable-dependency-tracking "--prefix=${HOST}/x86_64-w64-mingw32" >>"${LOG}" 2>&1 || error "Failed to configure ${P11}."
		make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${P11}."
		make install-exec 'DESTDIR=' "enginesexecdir=${PREFIX}/share/ssl/engines" "providersexecdir=${PREFIX}/share/ssl/modules" >>"${LOG}" 2>&1 || error "Failed to install ${P11}."
		for i in libpkcs11.dll pkcs11.dll.a pkcs11.la; do rm -f "${PREFIX}/share/ssl/engines/${i}" 2>/dev/null; done
		for i in libpkcs11.dll pkcs11prov.dll.a pkcs11prov.la; do rm -f "${PREFIX}/share/ssl/modules/${i}" 2>/dev/null; done
	else
		echo 'Skipped. Not configured.'
	fi
fi

if step "build ${SC_HSM_EMBED:-sc-hsm-embedded}"; then
	if [ "x${SC_HSM_EMBED}" != 'x' ]; then
		rm -rf "${BUILD}/sc-hsm-embedded"
		rcp -r "${SRC}/${SC_HSM_EMBED}" "${BUILD}/sc-hsm-embedded" || error "Failed to copy sc-hsm-embedded source to ${BUILD}/sc-hsm-embedded."
		cd "${BUILD}/sc-hsm-embedded"
		sed -i -e 's/__declspec(dllimport)//g' 'src/pkcs11/cryptoki.h' || error "Failed to patch ${SC_HSM_EMBED}/src/pkcs11/cryptoki.h."
		SC_HSM_EMBED_SRC='src/common/asn1.c src/common/bytebuffer.c src/common/bytestring.c src/common/cvc.c src/common/debug.c src/common/mutex.c src/common/pkcs15.c src/pkcs11/certificateobject.c src/pkcs11/crc32.c src/pkcs11/crypto-libcrypto.c src/pkcs11/dataobject.c src/pkcs11/object.c src/pkcs11/p11generic.c src/pkcs11/p11mechanisms.c src/pkcs11/p11objects.c src/pkcs11/p11session.c src/pkcs11/p11slots.c src/pkcs11/privatekeyobject.c src/pkcs11/publickeyobject.c src/pkcs11/secretkeyobject.c src/pkcs11/session.c src/pkcs11/slot-ctapi.c src/pkcs11/slot-pcsc-event.c src/pkcs11/slot-pcsc.c src/pkcs11/slot.c src/pkcs11/slotpool.c src/pkcs11/strbpcpy.c src/pkcs11/token-hba.c src/pkcs11/token-sc-hsm.c src/pkcs11/token-starcos-bnotk.c src/pkcs11/token-starcos-dgn.c src/pkcs11/token-starcos-dtrust.c src/pkcs11/token-starcos.c src/pkcs11/token.c'
		SC_HSM_EMBED_LIBS='-lcrypto.dll -lwinscard -lws2_32 -lgdi32 -ladvapi32 -lcrypt32 -luser32'
		cat <<"_EOF" >'sc-hsm-pkcs11.def' || error "Failed to create ${BUILD}/sc-hsm-embedded/sc-hsm-pkcs11.def."
EXPORTS
C_GetFunctionList
_EOF
		"${HOST}/bin/x86_64-w64-mingw32-gcc" $CFLAGS $LDFLAGS -Wl,--enable-auto-image-base -shared -o sc-hsm-pkcs11.dll -Isrc -DNDEBUG -DENABLE_LIBCRYPTO $SC_HSM_EMBED_SRC 'sc-hsm-pkcs11.def' $SC_HSM_EMBED_LIBS >>"${LOG}" 2>&1 || error "Failed to build ${SC_HSM_EMBED}."
		install -m 644 'sc-hsm-pkcs11.dll' "${PREFIX}/share/ssl/modules/sc-hsm-pkcs11.dll" || error "Failed to install ${SC_HSM_EMBED}/sc-hsm-pkcs11.dll."
	else
		echo 'Skipped. Not configured.'
	fi
fi

if step "build ${OPENPACE:-openpace}"; then
	if [ "x${OPENPACE}" != 'x' ]; then
		mkdir -p "${BUILD}/openpace" || error "Failed to create ${BUILD}/openpace."
		cd "${BUILD}/openpace"
		ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes "${SRC}/${OPENPACE}/configure" --host=x86_64-w64-mingw32 --enable-static --disable-shared --disable-dependency-tracking "--prefix=${HOST}/x86_64-w64-mingw32" "CPPFLAGS=${CPPFLAGS} -isystem \"${BUILD}/openssl/include\" -DHAVE_ASN1_STRING_GET0_DATA=1 -DHAVE_DECL_OPENSSL_ZALLOC=1 -DHAVE_DH_GET0_KEY=1 -DHAVE_DH_GET0_PQG=1 -DHAVE_DH_SET0_KEY=1 -DHAVE_DH_SET0_PQG=1 -DHAVE_ECDSA_SIG_GET0=1 -DHAVE_ECDSA_SIG_SET0=1 -DHAVE_EC_KEY_METHOD=1 -DHAVE_RSA_GET0_KEY=1 -DHAVE_RSA_SET0_KEY=1 -DHAVE_EC_POINT_GET_AFFINE_COORDINATES=1 -DHAVE_EC_POINT_SET_AFFINE_COORDINATES=1 -DDHAVE_EVP_PKEY_DUP" >>"${LOG}" 2>&1 || error "Failed to configure ${OPENPACE}."
		make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${OPENPACE}."
		make install >>"${LOG}" 2>&1 || error "Failed to install ${OPENPACE}."
	else
		echo 'Skipped. Not configured.'
	fi
fi

if step "build ${OPENSC:-opensc}"; then
	if [ "x${OPENSC}" != 'x' ]; then
		rm -rf "${BUILD}/opensc"
		rcp -r "${SRC}/${OPENSC}" "${BUILD}/opensc" || error "Failed to copy opensc source to ${BUILD}/opensc."
		cd "${BUILD}/opensc"
		# change libopensc.dll suffix
		sed -i '/version-info/c -avoid-version -release @OPENSC_LT_CURRENT@-x64 \\' 'src/libopensc/Makefile.am' || error "Failed to patch ${OPENSC}/src/libopensc/Makefile.am."
		# ensure shared built of minidriver with minimal size using the shared opensc library with some export additions
		sed -i -e 's/-module/& -shared/g' -e '/_static/a \	$(top_builddir)/src/common/libcompat.la \\\n	$(top_builddir)/src/ui/libnotify.la \\' -e 's/_static//g' 'src/minidriver/Makefile.am' || error "Failed to patch ${OPENSC}/src/minidriver/Makefile.am."
		echo 'sc_aux_data_get_md_flags' >>'src/libopensc/libopensc.exports' || error "Failed to patch ${OPENSC}/src/libopensc/libopensc.exports."
		echo 'pcsc_check_reader_handles' >>'src/libopensc/libopensc.exports' || error "Failed to patch ${OPENSC}/src/libopensc/libopensc.exports."
		echo 'sc_pkcs1_strip_02_padding_constant_time' >>'src/libopensc/libopensc.exports' || error "Failed to patch ${OPENSC}/src/libopensc/libopensc.exports."
		# make default PKCS#11 provider path relative to pkcs11-tool.exe
		sed -i '/DWORD expanded_len/r /dev/stdin' 'src/tools/pkcs11-tool.c' <<"_EOF" || error "Failed to patch ${OPENSC}/src/tools/pkcs11-tool.c."
	// mingw64-64 patch
	if (GetModuleFileNameA(GetModuleHandle(NULL), expanded_val, MAX_PATH) == 0) {
		return 1; /* could not get executable path */
	}
	char * dir;
	for (int i = 0; i < 2; i++) {
		dir = strrchr(expanded_val, '\\');
		if (dir == NULL) {
			dir = strrchr(expanded_val, '/');
		}
		if (dir == NULL) {
			return 1; /* not a directory */
		}
		*dir = 0;
	}
	_putenv_s("EXE_BASE_PATH", expanded_val);
_EOF
		# make default PKCS#15 profile path relative to the executable
		sed -i '/temp_len =/,/profile_dir = temp_path/c \		// mingw64-64 patch' 'src/pkcs15init/profile.c' && sed -i '/mingw64-64 patch/r /dev/stdin' 'src/pkcs15init/profile.c' <<"_EOF" || error "Failed to patch ${OPENSC}/src/pkcs15init/profile.c."
		temp_len = PATH_MAX - 1;
		if (GetModuleFileNameA(GetModuleHandle(NULL), temp_path, MAX_PATH) == 0) {
			LOG_FUNC_RETURN(ctx, SC_ERROR_PKCS15INIT); /* could not get executable path */
		}
		char * dir;
		for (int i = 0; i < 2; i++) {
			dir = strrchr(temp_path, '\\');
			if (dir == NULL) {
				dir = strrchr(temp_path, '/');
			}
			if (dir == NULL) {
				LOG_FUNC_RETURN(ctx, SC_ERROR_PKCS15INIT); /* not a directory */
			}
			*dir = 0;
		}
		strncat(temp_path, "\\share\\opensc\\profile", temp_len - strlen(temp_path));
		profile_dir = temp_path;
_EOF
		# make default opensc.conf path relative to the executable
		sed -i '/temp_len =/,/conf_path = temp_path/c \		// mingw64-64 patch' 'src/libopensc/ctx.c' && sed -i '/mingw64-64 patch/r /dev/stdin' 'src/libopensc/ctx.c' <<"_EOF" || error "Failed to patch ${OPENSC}/src/libopensc/ctx.c."
	conf_path = getenv("OPENSC_CONF");
	if (!conf_path) {
		temp_len = PATH_MAX - 1;
		if (GetModuleFileNameA(GetModuleHandle(NULL), temp_path, MAX_PATH) == 0) {
			sc_log(ctx, "process_config_file doesn't find base path of opensc config file.");
			return;
		}
		char * dir;
		for (int i = 0; i < 2; i++) {
			dir = strrchr(temp_path, '\\');
			if (dir == NULL) {
				dir = strrchr(temp_path, '/');
			}
			if (dir == NULL) {
				sc_log(ctx, "process_config_file doesn't find opensc config file.");
				return;
			}
			*dir = 0;
		}
		strncat(temp_path, "\\share\\opensc\\opensc.conf", temp_len - strlen(temp_path));
		conf_path = temp_path;
	}
_EOF
		# add minidriver install/uninstall files
		sed -n '/_MD_REGISTRATION/,/clang-format on/p' 'win32/customactions.cpp' >'make-batches.tpl' || error "Failed to create ${OPENSC}/make-batches.tpl."
		sed '/PLACEHOLDER/r make-batches.tpl' <<"_EOF" >'make-batches.c' || error "Failed to create ${OPENSC}/make-batches.c."
#include <stdio.h>
#include <string.h>

typedef unsigned char BYTE;
typedef unsigned long DWORD;
typedef char TCHAR;
#define TEXT(x) x

/* PLACEHOLDER */

int main() {
	FILE * fp[2] = {};
	const char * script[2] = {
		"install-opensc-minidriver.bat",
		"uninstall-opensc-minidriver.bat"
	};
	const char * baseKey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards";
	const char * cryptoProvider = "Microsoft Base Smart Card Crypto Provider";
	const char * keyStorageProvider = "Microsoft Smart Card Key Storage Provider";
	const char * driverName = "opensc-minidriver.dll";
	const char * packageName = "gcc-win64";
	const char * tempFile = "%TEMP%\\install-opensc-minidriver.reg";
	const size_t count = sizeof(minidriver_registration) / sizeof(minidriver_registration[0]);

	for (size_t i = 0; i < 2; i++) {
		fp[i] = fopen(script[i], "wb");
		if (fp[i] == NULL) {
			fprintf(stderr, "Error creating file: %s\r\n", script[i]);
			for (size_t j = 0; j < i; j++) {
				fclose(fp[j]);
			}
			return 1;
		}

		fprintf(fp[i], "@ECHO OFF\r\n");
		fprintf(fp[i], "SETLOCAL ENABLEDELAYEDEXPANSION\r\n");
		fprintf(fp[i], "\r\n");
		fprintf(fp[i], "NET SESSION >NUL 2>&1\r\n");
		fprintf(fp[i], "IF ERRORLEVEL 1 (\r\n");
		fprintf(fp[i], "	ECHO Please run this script with administrator privileges.\r\n");
		fprintf(fp[i], "	PAUSE\r\n");
		fprintf(fp[i], "	EXIT /B 1\r\n");
		fprintf(fp[i], ")\r\n");
		fprintf(fp[i], "\r\n");
		fprintf(fp[i], "SET BASE_KEY=%s\r\n", baseKey);
	}
	
	fprintf(fp[0], "FOR %%%%A IN (\"%%~dp0\\..\\..\\bin\") DO SET \"DRIVER_DIR=%%%%~fA\"\r\n");
	fprintf(fp[0], "SET COUNT=-1\r\n");
	fprintf(fp[0], "\r\n");
	fprintf(fp[0], "IF NOT EXIST \"%%DRIVER_DIR%%\\%s\" (\r\n", driverName);
	fprintf(fp[0], "	ECHO Could not find driver in \"%%DRIVER_DIR%%\\%s\".\r\n", driverName);
	fprintf(fp[0], "	PAUSE\r\n");
	fprintf(fp[0], "	EXIT /B 1\r\n");
	fprintf(fp[0], ")\r\n");
	fprintf(fp[0], "\r\n");

	for (size_t i = 0; i < count; i++) {
		fprintf(fp[0], "SET /A COUNT+=1\r\n");
		fprintf(fp[0], "SET  SC_NAME[%%COUNT%%]=%s\r\n", minidriver_registration[i].szName);
	
		fprintf(fp[0], "SET      ATR[%%COUNT%%]=");
		for (DWORD j = 0; j < minidriver_registration[i].dwAtrSize; j++) {
			if (j != 0) {
				fprintf(fp[0], ",");
			}
			fprintf(fp[0], "%02x", minidriver_registration[i].pbAtr[j]);
		}
		fprintf(fp[0], "\r\n");
	
		fprintf(fp[0], "SET ATR_MASK[%%COUNT%%]=");
		for (DWORD j = 0; j < minidriver_registration[i].dwAtrSize; j++) {
			if (j != 0) {
				fprintf(fp[0], ",");
			}
			fprintf(fp[0], "%02x", minidriver_registration[i].pbAtrMask[j]);
		}
		fprintf(fp[0], "\r\n");
	}

	fprintf(fp[0], "\r\n");
	fprintf(fp[0], "REM Loop through the registration data and add registry entries.\r\n");
	fprintf(fp[0], "FOR /L %%%%i IN (0,1,%%COUNT%%) DO (\r\n");
	fprintf(fp[0], "	SET \"INSTALLED_BY=\"\r\n");
	fprintf(fp[0], "	FOR /F \"tokens=2*\" %%%%A IN ('REG QUERY \"%%BASE_KEY%%\\!SC_NAME[%%%%i]!\" /V InstalledBy 2^>NUL') DO SET \"INSTALLED_BY=%%%%B\"\r\n");
	fprintf(fp[0], "	REG QUERY \"%%BASE_KEY%%\\!SC_NAME[%%%%i]!\" >NUL 2>&1\r\n");
	fprintf(fp[0], "	IF ERRORLEVEL 1 SET \"INSTALLED_BY=%s\"\r\n", packageName);
	fprintf(fp[0], "	IF \"!INSTALLED_BY!\"==\"%s\" (\r\n", packageName);
	fprintf(fp[0], "		ECHO Adding entry for \"!SC_NAME[%%%%i]!\".\r\n");
	fprintf(fp[0], "		SET \"SUB_KEY=%%BASE_KEY%%\\!SC_NAME[%%%%i]!\"\r\n");
	fprintf(fp[0], "\r\n");
	fprintf(fp[0], "		ECHO Windows Registry Editor Version 5.00 > \"%s\"\r\n", tempFile);
	fprintf(fp[0], "		ECHO. >> \"%s\"\r\n", tempFile);
	fprintf(fp[0], "		ECHO [!SUB_KEY!] >> \"%s\"\r\n", tempFile);
	fprintf(fp[0], "		ECHO \"ATR\"=hex:!ATR[%%%%i]! >> \"%s\"\r\n", tempFile);
	fprintf(fp[0], "		ECHO \"ATRMask\"=hex:!ATR_MASK[%%%%i]! >> \"%s\"\r\n", tempFile);
	fprintf(fp[0], "		ECHO \"Crypto Provider\"=\"%s\" >> \"%s\"\r\n", cryptoProvider, tempFile);
	fprintf(fp[0], "		ECHO \"80000001\"=\"%%DRIVER_DIR%%\\%s\" >> \"%s\"\r\n", driverName, tempFile);
	fprintf(fp[0], "		ECHO \"Smart Card Key Storage Provider\"=\"%s\" >> \"%s\"\r\n", keyStorageProvider, tempFile);
	fprintf(fp[0], "		ECHO \"InstalledBy\"=\"%s\" >> \"%s\"\r\n", packageName, tempFile);
	fprintf(fp[0], "\r\n");
	fprintf(fp[0], "		REG IMPORT \"%s\" >NUL 2>&1\r\n", tempFile);
	fprintf(fp[0], "		IF ERRORLEVEL 1 (\r\n");
	fprintf(fp[0], "			ECHO Failed to add registry entry for \"!SC_NAME[%%%%i]!\".\r\n");
	fprintf(fp[0], "		) ELSE (\r\n");
	fprintf(fp[0], "			ECHO Successfully added registry entry for \"!SC_NAME[%%%%i]!\".\r\n");
	fprintf(fp[0], "		)\r\n");
	fprintf(fp[0], "		ECHO.\r\n");
	fprintf(fp[0], "	)\r\n");
	fprintf(fp[0], ")\r\n");
	fprintf(fp[0], "DEL /F /Q \"%s\"\r\n", tempFile);

	fprintf(fp[1], "\r\n");
	fprintf(fp[1], "REM Delete all drivers previously installed.\r\n");
	fprintf(fp[1], "FOR /F \"tokens=*\" %%%%A IN ('REG QUERY \"%%BASE_KEY%%\" 2^>NUL') DO (\r\n");
	fprintf(fp[1], "	SET \"INSTALLED_BY=\"\r\n");
	fprintf(fp[1], "	FOR /F \"tokens=2*\" %%%%X IN ('REG QUERY \"%%%%A\" /V InstalledBy 2^>NUL') DO SET \"INSTALLED_BY=%%%%Y\"\r\n");
	fprintf(fp[1], "	IF \"!INSTALLED_BY!\"==\"%s\" (\r\n", packageName);
	fprintf(fp[1], "		ECHO Deleting path \"%%%%A\".\r\n");
	fprintf(fp[1], "		REG DELETE \"%%%%A\" /F >NUL 2>&1\r\n");
	fprintf(fp[1], "		IF ERRORLEVEL 1 (\r\n");
	fprintf(fp[1], "			ECHO Failed to delete registry path \"%%%%A\".\r\n");
	fprintf(fp[1], "		) ELSE (\r\n");
	fprintf(fp[1], "			ECHO Successfully deleted registry path \"%%%%A\".\r\n");
	fprintf(fp[1], "		)\r\n");
	fprintf(fp[1], "	)\r\n");
	fprintf(fp[1], "	ECHO.\r\n");
	fprintf(fp[1], ")\r\n");

	for (size_t i = 0; i < 2; i++) {
		fprintf(fp[i], "\r\n");
		fprintf(fp[i], "ECHO Done.\r\n");
		fprintf(fp[i], "PAUSE\r\n");
		fprintf(fp[i], "EXIT /B 0\r\n");
		fclose(fp[i]);
	}

	return 0;
}
_EOF
		# fix name conflict with rpc.h "interface" macro
		sed -i '/#define MAGIC/a \#undef interface' 'src/common/libpkcs11.c' || error "Failed to patch ${OPENSC}/common/libpkcs11.c."
		# fix missing manifests in .rc files
		echo '2 24 "opensc-pkcs11.dll.manifest"' >> 'src/pkcs11/versioninfo-pkcs11.rc.in' || error "Failed to add manifest to ${OPENSC}/versioninfo-pkcs11.rc.in."
		echo '2 24 "opensc-pkcs11.dll.manifest"' >> 'src/pkcs11/versioninfo-pkcs11-spy.rc.in' || error "Failed to add manifest to ${OPENSC}/versioninfo-pkcs11-spy.rc.in."
		echo '2 24 "exe.manifest"' >> 'src/tools/versioninfo-opensc-notify.rc.in' || error "Failed to add manifest to ${OPENSC}/versioninfo-opensc-notify.rc.in."
		echo '2 24 "exe.manifest"' >> 'src/tools/versioninfo-tools.rc.in' || error "Failed to add manifest to ${OPENSC}/versioninfo-tools.rc.in."
		echo '2 24 "opensc-minidriver.dll.manifest"' >> 'src/minidriver/versioninfo-minidriver.rc.in' || error "Failed to add manifest to ${OPENSC}/versioninfo-minidriver.rc.in."
		autoreconf --install --force >>"${LOG}" 2>&1 || error "Failed to reconfigure ${OPENSC}."
		sed -i '/lt_cv_deplibs_check_method=/c lt_cv_deplibs_check_method=pass_all' configure || error "Failed to patch ${OPENSC}/configure."
		if [ "x${OPENPACE}" != 'x' ]; then
			OPENSC_CONF="--enable-openpace"
			OPENSC_LIBS="-leac -lcrypto -lz -lwinscard -lws2_32 -lgdi32 -ladvapi32 -lcrypt32 -lncrypt -luser32 -lshlwapi -lcomctl32"
		else
			OPENSC_CONF=""
			OPENSC_LIBS="-lcrypto -lz -lwinscard -lws2_32 -lgdi32 -ladvapi32 -lcrypt32 -lncrypt -luser32 -lshlwapi -lcomctl32"
		fi
		lt_cv_to_host_file_cmd=func_convert_file_noop ./configure --disable-static --enable-shared --host=x86_64-w64-mingw32 --disable-dependency-tracking --enable-openssl-secure-malloc=65536 --enable-notify --disable-strict $OPENSC_CONF --enable-minidriver --enable-zlib --enable-readline --enable-openssl --enable-thread-locking --disable-doc --disable-tests '--with-pkcs11-provider=%EXE_BASE_PATH%\\share\\ssl\\modules\\opensc-pkcs11.dll' '--enable-cvcdir=%EXE_BASE_PATH%\\share\\opensc\\cvc' "--prefix=${HOST}/x86_64-w64-mingw32" "OPENPACE_LIBS=-leac -lcrypto" "LIBS=${OPENSC_LIBS}" "CPPFLAGS=${CPPFLAGS} -DWINVER=0x0601 -D_WIN32_WINNT=0x601 -DWIN32_LEAN_AND_MEAN -DOPENSSL_SECURE_MALLOC_SIZE=65536" >>"${LOG}" 2>&1 || error "Failed to configure ${OPENSC}."
		sed -i -e '/HAVE_OPENSSL_CRYPTO_H/c \#define HAVE_OPENSSL_CRYPTO_H 1\n#define HAVE_IO_H 1' -e '/OPENSC_FEATURES/c \#define OPENSC_FEATURES "pcsc openssl zlib"' 'config.h' || error "Failed to patch ${OPENSC}/confg.h."
		make -j $THREADS V=1 >>"${LOG}" 2>&1 || error "Failed to build ${OPENSC}."
		gcc -o 'make-batches' 'make-batches.c' || error "Failed to compile ${OPENSC}/make-batches.c."
		./make-batches || error "Failed to create minidriver install/uninstall scripts for ${OPENSC}."
		install -m 644 'src/libopensc/.libs/libopensc-12-x64.dll' "${PREFIX}/bin/libopensc-12-x64.dll" || error "Failed to install ${OPENSC}/libopensc-12-x64.dll."
		for i in opensc-tool pkcs11-tool pkcs15-crypt pkcs15-init pkcs15-tool sc-hsm-tool; do
			install -m 644 "src/tools/.libs/${i}.exe" "${PREFIX}/bin/${i}.exe" || error "Failed to install ${OPENSC}/${i}.exe."
		done
		install -m 644 'src/minidriver/.libs/opensc-minidriver64.dll' "${PREFIX}/bin/opensc-minidriver.dll" || error "Failed to install ${OPENSC}/opensc-minidriver.dll."
		install -m 644 'src/pkcs11/.libs/pkcs11-spy.dll' "${PREFIX}/share/ssl/modules/pkcs11-spy.dll" || error "Failed to install ${OPENSC}/pkcs11-spy.dll."
		install -m 644 'src/pkcs11/.libs/opensc-pkcs11.dll' "${PREFIX}/share/ssl/modules/opensc-pkcs11.dll" || error "Failed to install ${OPENSC}/opensc-pkcs11.dll."
		install -Dm 644 "etc/opensc.conf" "${PREFIX}/share/opensc/opensc.conf" || error "Failed to install ${OPENSC}/opensc.conf."
		for i in 'install-opensc-minidriver.bat' 'uninstall-opensc-minidriver.bat'; do
			install -Dm 644 "${i}" "${PREFIX}/share/opensc/${i}" || error "Failed to install ${OPENSC}/${i}."
		done
		for i in "src/pkcs15init/"*".profile"; do
			install -Dm 644 "${i}" "${PREFIX}/share/opensc/profile/$(basename "${i}")" || error "Failed to install ${OPENSC}/$(basename "${i}")."
		done
	else
		echo 'Skipped. Not configured.'
	fi
fi

if step "build ${OSSLSIGNCODE:-osslsigncode}"; then
	if [ "x${OSSLSIGNCODE}" != 'x' ]; then
		rm -rf "${BUILD}/osslsigncode"
		rcp -r "${SRC}/${OSSLSIGNCODE}" "${BUILD}/osslsigncode" || error "Failed to copy osslsigncode source to ${BUILD}/osslsigncode."
		cd "${BUILD}/osslsigncode"
		sed -i 's/ws2_32/ossl-paths.lib ws2_32/g' 'CMakeLists.txt' || error "Failed to patch ${BUILD}/osslsigncode/CMakeLists.txt."
		cmake --install-prefix "${PREFIX}" -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY "-DCMAKE_C_COMPILER=${HOST}/bin/x86_64-w64-mingw32-gcc" "-DCMAKE_C_FLAGS=${CFLAGS}" "-DCMAKE_AR=${HOST}/bin/x86_64-w64-mingw32-gcc-ar" "-DCMAKE_RANLIB=${HOST}/bin/x86_64-w64-mingw32-gcc-ranlib" "-DCMAKE_EXE_LINKER_FLAGS=${LDFLAGS}" -DCMAKE_BUILD_TYPE=Release "-DOPENSSL_ROOT_DIR=${HOST}/x86_64-w64-mingw32" "-DZLIB_INCLUDE_DIR=${HOST}/x86_64-w64-mingw32/include" "-DZLIB_LIBRARY=${HOST}/x86_64-w64-mingw32/lib/libz.a" "-DCMAKE_VERBOSE_MAKEFILE=ON" . >>"${LOG}" 2>&1 || error "Failed create build scripts for ${OSSLSIGNCODE}."
		sed -i -e '/main(/i extern void _ossl_adjust_paths(void);' -e '/main(/{n;a_ossl_adjust_paths();' -e '}' 'osslsigncode.c' || error "Failed to path ${BUILD}/osslsigncode/osslsigncode.c."
		make -j $THREADS >>"${LOG}" 2>&1 || error "Failed to build ${OSSLSIGNCODE}."
		install -m 644 'osslsigncode.exe' "${PREFIX}/bin/" >>"${LOG}" 2>&1 || error "Failed to install ${OSSLSIGNCODE}/osslsigncode.exe."
	else
		echo 'Skipped. Not configured.'
	fi
fi

if step 'strip debug symbols in executables'; then
	cd "${PREFIX}"
	cat <<"_EOF" >"${BUILD}/remove-signature.sh" || error "Failed to create ${BUILD}/remove-signature.sh."
#!/bin/sh
osslsigncode remove-signature -in "$1" -out "$1.tmp" >/dev/null 2>&1 && mv -f "$1.tmp" "$1" >/dev/null 2>&1
_EOF
	chmod 755 "${BUILD}/remove-signature.sh"
	# ensure previously attached code sign certificates are removed before stripping
	find . -type f '(' -iname '*.dll' -o -iname '*.pyd' -o -iname '*.exe' ')' -exec "${BUILD}/remove-signature.sh" '{}' ';' >>"${LOG}" 2>&1
	find . -type f '(' -iname '*.dll' -o -iname '*.pyd' -o -iname '*.exe' ')' -exec "${HOST}/bin/x86_64-w64-mingw32-strip" --strip-all '{}' ';' >>"${LOG}" 2>&1
fi

if step 'create copyright and license files'; then
	mkdir -p "${LICENSE}" || error "Failed to create ${LICENSE}."
	mkdir -p "${BUILD}/license" || error "Failed to create ${BUILD}/license."
	cd "${BUILD}/license"
	targets="${ZLIB}"
	targets="${targets} ${GMP}"
	targets="${targets} ${MPFR}"
	targets="${targets} ${MPC}"
	targets="${targets} ${ISL}"
	targets="${targets} ${CLOOG_ISL}"
	targets="${targets} ${BINUTILS}"
	targets="${targets} ${MINGW}"
	targets="${targets} ${GCC}"
	targets="${targets} ${EXPAT}"
	targets="${targets} ${NCURSES}"
	targets="${targets} ${BOOST}"
	targets="${targets} ${HIGHLIGHT}"
	targets="${targets} ${IPT}"
	targets="${targets} ${WINIPT}"
	targets="${targets} ${XXHASH}"
	targets="${targets} ${FFI}"
	targets="${targets} ${ICONV}"
	targets="${targets} ${PYTHON}"
	targets="${targets} ${GDB}"
	[ "x${ZSTD}" != 'x' ] && targets="${targets} ${ZSTD}"
	[ "x${OCL_SDK}" != 'x' ] && targets="${targets} ${OCL_SDK}"
	[ "x${OPENSSL}" != 'x' ] && targets="${targets} ${OPENSSL}"
	[ "x${P11}" != 'x' ] && targets="${targets} ${P11}"
	[ "x${SC_HSM_EMBED}" != 'x' ] && targets="${targets} ${SC_HSM_EMBED}"
	[ "x${OPENPACE}" != 'x' ] && targets="${targets} ${OPENPACE}"
	[ "x${OPENSC}" != 'x' ] && targets="${targets} ${OPENSC}"
	[ "x${OSSLSIGNCODE}" != 'x' ] && targets="${targets} ${OSSLSIGNCODE}"
	cat <<"_EOF" >Makefile
all: $(addsuffix .txt,$(addprefix $(DST)/,$(TARGETS)))
$(DST)/%.txt: $(SRC)/%
	cd "$<" && licensecheck --copyright -c '.*' -r -l 0 -i '(?i)(.*(huffman-rand-max\.in)|(mutation\.d)|(\.(1|au|bin|bz2|chm|crw|doctree|dia|elf5|exe|golden|gif|gmo|gz|html|icns|ico|jpg|jpeg|odg|odp|pdf|png|po|pptx|psd|pyc|sln|so|tar|tif|vcproj|vcxproj|wav|whl|xls|xz|zip)))' -- * | sed -e '/: \*No copyright\* UNKNOWN$$/d' -e '/^[[:space:]]*$$/d' >"$@"
_EOF
	make -j $THREADS "SRC=${SRC}" "DST=${LICENSE}" "TARGETS=${targets}" 2>&1 | grep -v 'does not map to ascii at' >>"${LOG}" || error "Failed to create copyright and licenses."
fi

if step 'sign executables'; then
	if [ "x${SIGN}" != 'x' ]; then
		cd "${ROOT}"
		find "${PREFIX}" -type f '(' -iname '*.dll' -o -iname '*.pyd' -o -iname '*.exe' ')' -exec "${SIGN}" '{}' ';' >>"${LOG}" 2>&1 || error "Failed to sign files."
	else
		echo 'Skipped. Not configured.'
	fi
fi

if step 'create distribution package'; then
	cd "${ROOT}"
	cp "${0}" "${PREFIX}/" || error "Failed to copy ${0} to ${PREFIX}."
	cat <<"_EOFSH" >"${PREFIX}/test-mingw64.sh" || error "Failed to create ${PREFIX}/test-mingw64.sh."
#!/bin/sh

PREFIX="./bin/"
VERSION="$(${PREFIX}gcc --version | awk '{ print $3; exit}')"
VERBOSE="no" # yes/no

CCEXE="mingw64-c.exe"
CC="gcc"
CFLAGS="-o ${CCEXE} -O2"

CXXEXE="mingw64-c++.exe"
CXX="g++"
CXXFLAGS="-o ${CXXEXE} -O2"

for mode in m32 m64 m32-static m64-static m32-e m64-e m32-e-static m64-e-static m32-ee m64-ee m32-ee-static m64-ee-static; do
echo -e "\e[1mInfo: Trying mode '${mode}'.\e[0m"

case "${mode}" in
	m32*)
		EFLAGS="-m32"
		cp -f "${PREFIX%/*}/../x86_64-w64-mingw32/lib/gcc/x86_64-w64-mingw32/${VERSION}/32/libstdc++-6-x86.dll" .
		;;
	m64*)
		EFLAGS="-m64"
		cp -f "${PREFIX%/*}/../x86_64-w64-mingw32/lib/gcc/x86_64-w64-mingw32/${VERSION}/libstdc++-6-x64.dll" .
		;;
esac

case "${mode}" in
	*-static)
		EFLAGS="${EFLAGS} -static"
		;;
esac

case "${mode}" in
	*-e*)
		EFLAGS="${EFLAGS} -flto -fuse-linker-plugin"
		;;
esac

case "${mode}" in
	*-ee*)
		EFLAGS="${EFLAGS} -fgraphite"
		;;
esac

[ "${VERBOSE}" = "yes" ] && echo ${PREFIX}${CC} ${CFLAGS} ${EFLAGS} -x c -
${PREFIX}${CC} ${CFLAGS} ${EFLAGS} -x c - <<'_EOF'
#include <stdlib.h>
#include <stdio.h>

__attribute__((used))
extern void __main ();

int main(int argc, char * argv[], char * envp[]) {
	fprintf(stdout, "Hello World!\n");
	return EXIT_SUCCESS;
}

_EOF
if [ $? -ne 0 ]; then
	echo "Error: Failed to build C application." >&2
	#exit 1
fi

./${CCEXE}
if [ $? -ne 0 ]; then
	echo "Error: Failed to run built C application." >&2
	#exit 1
fi

[ "${VERBOSE}" = "yes" ] && echo ${PREFIX}${CXX} ${CXXFLAGS} ${EFLAGS} -x c++ -
${PREFIX}${CXX} ${CXXFLAGS} ${EFLAGS} -x c++ - <<'_EOF'
#include <cstdlib>
#include <iostream>

__attribute__((used))
extern void __main ();

__attribute__((used))
int main(int argc, char * argv[], char * envp[]) {
	std::cout << "Hello World!" << std::endl;
	return EXIT_SUCCESS;
}

_EOF
if [ $? -ne 0 ]; then
	echo "Error: Failed to build C++ application." >&2
	#exit 1
fi

./${CXXEXE}
if [ $? -ne 0 ]; then
	echo "Error: Failed to run built C++ application." >&2
	#exit 1
fi
done
_EOFSH
	cat <<"_EOFBAT" | sed 's/$/\r/' >"${PREFIX}/test-mingw64.bat" || error "Failed to create ${PREFIX}/test-mingw64.bat."
@ECHO off
SETLOCAL ENABLEDELAYEDEXPANSION

SET "PREFIX=%~dp0\bin"
FOR /f "tokens=3" %%i in ('%PREFIX%\gcc.exe --version') DO SET "VERSION=%%i" & GOTO :version_found
:version_found
SET "VERBOSE=no"

SET "CCEXE=mingw64-c.exe"
SET "CC=gcc.exe"
SET "CFLAGS=-o %CCEXE% -O2"

SET "CXXEXE=mingw64-c^+^+.exe"
SET "CXX=g^+^+.exe"
SET "CXXFLAGS=-o %CXXEXE% -O2"

FOR %%m IN (m32 m64 m32-static m64-static m32-e m64-e m32-e-static m64-e-static m32-ee m64-ee m32-ee-static m64-ee-static) DO (
	ECHO Info: Trying mode '%%m'.

	IF "%%m"=="m32" (
		SET "EFLAGS=-m32"
		COPY /y "%PREFIX%\..\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\%VERSION%\32\libstdc++-6-x86.dll" . >NUL
	) ELSE IF "%%m"=="m64" (
		SET "EFLAGS=-m64"
		COPY /y "%PREFIX%\..\x86_64-w64-mingw32\lib\gcc\x86_64-w64-mingw32\%VERSION%\libstdc++-6-x64.dll" . >NUL
	)

	IF "%%m"=="m32-static" (
		SET "EFLAGS=!EFLAGS! -static"
	) ELSE IF "%%m"=="m64-static" (
		SET "EFLAGS=!EFLAGS! -static"
	)

	IF "%%m"=="m32-e" (
		SET "EFLAGS=!EFLAGS! -flto -fuse-linker-plugin"
	) ELSE IF "%%m"=="m64-e" (
		SET "EFLAGS=!EFLAGS! -flto -fuse-linker-plugin"
	)

	IF "%%m"=="m32-ee" (
		SET "EFLAGS=!EFLAGS! -fgraphite"
	) ELSE IF "%%m"=="m64-ee" (
		SET "EFLAGS=!EFLAGS! -fgraphite"
	)

	IF "%VERBOSE%"=="yes" ECHO %PREFIX%\%CC% %CFLAGS% !EFLAGS! -x c temp.c

	(
		ECHO #include ^<stdlib.h^>
		ECHO #include ^<stdio.h^>
		ECHO.
		ECHO __attribute__^(^(used^)^)
		ECHO extern void __main ^(^);
		ECHO.
		ECHO int main^(int argc, char * argv[], char * envp[]^) {
		ECHO     fprintf^(stdout, "Hello World^!\n"^);
		ECHO     return EXIT_SUCCESS;
		ECHO }
	) > temp.c

	%PREFIX%\%CC% %CFLAGS% !EFLAGS! -x c temp.c
	IF NOT %errorlevel% == 0 (
		DEL /f temp.c
		ECHO Error: Failed to build C application.
		REM exit /b 1
	)
	DEL /f temp.c

	CALL .\%CCEXE%
	IF NOT %errorlevel% == 0 (
		ECHO Error: Failed to run built C application.
		REM exit /b 1
	)

	IF "%VERBOSE%"=="yes" ECHO %PREFIX%\%CXX% %CXXFLAGS% !EFLAGS! -x c^+^+ temp.cpp

	(
		ECHO #include ^<cstdlib^>
		ECHO #include ^<iostream^>
		ECHO.
		ECHO __attribute__^(^(used^)^)
		ECHO extern void __main ^(^);
		ECHO.
		ECHO __attribute__^(^(used^)^)
		ECHO int main^(int argc, char * argv[], char * envp[]^) {
		ECHO     std::cout ^<^< "Hello World^!" ^<^< std::endl;
		ECHO     return EXIT_SUCCESS;
		ECHO }
	) > temp.cpp

	%PREFIX%\%CXX% %CXXFLAGS% !EFLAGS! -x c++ temp.cpp
	IF NOT %errorlevel% == 0 (
		DEL /f temp.cpp
		ECHO Error: Failed to build C++ application.
		REM exit /b 1
	)
	DEL /f temp.cpp

	CALL .\%CXXEXE%
	IF NOT %errorlevel% == 0 (
		ECHO Error: Failed to run built C++ application.
		REM exit /b 1
	)
)
_EOFBAT
	cd "${PREFIX}"
	find . -depth -type d -name '__pycache__' -exec rm -rf '{}' ';'
	GDB="$(echo "${GDB}" | sed 's/^gdb-gdb/gdb/')"
	rm -f "${ROOT}/${GCC}-${GDB}-${BINUTILS}-${MINGW}-${MCRTDLL}.7z" >/dev/null 2>&1
	7z a -t7z -mx9 -myx -md192m -mfb273 -ms=on -l "${ROOT}/${GCC}-${GDB}-${BINUTILS}-${MINGW}-${MCRTDLL}.7z" * || error "Failed to pack ${GCC}-${GDB}-${BINUTILS}-${MINGW}-${MCRTDLL}.7z."
	# The following commands can be used to retain symlinks.
	# This, however, requires admin right on Windows for unpacking.
	#rm -f "${ROOT}/${GCC}-${GDB}-${BINUTILS}-${MINGW}-${MCRTDLL}.tar.xz" >/dev/null 2>&1
	#XZ_OPT="-e9 --lzma2=dict=192MiB,nice=273" tar -cJf "${ROOT}/${GCC}-${GDB}-${BINUTILS}-${MINGW}-${MCRTDLL}.tar.xz" --owner=0 --group=0 --mode=og-w * || error "Failed to pack ${GCC}-${GDB}-${BINUTILS}-${MINGW}-${MCRTDLL}.tar.xz."
fi
