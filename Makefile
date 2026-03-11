CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?=
LDLIBS  ?=
JOBS    ?= 4

COMPAT_CPU ?=
COMPAT_CFLAGS :=

ifeq ($(COMPAT_CPU),generic)
COMPAT_CFLAGS +=
else ifeq ($(COMPAT_CPU),x86)
COMPAT_CFLAGS += -march=i686
else ifeq ($(COMPAT_CPU),x86_64)
COMPAT_CFLAGS += -mcpu=x86_64
else ifeq ($(COMPAT_CPU),arm32)
COMPAT_CFLAGS += -mcpu=arm10tdmi -marm
else ifeq ($(COMPAT_CPU),arm32hf)
COMPAT_CFLAGS += -march=armv6 -marm -mfloat-abi=hard
else ifeq ($(COMPAT_CPU),armeb)
COMPAT_CFLAGS += -mcpu=arm10tdmi -marm
else ifeq ($(COMPAT_CPU),armebhf)
COMPAT_CFLAGS += -march=armv6 -marm -mfloat-abi=hard
else ifeq ($(COMPAT_CPU),aarch64)
COMPAT_CFLAGS += -mcpu=baseline
else ifeq ($(COMPAT_CPU),aarch64_be)
COMPAT_CFLAGS += -mcpu=baseline
else ifeq ($(COMPAT_CPU),mips)
COMPAT_CFLAGS += -march=mips32 -msoft-float
else ifeq ($(COMPAT_CPU),mipshf)
COMPAT_CFLAGS += -march=mips32 -mhard-float
else ifeq ($(COMPAT_CPU),mipsel)
COMPAT_CFLAGS += -march=mips32 -msoft-float
else ifeq ($(COMPAT_CPU),mipselhf)
COMPAT_CFLAGS += -march=mips32 -mhard-float
else ifeq ($(COMPAT_CPU),mips64)
COMPAT_CFLAGS += -march=mips64r2 -mabi=64
else ifeq ($(COMPAT_CPU),mips64el)
COMPAT_CFLAGS += -march=mips64r2 -mabi=64
else ifeq ($(COMPAT_CPU),mips64n32)
COMPAT_CFLAGS += -march=mips64r2 -mabi=n32
else ifeq ($(COMPAT_CPU),mips64eln32)
COMPAT_CFLAGS += -march=mips64r2 -mabi=n32
else ifeq ($(COMPAT_CPU),powerpc)
COMPAT_CFLAGS += -mcpu=ppc -mno-altivec
else ifeq ($(COMPAT_CPU),powerpchf)
COMPAT_CFLAGS += -mcpu=ppc -mhard-float -mno-altivec
else ifeq ($(COMPAT_CPU),powerpc64)
COMPAT_CFLAGS += -mcpu=ppc64 -mno-altivec
else ifeq ($(COMPAT_CPU),powerpc64le)
COMPAT_CFLAGS += -mcpu=ppc64 -mno-altivec
else ifeq ($(COMPAT_CPU),riscv32)
COMPAT_CFLAGS += -mcpu=baseline_rv32
else ifeq ($(COMPAT_CPU),riscv64)
COMPAT_CFLAGS += -mcpu=baseline_rv64 -mabi=lp64d
else ifeq ($(COMPAT_CPU),s390x)
COMPAT_CFLAGS += -march=z10
else ifeq ($(COMPAT_CPU),sparc64)
COMPAT_CFLAGS += -mcpu=ultrasparc
else ifeq ($(COMPAT_CPU),loongarch64)
COMPAT_CFLAGS += -march=loongarch64
else ifneq ($(strip $(COMPAT_CPU)),)
$(error Unsupported COMPAT_CPU '$(COMPAT_CPU)')
endif

ELA_USE_READLINE ?= 1

ifneq (,$(findstring zig cc,$(CC)))
LDFLAGS += -Wl,--no-gc-sections
endif

empty :=
space := $(empty) $(empty)
compat_tag = $(if $(strip $(COMPAT_CPU)),$(COMPAT_CPU),default)
sanitize_tag = $(subst :,_,$(subst /,_,$(subst $(space),_,$(1))))
CC_TAG := $(call sanitize_tag,$(CC))-$(compat_tag)

CMAKE_C_COMPILER ?= $(CC)
CMAKE_C_COMPILER_ARG1 ?=
CMAKE_C_COMPILER_TARGET ?=
# Avoid CMake executable try-compile link checks for cross targets that may fail
# during compiler probing (e.g. Zig + older CPU compatibility profiles).
CMAKE_TRY_COMPILE_TARGET_TYPE ?= STATIC_LIBRARY

OPENSSL_TARGET_TRIPLE ?= $(strip $(CMAKE_C_COMPILER_TARGET))
OPENSSL_CONFIGURE_TARGET ?=
OPENSSL_EXTRA_CONFIGURE_FLAGS ?=

ifeq ($(strip $(OPENSSL_CONFIGURE_TARGET)),)
ifneq ($(strip $(OPENSSL_TARGET_TRIPLE)),)
ifneq (,$(or \
  $(findstring x86_64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring aarch64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring mips64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring powerpc64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring riscv64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring s390x,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring sparc64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring loongarch64,$(OPENSSL_TARGET_TRIPLE)) \
))
OPENSSL_CONFIGURE_TARGET := linux-generic64
else
OPENSSL_CONFIGURE_TARGET := linux-generic32
endif
endif
endif

CMAKE_CC_ARGS := -DCMAKE_C_COMPILER=$(CMAKE_C_COMPILER)
ifneq ($(strip $(CMAKE_C_COMPILER_ARG1)),)
CMAKE_CC_ARGS += -DCMAKE_C_COMPILER_ARG1=$(CMAKE_C_COMPILER_ARG1)
endif
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
CMAKE_CC_ARGS += -DCMAKE_C_COMPILER_TARGET=$(CMAKE_C_COMPILER_TARGET)
 CMAKE_CC_ARGS += -DCMAKE_TRY_COMPILE_TARGET_TYPE=$(CMAKE_TRY_COMPILE_TARGET_TYPE)
endif
ifneq ($(strip $(COMPAT_CFLAGS)),)
CMAKE_CC_ARGS += -DCMAKE_C_FLAGS="$(COMPAT_CFLAGS)"
endif

WOLFSSL_CONFIGURE_HOST_ARG :=
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
WOLFSSL_CONFIGURE_HOST_ARG := --host=$(CMAKE_C_COMPILER_TARGET)
endif

ELA_ENABLE_WOLFSSL ?=
ifeq ($(strip $(ELA_ENABLE_WOLFSSL)),)
ifneq ($(filter $(COMPAT_CPU),powerpc powerpchf powerpc64 powerpc64le),)
ELA_ENABLE_WOLFSSL := 1
else ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
ifneq (,$(or $(findstring powerpc,$(CMAKE_C_COMPILER_TARGET)),$(findstring ppc,$(CMAKE_C_COMPILER_TARGET))))
ELA_ENABLE_WOLFSSL := 1
else
ELA_ENABLE_WOLFSSL := 0
endif
else
ELA_ENABLE_WOLFSSL := 0
endif
endif

WOLFSSL_EXTRA_CONFIGURE_FLAGS :=
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
ifneq (,$(findstring mips64,$(CMAKE_C_COMPILER_TARGET)))
# wolfSSL's MIPS64 SP asm currently emits inline asm clobbers ($lo/$hi) that
# clang-as-zig rejects for these cross builds. Keep SP math enabled but force
# the portable C implementation for MIPS64 targets.
WOLFSSL_EXTRA_CONFIGURE_FLAGS += --disable-sp-asm
endif
endif

CURL_CMAKE_ARGS := $(CMAKE_CC_ARGS)
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
# curl's CMake feature probes are fragile for older cross targets under zig cc.
# Prefill known Unix results so configure does not depend on executable try-compile
# checks that fail for arm32 compatibility targets.
CURL_CMAKE_ARGS += -D_CURL_PREFILL=ON
ifneq (,$(findstring linux,$(CMAKE_C_COMPILER_TARGET)))
# musl uses the POSIX strerror_r signature; curl's probe can become ambiguous
# when cross-compiling these Zig Linux targets and then trips a hard preprocessor error.
CURL_CMAKE_ARGS += -DHAVE_POSIX_STRERROR_R=1 -DHAVE_GLIBC_STRERROR_R=0
endif
endif
ifneq ($(filter $(COMPAT_CPU),arm32 armeb),)
# Older 32-bit ARM compatibility targets do not reliably report these sizes via
# curl's CMake probes when cross-compiling with zig cc. Seed the known values.
CURL_CMAKE_ARGS += -DSIZEOF_SIZE_T=4 -DSIZEOF_SSIZE_T=4 -DSIZEOF_LONG=4 -DSIZEOF_INT=4 -DSIZEOF_TIME_T=4 -DSIZEOF_SUSECONDS_T=4 -DSIZEOF_SA_FAMILY_T=2 -DSIZEOF_OFF_T=8 -DSIZEOF_CURL_OFF_T=8 -DSIZEOF_CURL_SOCKET_T=4
endif

ifneq ($(filter $(COMPAT_CPU),arm32 armeb powerpc powerpchf),)
# Older 32-bit ARM and PowerPC compatibility targets built through zig cc can
# mis-detect working atomics in curl/zlib during cross-compile feature probes.
# That can produce binaries that only fault once libcurl first initializes on
# the target. Force the non-atomic fallback paths for these compat builds.
CURL_CMAKE_ARGS += -DHAVE_ATOMIC=0 -DHAVE_STDATOMIC_H=0
ZLIB_EXTRA_CFLAGS += -D__STDC_NO_ATOMICS__=1
endif

ifneq ($(filter $(COMPAT_CPU),powerpc powerpchf),)
# Make libcurl as small and conservative as possible for 32-bit PowerPC compat
# builds. These targets have been hitting runtime illegal-instruction faults on
# HTTP output paths, so disable optional subsystems and cache/IPC helpers that
# are not required by this project's simple HTTP use case.
CURL_CMAKE_ARGS += -DCURL_DISABLE_ALTSVC=ON -DCURL_DISABLE_COOKIES=ON -DCURL_DISABLE_DICT=ON -DCURL_DISABLE_FILE=ON -DCURL_DISABLE_FTP=ON -DCURL_DISABLE_GOPHER=ON -DCURL_DISABLE_HSTS=ON -DCURL_DISABLE_IMAP=ON -DCURL_DISABLE_IPFS=ON -DCURL_DISABLE_LDAP=ON -DCURL_DISABLE_LDAPS=ON -DCURL_DISABLE_MIME=ON -DCURL_DISABLE_MQTT=ON -DCURL_DISABLE_NETRC=ON -DCURL_DISABLE_NTLM=ON -DCURL_DISABLE_POP3=ON -DCURL_DISABLE_PROXY=ON -DCURL_DISABLE_RTSP=ON -DCURL_DISABLE_SMB=ON -DCURL_DISABLE_SMTP=ON -DCURL_DISABLE_SOCKETPAIR=ON -DCURL_DISABLE_SHUFFLE_DNS=ON -DCURL_DISABLE_TELNET=ON -DCURL_DISABLE_TFTP=ON -DCURL_DISABLE_WEBSOCKETS=ON -DPICKY_COMPILER=OFF -DENABLE_UNIX_SOCKETS=OFF

# Also make libcrypto/libssl as conservative as possible. These flags keep the
# build focused on the minimal static TLS functionality curl needs while
# avoiding extra provider/config/error/DSO code paths that may still exercise
# problematic CPU-detection or runtime-init behavior on older PowerPC systems.
OPENSSL_EXTRA_CONFIGURE_FLAGS += no-autoerrinit no-autoload-config no-atexit no-cmp no-comp no-dgram no-dso no-engine no-legacy no-ocsp no-psk no-srp no-srtp no-ssl3 no-stdio no-tls1 no-tls1_1 no-ui-console no-weak-ssl-ciphers
endif

JSONC_CMAKE_ARGS := $(CMAKE_CC_ARGS)
ifneq ($(strip $(COMPAT_CFLAGS)),)
JSONC_CMAKE_ARGS += -DCMAKE_C_FLAGS="$(COMPAT_CFLAGS)"
endif
ifneq ($(filter $(COMPAT_CPU),arm32 armeb powerpc powerpchf),)
# Be explicit that json-c should not enable its optional threaded refcount path
# for older 32-bit ARM/PowerPC compatibility builds. Its feature probes can
# otherwise conclude that __sync atomics are available even when the generated
# instructions are not safe on the oldest CPUs we target.
JSONC_CMAKE_ARGS += -DENABLE_THREADING=OFF
endif

LIBCSV_DIR    := third_party/libcsv
LIBCSV_SRC    := $(LIBCSV_DIR)/libcsv.c
LIBCSV_CFLAGS := -I$(LIBCSV_DIR)
LIBUBOOTENV_DIR := third_party/libubootenv
LIBUBOOTENV_BUILD := $(LIBUBOOTENV_DIR)/build-$(CC_TAG)
LIBUBOOTENV_LIB := $(LIBUBOOTENV_BUILD)/src/libubootenv.a
LIBUBOOTENV_CFLAGS := -I$(LIBUBOOTENV_DIR)/src
LIBEFIVAR_DIR := third_party/libefivar
LIBEFIVAR_BUILD_STAMP := $(LIBEFIVAR_DIR)/.ela-build-$(CC_TAG)
LIBEFIVAR_LIB := $(LIBEFIVAR_DIR)/src/libefivar.a
LIBEFIVAR_CFLAGS := -I$(LIBEFIVAR_DIR)/src/include
ZLIB_DIR      := third_party/zlib
ZLIB_BUILD    := $(ZLIB_DIR)/build-$(CC_TAG)
ZLIB_LIB      := $(ZLIB_BUILD)/libz.a
ZLIB_CFLAGS   := -I$(ZLIB_DIR) -I$(ZLIB_BUILD)
ZLIB_EXTRA_CFLAGS := $(COMPAT_CFLAGS)
LIBUBOOTENV_EXTRA_CFLAGS := -I$(abspath compat) -I$(abspath $(ZLIB_DIR)) -I$(abspath $(ZLIB_BUILD)) -Wno-switch $(COMPAT_CFLAGS)
JSONC_DIR     := third_party/json-c
JSONC_BUILD   := $(JSONC_DIR)/build-$(CC_TAG)
JSONC_LIB     := $(JSONC_BUILD)/libjson-c.a
JSONC_CFLAGS  := -Ithird_party -I$(JSONC_DIR) -I$(JSONC_BUILD)
CURL_DIR      := third_party/curl
CURL_BUILD    := $(CURL_DIR)/build-$(CC_TAG)
CURL_LIB      := $(CURL_BUILD)/lib/libcurl.a
CURL_CFLAGS   := -I$(CURL_DIR)/include
WOLFSSL_DIR   := third_party/wolfssl
WOLFSSL_BUILD := $(WOLFSSL_DIR)/build-$(CC_TAG)
WOLFSSL_LIB   := $(WOLFSSL_BUILD)/src/.libs/libwolfssl.a
WOLFSSL_CFLAGS := -I$(WOLFSSL_DIR) -I$(WOLFSSL_BUILD)
OPENSSL_DIR   := third_party/openssl
OPENSSL_BUILD := $(OPENSSL_DIR)/build-$(CC_TAG)
OPENSSL_INSTALL := $(OPENSSL_BUILD)/install
OPENSSL_CMAKE_DIR := $(OPENSSL_INSTALL)/lib/cmake/OpenSSL
OPENSSL_SSL_LIB := $(OPENSSL_INSTALL)/lib/libssl.a
OPENSSL_LIB   := $(OPENSSL_INSTALL)/lib/libcrypto.a
OPENSSL_CFLAGS := -I$(OPENSSL_INSTALL)/include
NCURSES_DIR   := third_party/ncurses
NCURSES_BUILD_STAMP := $(NCURSES_DIR)/.ela-build-$(CC_TAG)
NCURSES_LIB_DIR := $(NCURSES_DIR)/lib
NCURSES_LIB   := $(NCURSES_LIB_DIR)/libncurses.a
NCURSES_TINFO_LIB := $(NCURSES_LIB_DIR)/libtinfo.a
READLINE_DIR  := third_party/readline
READLINE_BUILD_STAMP := $(READLINE_DIR)/.ela-build-$(CC_TAG)
READLINE_LIB  := $(READLINE_DIR)/libreadline.a
READLINE_HISTORY_LIB := $(READLINE_DIR)/libhistory.a
READLINE_BUILD_CFLAGS ?= -O2 -Wno-incompatible-pointer-types
LIBEFIVAR_HOST_CFLAGS ?= -O2 -std=gnu11 -funsigned-char -fvisibility=hidden
LIBEFIVAR_HOST_CPPFLAGS ?= -I$(abspath $(LIBEFIVAR_DIR))/src/include -DEFIVAR_BUILD_ENVIRONMENT
LIBEFIVAR_HOST_LDFLAGS ?= $(LIBEFIVAR_HOST_CFLAGS)
GENERATED_DIR := generated
DEFAULT_CA_BUNDLE_PEM := $(GENERATED_DIR)/cacert.pem
CA_BUNDLE_URL ?= https://curl.se/ca/cacert.pem
CA_BUNDLE_PEM ?= $(DEFAULT_CA_BUNDLE_PEM)
GENERATED_CA_SRC := $(GENERATED_DIR)/fw_default_ca_bundle.c

ZLIB_CMAKE_ARGS := $(CMAKE_CC_ARGS)
ifneq ($(strip $(ZLIB_EXTRA_CFLAGS)),)
ZLIB_CMAKE_ARGS += -DCMAKE_C_FLAGS="$(ZLIB_EXTRA_CFLAGS)"
endif

CFLAGS += $(LIBCSV_CFLAGS)
CFLAGS += $(LIBUBOOTENV_CFLAGS)
CFLAGS += $(LIBEFIVAR_CFLAGS)
CFLAGS += $(ZLIB_CFLAGS)
CFLAGS += $(JSONC_CFLAGS)
CFLAGS += $(CURL_CFLAGS)
ifeq ($(ELA_ENABLE_WOLFSSL),1)
CFLAGS += $(WOLFSSL_CFLAGS)
CFLAGS += -DELA_HAS_WOLFSSL=1
endif
CFLAGS += $(OPENSSL_CFLAGS)
CFLAGS += $(COMPAT_CFLAGS)
CFLAGS += -I.
CFLAGS += -Iagent

ifeq ($(ELA_USE_READLINE),1)
CFLAGS += -DELA_HAS_READLINE -I$(READLINE_DIR)
LDLIBS += $(READLINE_LIB) $(READLINE_HISTORY_LIB) $(NCURSES_LIB) $(NCURSES_TINFO_LIB)
READLINE_DEPS := $(NCURSES_BUILD_STAMP) $(READLINE_BUILD_STAMP)
else
READLINE_DEPS :=
endif

TARGET := embedded_linux_audit
SRC    := agent/embedded_linux_audit.c agent/uboot/env/uboot_env_cmd.c agent/uboot/env/uboot_env_read_vars_cmd.c agent/uboot/env/uboot_env_write_vars_cmd.c agent/uboot/uboot_image_cmd.c agent/uboot/image/uboot_image_pull_cmd.c agent/uboot/image/uboot_image_find_address_cmd.c agent/uboot/image/uboot_image_list_commands_cmd.c agent/uboot/uboot_security_audit_cmd.c agent/linux/linux_dmesg_cmd.c agent/linux/linux_download_file_cmd.c agent/linux/linux_execute_command_cmd.c agent/linux/linux_grep_cmd.c agent/linux/linux_list_files_cmd.c agent/linux/linux_list_symlinks_cmd.c agent/linux/linux_remote_copy_cmd.c agent/orom/orom_pull_cmd_common.c agent/efi/efi_pull_orom_cmd.c agent/efi/efi_dump_vars_cmd.c agent/bios/bios_pull_orom_cmd.c agent/embedded_linux_audit_cmd.c \
	  agent/uboot/audit-rules/uboot_validate_crc32_rule.c \
	  agent/uboot/audit-rules/uboot_validate_cmdline_init_writeability_rule.c \
	  agent/uboot/audit-rules/uboot_validate_env_security_rule.c \
	  agent/uboot/audit-rules/uboot_validate_env_writeability_rule.c \
	  agent/uboot/audit-rules/uboot_validate_secureboot_rule.c \
	  $(LIBCSV_SRC) $(GENERATED_CA_SRC)

ifneq ($(filter $(COMPAT_CPU),arm32 armeb powerpc powerpchf),)
SRC += compat/legacy_sync_builtins.c
endif

.PHONY: all env image static test clean

all: $(TARGET)

env: $(TARGET)

image: $(TARGET)

$(JSONC_LIB):
	cmake -S $(JSONC_DIR) -B $(JSONC_BUILD) $(JSONC_CMAKE_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF -DBUILD_APPS=OFF
	cmake --build $(JSONC_BUILD) --parallel $(JOBS) --target json-c

$(LIBUBOOTENV_LIB): $(ZLIB_LIB)
	cmake -S $(LIBUBOOTENV_DIR) -B $(LIBUBOOTENV_BUILD) $(CMAKE_CC_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_DOC=OFF -DNO_YML_SUPPORT=ON -DCMAKE_C_FLAGS="$(LIBUBOOTENV_EXTRA_CFLAGS)"
	cmake --build $(LIBUBOOTENV_BUILD) --parallel $(JOBS) --target ubootenv_static

$(LIBEFIVAR_BUILD_STAMP):
	-$(MAKE) -C $(LIBEFIVAR_DIR)/src TOPDIR='$(abspath $(LIBEFIVAR_DIR))' clean >/dev/null 2>&1 || true
	$(MAKE) -C $(LIBEFIVAR_DIR)/src TOPDIR='$(abspath $(LIBEFIVAR_DIR))' libefivar.a CC='$(CC)' HOSTCC='cc' HOSTCCLD='cc' AR='ar' RANLIB='ranlib' CFLAGS='$(COMPAT_CFLAGS)' CPPFLAGS='-I$(abspath $(LIBEFIVAR_DIR))/src/include' HOST_CFLAGS='$(LIBEFIVAR_HOST_CFLAGS)' HOST_CPPFLAGS='$(LIBEFIVAR_HOST_CPPFLAGS)' HOST_LDFLAGS='$(LIBEFIVAR_HOST_LDFLAGS)' HOST_CCLDFLAGS='$(LIBEFIVAR_HOST_LDFLAGS)'
	test -f $(LIBEFIVAR_LIB)
	touch $@

$(ZLIB_LIB):
	cmake -S $(ZLIB_DIR) -B $(ZLIB_BUILD) $(ZLIB_CMAKE_ARGS) -DCMAKE_BUILD_TYPE=Release -DZLIB_BUILD_SHARED=OFF -DZLIB_BUILD_STATIC=ON -DZLIB_BUILD_TESTING=OFF -DZLIB_INSTALL=OFF
	cmake --build $(ZLIB_BUILD) --parallel $(JOBS) --target zlibstatic

$(CURL_LIB): $(OPENSSL_SSL_LIB)
	cmake -S $(CURL_DIR) -B $(CURL_BUILD) $(CURL_CMAKE_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DBUILD_TESTING=OFF -DCURL_USE_OPENSSL=ON -DOPENSSL_ROOT_DIR="$(abspath $(OPENSSL_INSTALL))" -DOPENSSL_INCLUDE_DIR="$(abspath $(OPENSSL_INSTALL))/include" -DOPENSSL_SSL_LIBRARY="$(abspath $(OPENSSL_SSL_LIB))" -DOPENSSL_CRYPTO_LIBRARY="$(abspath $(OPENSSL_LIB))" -DCURL_ZLIB=OFF -DUSE_LIBIDN2=OFF -DUSE_NGHTTP2=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DENABLE_ARES=OFF -DENABLE_THREADED_RESOLVER=OFF -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DUSE_ECH=OFF -DUSE_NTLM=OFF -DUSE_OPENLDAP=OFF -DUSE_LIBRTMP=OFF -DUSE_WEBSOCKETS=OFF -DCURL_DISABLE_NETRC=ON -DHTTP_ONLY=ON
	cmake --build $(CURL_BUILD) --parallel $(JOBS) --target libcurl_static

$(OPENSSL_LIB): $(OPENSSL_SSL_LIB)

$(WOLFSSL_LIB):
	mkdir -p $(WOLFSSL_BUILD)
	cd $(WOLFSSL_DIR) && ./autogen.sh
	cd $(WOLFSSL_BUILD) && $(abspath $(WOLFSSL_DIR))/configure \
		CC="$(CC)" CFLAGS="$(COMPAT_CFLAGS)" \
		$(WOLFSSL_CONFIGURE_HOST_ARG) \
		$(WOLFSSL_EXTRA_CONFIGURE_FLAGS) \
		--enable-static --disable-shared --disable-benchmark --disable-examples \
		--disable-crypttests --disable-dtls --disable-oldtls --disable-tls13 \
		--disable-tls13 --enable-sni --prefix="$(abspath $(WOLFSSL_BUILD))/install"
	$(MAKE) -C $(WOLFSSL_BUILD) -j$(JOBS)

$(OPENSSL_SSL_LIB):
	mkdir -p $(OPENSSL_BUILD)
	cd $(OPENSSL_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	# Use no-asm so cross builds (e.g. zig cc -target arm-*) don't pick host x86 asm paths.
	cd $(OPENSSL_DIR) && CC="$(CC)" CFLAGS="$(COMPAT_CFLAGS)" ./Configure $(OPENSSL_CONFIGURE_TARGET) no-asm no-shared no-module no-threads no-tests no-docs $(OPENSSL_EXTRA_CONFIGURE_FLAGS) --prefix="$(abspath $(OPENSSL_INSTALL))" --openssldir="$(abspath $(OPENSSL_INSTALL))/ssl" --libdir=lib
	$(MAKE) -C $(OPENSSL_DIR) -j$(JOBS) build_generated
	$(MAKE) -C $(OPENSSL_DIR) -j$(JOBS) build_libs
	mkdir -p "$(OPENSSL_INSTALL)/include" "$(OPENSSL_INSTALL)/lib" "$(OPENSSL_CMAKE_DIR)"
	rm -rf "$(OPENSSL_INSTALL)/include/openssl"
	cp -a "$(OPENSSL_DIR)/include/openssl" "$(OPENSSL_INSTALL)/include/"
	cp "$(OPENSSL_DIR)/libssl.a" "$(OPENSSL_SSL_LIB)"
	cp "$(OPENSSL_DIR)/libcrypto.a" "$(OPENSSL_LIB)"
	cp "$(OPENSSL_DIR)/exporters/OpenSSLConfig.cmake" "$(OPENSSL_CMAKE_DIR)/OpenSSLConfig.cmake"
	cp "$(OPENSSL_DIR)/exporters/OpenSSLConfigVersion.cmake" "$(OPENSSL_CMAKE_DIR)/OpenSSLConfigVersion.cmake"

$(GENERATED_DIR):
	mkdir -p $(GENERATED_DIR)

ifeq ($(CA_BUNDLE_PEM),$(DEFAULT_CA_BUNDLE_PEM))
$(DEFAULT_CA_BUNDLE_PEM): | $(GENERATED_DIR)
	curl -fsSL "$(CA_BUNDLE_URL)" -o "$@"
endif

$(GENERATED_CA_SRC): tools/embed_ca_bundle.py $(CA_BUNDLE_PEM)
	python3 tools/embed_ca_bundle.py --input "$(CA_BUNDLE_PEM)" --output "$@"

$(NCURSES_BUILD_STAMP):
	cd $(NCURSES_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	cd $(NCURSES_DIR) && ./configure --without-shared --without-cxx --without-cxx-binding --without-ada --without-tests --without-progs --without-manpages --with-normal --with-termlib CC='$(CC)' CFLAGS='$(CFLAGS)'
	$(MAKE) -C $(NCURSES_DIR) -j$(JOBS) libs
	touch $@

$(READLINE_BUILD_STAMP):
	cd $(READLINE_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	cd $(READLINE_DIR) && bash_cv_termcap_lib=libtermcap ac_cv_type_signal=void bash_cv_void_sighandler=yes ./configure --disable-shared --enable-static CC='$(CC) -std=gnu89' CFLAGS='$(READLINE_BUILD_CFLAGS)' LDFLAGS='-L$(abspath $(NCURSES_LIB_DIR))'
	$(MAKE) -C $(READLINE_DIR) -j$(JOBS) libreadline.a libhistory.a
	touch $@

TARGET_DEPS := $(SRC) $(ZLIB_LIB) $(LIBUBOOTENV_LIB) $(LIBEFIVAR_BUILD_STAMP) $(JSONC_LIB) $(CURL_LIB) $(OPENSSL_SSL_LIB) $(OPENSSL_LIB) $(READLINE_DEPS)
TARGET_LIBS := $(LIBUBOOTENV_LIB) $(LIBEFIVAR_LIB) $(ZLIB_LIB) $(JSONC_LIB) $(CURL_LIB) $(OPENSSL_SSL_LIB) $(OPENSSL_LIB)
ifeq ($(ELA_ENABLE_WOLFSSL),1)
TARGET_DEPS += $(WOLFSSL_LIB)
TARGET_LIBS += $(WOLFSSL_LIB)
endif

$(TARGET): $(TARGET_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(TARGET_LIBS) $(LDFLAGS) $(LDLIBS)

static: LDFLAGS += -static
static: all

test:
	bash tests/agent/test_all.sh

clean:
	rm -f $(TARGET)
	rm -rf $(GENERATED_DIR)
	rm -rf $(JSONC_DIR)/build*
	rm -rf $(LIBUBOOTENV_DIR)/build*
	-$(MAKE) -C $(LIBEFIVAR_DIR)/src TOPDIR='$(abspath $(LIBEFIVAR_DIR))' clean >/dev/null 2>&1 || true
	rm -f $(LIBEFIVAR_BUILD_STAMP)
	rm -rf $(ZLIB_DIR)/build*
	rm -rf $(CURL_DIR)/build*
	rm -rf $(WOLFSSL_DIR)/build*
	-cd $(OPENSSL_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	rm -rf $(OPENSSL_BUILD)
	-cd $(NCURSES_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	rm -f $(NCURSES_BUILD_STAMP)
	-cd $(READLINE_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	rm -f $(READLINE_BUILD_STAMP)
	-git submodule foreach --recursive 'git clean -xfd >/dev/null 2>&1 || true'
	-git submodule foreach --recursive 'git reset --hard >/dev/null 2>&1 || true'