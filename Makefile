CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?=
LDLIBS  ?=

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
CC_TAG := $(subst $(space),_,$(CC))-$(compat_tag)

CMAKE_C_COMPILER ?= $(CC)
CMAKE_C_COMPILER_ARG1 ?=
CMAKE_C_COMPILER_TARGET ?=
# Avoid CMake executable try-compile link checks for cross targets that may fail
# during compiler probing (e.g. Zig + older CPU compatibility profiles).
CMAKE_TRY_COMPILE_TARGET_TYPE ?= STATIC_LIBRARY

OPENSSL_TARGET_TRIPLE ?= $(strip $(CMAKE_C_COMPILER_TARGET))
OPENSSL_CONFIGURE_TARGET ?=

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

LIBCSV_DIR    := third_party/libcsv
LIBCSV_SRC    := $(LIBCSV_DIR)/libcsv.c
LIBCSV_CFLAGS := -I$(LIBCSV_DIR)
LIBUBOOTENV_DIR := third_party/libubootenv
LIBUBOOTENV_BUILD := $(LIBUBOOTENV_DIR)/build-$(CC_TAG)
LIBUBOOTENV_LIB := $(LIBUBOOTENV_BUILD)/src/libubootenv.a
LIBUBOOTENV_CFLAGS := -I$(LIBUBOOTENV_DIR)/src
ZLIB_DIR      := third_party/zlib
ZLIB_BUILD    := $(ZLIB_DIR)/build-$(CC_TAG)
ZLIB_LIB      := $(ZLIB_BUILD)/libz.a
ZLIB_CFLAGS   := -I$(ZLIB_DIR) -I$(ZLIB_BUILD)
LIBUBOOTENV_EXTRA_CFLAGS := -I$(abspath compat) -I$(abspath $(ZLIB_DIR)) -I$(abspath $(ZLIB_BUILD)) -Wno-switch $(COMPAT_CFLAGS)
JSONC_DIR     := third_party/json-c
JSONC_BUILD   := $(JSONC_DIR)/build-$(CC_TAG)
JSONC_LIB     := $(JSONC_BUILD)/libjson-c.a
JSONC_CFLAGS  := -Ithird_party -I$(JSONC_DIR) -I$(JSONC_BUILD)
CURL_DIR      := third_party/curl
CURL_BUILD    := $(CURL_DIR)/build-$(CC_TAG)
CURL_LIB      := $(CURL_BUILD)/lib/libcurl.a
CURL_CFLAGS   := -I$(CURL_DIR)/include
OPENSSL_DIR   := third_party/openssl
OPENSSL_BUILD := $(OPENSSL_DIR)/build-$(CC_TAG)
OPENSSL_INSTALL := $(OPENSSL_BUILD)/install
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
GENERATED_DIR := generated
DEFAULT_CA_BUNDLE_PEM := $(GENERATED_DIR)/cacert.pem
CA_BUNDLE_URL ?= https://curl.se/ca/cacert.pem
CA_BUNDLE_PEM ?= $(DEFAULT_CA_BUNDLE_PEM)
GENERATED_CA_SRC := $(GENERATED_DIR)/fw_default_ca_bundle.c

CFLAGS += $(LIBCSV_CFLAGS)
CFLAGS += $(LIBUBOOTENV_CFLAGS)
CFLAGS += $(ZLIB_CFLAGS)
CFLAGS += $(JSONC_CFLAGS)
CFLAGS += $(CURL_CFLAGS)
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
SRC    := agent/embedded_linux_audit.c agent/uboot/env/uboot_env_cmd.c agent/uboot/env/uboot_env_read_vars_cmd.c agent/uboot/env/uboot_env_write_vars_cmd.c agent/uboot/uboot_image_cmd.c agent/uboot/image/uboot_image_pull_cmd.c agent/uboot/image/uboot_image_find_address_cmd.c agent/uboot/image/uboot_image_list_commands_cmd.c agent/uboot/uboot_security_audit_cmd.c agent/linux/linux_dmesg_cmd.c agent/linux/linux_execute_command_cmd.c agent/linux/linux_grep_cmd.c agent/linux/linux_list_files_cmd.c agent/linux/linux_list_symlinks_cmd.c agent/linux/linux_remote_copy_cmd.c agent/orom/orom_pull_cmd_common.c agent/efi/efi_pull_orom_cmd.c agent/bios/bios_pull_orom_cmd.c agent/embedded_linux_audit_cmd.c \
	  agent/uboot/audit-rules/uboot_validate_crc32_rule.c \
	  agent/uboot/audit-rules/uboot_validate_cmdline_init_writeability_rule.c \
	  agent/uboot/audit-rules/uboot_validate_env_security_rule.c \
	  agent/uboot/audit-rules/uboot_validate_env_writeability_rule.c \
	  agent/uboot/audit-rules/uboot_validate_secureboot_rule.c \
	  $(LIBCSV_SRC) $(GENERATED_CA_SRC)

.PHONY: all env image static test clean

all: $(TARGET)

env: $(TARGET)

image: $(TARGET)

$(JSONC_LIB):
	cmake -S $(JSONC_DIR) -B $(JSONC_BUILD) $(CMAKE_CC_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF -DBUILD_APPS=OFF
	cmake --build $(JSONC_BUILD) --target json-c

$(LIBUBOOTENV_LIB): $(ZLIB_LIB)
	cmake -S $(LIBUBOOTENV_DIR) -B $(LIBUBOOTENV_BUILD) $(CMAKE_CC_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_DOC=OFF -DNO_YML_SUPPORT=ON -DCMAKE_C_FLAGS="$(LIBUBOOTENV_EXTRA_CFLAGS)"
	cmake --build $(LIBUBOOTENV_BUILD) --target ubootenv_static

$(ZLIB_LIB):
	cmake -S $(ZLIB_DIR) -B $(ZLIB_BUILD) $(CMAKE_CC_ARGS) -DCMAKE_BUILD_TYPE=Release -DZLIB_BUILD_SHARED=OFF -DZLIB_BUILD_STATIC=ON -DZLIB_BUILD_TESTING=OFF -DZLIB_INSTALL=OFF
	cmake --build $(ZLIB_BUILD) --target zlibstatic

$(CURL_LIB):
	cmake -S $(CURL_DIR) -B $(CURL_BUILD) $(CMAKE_CC_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DBUILD_TESTING=OFF -DCURL_USE_OPENSSL=OFF -DCURL_ZLIB=OFF -DUSE_LIBIDN2=OFF -DUSE_NGHTTP2=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DENABLE_ARES=OFF -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DCURL_DISABLE_NETRC=ON -DHTTP_ONLY=ON
	cmake --build $(CURL_BUILD) --target libcurl_static

$(OPENSSL_LIB):
	mkdir -p $(OPENSSL_BUILD)
	cd $(OPENSSL_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	# Use no-asm so cross builds (e.g. zig cc -target arm-*) don't pick host x86 asm paths.
	cd $(OPENSSL_DIR) && CC="$(CC)" CFLAGS="$(COMPAT_CFLAGS)" ./Configure $(OPENSSL_CONFIGURE_TARGET) no-asm no-shared no-module no-threads no-tests no-docs --prefix="$(abspath $(OPENSSL_INSTALL))" --openssldir="$(abspath $(OPENSSL_INSTALL))/ssl" --libdir=lib
	$(MAKE) -C $(OPENSSL_DIR) build_libs
	mkdir -p "$(OPENSSL_INSTALL)/include" "$(OPENSSL_INSTALL)/lib"
	rm -rf "$(OPENSSL_INSTALL)/include/openssl"
	cp -a "$(OPENSSL_DIR)/include/openssl" "$(OPENSSL_INSTALL)/include/"
	cp "$(OPENSSL_DIR)/libcrypto.a" "$(OPENSSL_LIB)"

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
	$(MAKE) -C $(NCURSES_DIR) -j2 libs
	touch $@

$(READLINE_BUILD_STAMP):
	cd $(READLINE_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	cd $(READLINE_DIR) && bash_cv_termcap_lib=libtermcap ac_cv_type_signal=void bash_cv_void_sighandler=yes ./configure --disable-shared --enable-static CC='$(CC) -std=gnu89' CFLAGS='$(READLINE_BUILD_CFLAGS)' LDFLAGS='-L$(abspath $(NCURSES_LIB_DIR))'
	$(MAKE) -C $(READLINE_DIR) libreadline.a libhistory.a
	touch $@

$(TARGET): $(SRC) $(ZLIB_LIB) $(LIBUBOOTENV_LIB) $(JSONC_LIB) $(CURL_LIB) $(OPENSSL_LIB) $(READLINE_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LIBUBOOTENV_LIB) $(ZLIB_LIB) $(JSONC_LIB) $(CURL_LIB) $(OPENSSL_LIB) $(LDFLAGS) $(LDLIBS)

static: LDFLAGS += -static
static: all

test:
	bash tests/agent/test_all.sh

clean:
	rm -f $(TARGET)
	rm -rf $(GENERATED_DIR)
	rm -rf $(JSONC_DIR)/build*
	rm -rf $(LIBUBOOTENV_DIR)/build*
	rm -rf $(ZLIB_DIR)/build*
	rm -rf $(CURL_DIR)/build*
	-cd $(OPENSSL_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	rm -rf $(OPENSSL_BUILD)
	-cd $(NCURSES_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	rm -f $(NCURSES_BUILD_STAMP)
	-cd $(READLINE_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	rm -f $(READLINE_BUILD_STAMP)
	-git submodule foreach --recursive 'git clean -xfd >/dev/null 2>&1 || true'
	-git submodule foreach --recursive 'git reset --hard >/dev/null 2>&1 || true'