CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?=
LDLIBS  ?=

ifneq (,$(findstring zig cc,$(CC)))
LDFLAGS += -Wl,--no-gc-sections
endif

empty :=
space := $(empty) $(empty)
CC_TAG := $(subst $(space),_,$(CC))

CMAKE_C_COMPILER ?= $(CC)
CMAKE_C_COMPILER_ARG1 ?=
CMAKE_C_COMPILER_TARGET ?=

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
LIBUBOOTENV_EXTRA_CFLAGS := -I$(abspath compat) -I$(abspath $(ZLIB_DIR)) -I$(abspath $(ZLIB_BUILD)) -Wno-switch
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
CFLAGS += -I.
CFLAGS += -Iagent

TARGET := uboot_audit
SRC    := agent/embedded_linux_audit.c agent/uboot/env/uboot_env_cmd.c agent/uboot/env/uboot_env_read_vars_cmd.c agent/uboot/env/uboot_env_write_vars_cmd.c agent/uboot/uboot_image_cmd.c agent/uboot/uboot_audit_cmd.c agent/linux/linux_dmesg_cmd.c agent/linux/linux_remote_copy_cmd.c agent/embedded_linux_audit_cmd.c \
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
	cd $(OPENSSL_DIR) && CC="$(CC)" ./Configure $(OPENSSL_CONFIGURE_TARGET) no-asm no-shared no-module no-threads no-tests no-docs --prefix="$(abspath $(OPENSSL_INSTALL))" --openssldir="$(abspath $(OPENSSL_INSTALL))/ssl" --libdir=lib
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

$(TARGET): $(SRC) $(ZLIB_LIB) $(LIBUBOOTENV_LIB) $(JSONC_LIB) $(CURL_LIB) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LIBUBOOTENV_LIB) $(ZLIB_LIB) $(JSONC_LIB) $(CURL_LIB) $(OPENSSL_LIB) $(LDFLAGS) $(LDLIBS)

static: LDFLAGS += -static
static: all

test:
	bash tests/test_all.sh

clean:
	rm -f $(TARGET)
	rm -rf $(GENERATED_DIR)
	rm -rf $(JSONC_DIR)/build*
	rm -rf $(LIBUBOOTENV_DIR)/build*
	rm -rf $(ZLIB_DIR)/build*
	rm -rf $(CURL_DIR)/build*
	-cd $(OPENSSL_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	rm -rf $(OPENSSL_BUILD)