CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?=

COMMON_SRC := fw_scan.c

ENV_TARGET := fw_env_scan
ENV_SRC    := fw_env_scan.c $(COMMON_SRC)

IMAGE_TARGET := fw_image_scan
IMAGE_SRC    := fw_image_scan.c $(COMMON_SRC)

.PHONY: all env image static clean

all: env image

env: $(ENV_TARGET)

image: $(IMAGE_TARGET)

$(ENV_TARGET): $(ENV_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(ENV_SRC)

$(IMAGE_TARGET): $(IMAGE_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(IMAGE_SRC)

static: LDFLAGS += -static
static: all

clean:
	rm -f $(ENV_TARGET) $(IMAGE_TARGET)