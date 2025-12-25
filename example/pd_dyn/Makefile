#
# Copyright 2025, UNSW
#
# SPDX-License-Identifier: BSD-2-Clause
#
ifeq ($(strip $(BUILD_DIR)),)
$(error BUILD_DIR must be specified)
endif

ifeq ($(strip $(MICROKIT_SDK)),)
$(error MICROKIT_SDK must be specified)
endif

ifeq ($(strip $(MICROKIT_BOARD)),)
$(error MICROKIT_BOARD must be specified)
endif

ifeq ($(strip $(MICROKIT_CONFIG)),)
$(error MICROKIT_CONFIG must be specified)
endif

BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

ARCH := ${shell grep 'CONFIG_SEL4_ARCH  ' $(BOARD_DIR)/include/kernel/gen_config.h | cut -d' ' -f4}

ifeq ($(ARCH),x86_64)
	TOOLCHAIN := x86_64-linux-gnu
	CFLAGS_ARCH := -march=x86-64 -mtune=generic
else
$(error Unsupported ARCH)
endif

CC := $(TOOLCHAIN)-gcc
LD := $(TOOLCHAIN)-ld
AS := $(TOOLCHAIN)-as
AR := $(TOOLCHAIN)-ar
OBJCOPY := $(TOOLCHAIN)-objcopy
MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit

LIBTSLDR_SRC_DIR := $(CURDIR)/trustedloader
LIBEXTELF_SRC_DIR := $(CURDIR)/extelf

include $(LIBTSLDR_SRC_DIR)/Makefile
include $(LIBEXTELF_SRC_DIR)/Makefile

IMAGES := template.elf protocon.elf
CFLAGS := -nostdlib -ffreestanding -g3 -O3 \
			-I$(BOARD_DIR)/include $(CFLAGS_ARCH) \
			-I$(LIBEXTELF_SRC_DIR)/include \
			-I$(LIBTSLDR_SRC_DIR)/include

LDFLAGS := -L$(BOARD_DIR)/lib -z noexecstack -L$(LIBEXTELF_BUILD_DIR) -L$(LIBTSLDR_BUILD_DIR)
LIBS := -lmicrokit -Tmicrokit.ld

INITIAL_TASK = $(BUILD_DIR)/initialiser.elf
KERNEL = $(BUILD_DIR)/sel4.elf
KERNEL_32B = $(BUILD_DIR)/sel4_32.elf
REPORT = $(BUILD_DIR)/report.txt
SPEC = $(BUILD_DIR)/capdl_spec.json

PACKAGE_OBJS := $(BUILD_DIR)/package.o

all: $(KERNEL) $(INITIAL_TASK)
qemu: $(KERNEL_32B) $(INITIAL_TASK)

$(BUILD_DIR)/template.o: template.c Makefile
	$(CC) -c $(CFLAGS) -Wall -Wno-unused-function -Werror $< -o $@

$(BUILD_DIR)/template.elf: $(BUILD_DIR)/template.o $(PACKAGE_OBJS) ${LIBEXTELF}
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/protocon.o: protocon.c Makefile
	$(CC) -c $(CFLAGS) -Wall -Wno-unused-function -Werror $< -o $@

$(BUILD_DIR)/protocon.elf: $(BUILD_DIR)/protocon.o $(LIBTSLDR) ${LIBEXTELF}
	$(LD) $(LDFLAGS) --defsym __sel4_ipc_buffer=0x100000 $^ $(LIBS) -o $@

$(PACKAGE_OBJS): package.S $(BUILD_DIR)/protocon.elf
	$(CC) -c -g3 -x assembler-with-cpp \
		-DLOADER_PATH=\"$(BUILD_DIR)/protocon.elf\" \
		package.S -o $@

$(KERNEL) $(KERNEL_32B) $(INITIAL_TASK): $(addprefix $(BUILD_DIR)/, $(IMAGES)) pd_dyn.system
	$(MICROKIT_TOOL) pd_dyn.system --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) -o $(INITIAL_TASK) -r $(REPORT) --capdl-json $(SPEC)

qemu:
	qemu-system-x86_64                      \
			-cpu qemu64,+fsgsbase,+pdpe1gb,+xsaveopt,+xsave \
			-m "1G"                         \
			-display none                   \
			-serial mon:stdio               \
		-kernel $(KERNEL_32B) \
		-initrd $(INITIAL_TASK)
