#
# Copyright 2024, UNSW
#
# SPDX-License-Identifier: BSD-2-Clause
#

MICROKIT_BOARD ?= qemu_virt_aarch64
MICROKIT_CONFIG ?= debug
BUILD_DIR ?= build

MICROKIT_SRC_DIR ?= $(CURDIR)/../../..
MICROKIT_SDK ?= $(MICROKIT_SRC_DIR)/release/microkit-sdk-1.4.1
SYSTEM_HASH	?= 0x12fe22638f1bcbbe

# Toolchain and compiler settings
TOOLCHAIN := aarch64-none-elf
CPU := cortex-a53

CC := $(TOOLCHAIN)-gcc
LD := $(TOOLCHAIN)-ld
AS := $(TOOLCHAIN)-as

MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit
PYTHON ?= $(MICROKIT_SRC_DIR)/pyenv/bin/python

LIBCRYPTO_SRC_DIR := $(CURDIR)/crypto
LIBEXTELF_SRC_DIR := $(CURDIR)/extelf
LIBTSLDR_SRC_DIR := $(CURDIR)/trustedloader
include $(LIBCRYPTO_SRC_DIR)/Makefile
include $(LIBEXTELF_SRC_DIR)/Makefile
include $(LIBTSLDR_SRC_DIR)/Makefile

# Object files
TRUSTED_LOADER_OBJS := trusted_loader.o
PROTO_CONTAINER_OBJS := proto-container.o
RECEIVER2_OBJS := receiver2.o
CLIENT_OBJS	:= client.o
SENDER_LOADER_OBJS := sender_loader.o
FRONTEND_OBJS := frontend.o

PACKAGE_PROGS_OBJS := $(BUILD_DIR)/programs.o

# Board directory
BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

# Patched ELF file names
PATCHED_PROTO_CONTAINER_ELF := $(BUILD_DIR)/proto-container_patched.elf
PATCHED_RECEIVER2_ELF := $(BUILD_DIR)/receiver2_patched.elf
PATCHED_CLIENT_ELF := $(BUILD_DIR)/client_patched.elf

CLIENT_ELF := $(BUILD_DIR)/client.elf

# Images to include patched ELF files
IMAGES := $(BUILD_DIR)/trusted_loader.elf \
			$(PATCHED_PROTO_CONTAINER_ELF) $(PATCHED_RECEIVER2_ELF) $(CLIENT_ELF) \
			$(BUILD_DIR)/frontend.elf $(BUILD_DIR)/sender_loader.elf

# Private key file

KEYS_GENERATOR	:= $(CURDIR)/keygen/generate_ed25519_keys.py
KEYS_GEN_DIR	:= $(BUILD_DIR)/keygen
PUBLIC_KEY_FILE	:= $(KEYS_GEN_DIR)/ed25519_public_key.bin
PRIVATE_KEY_FILE := $(KEYS_GEN_DIR)/ed25519_private_key.pem
KEYS_STAMP		:= .generated.stamp

# PRIVATE_KEY_FILE ?= $(PRIVATE_KEY)

# Compiler and linker flags
CFLAGS := -mcpu=$(CPU) -mstrict-align -nostdlib -ffreestanding -g -O3 \
          -Wall -Wno-unused-function -Werror \
          -I$(BOARD_DIR)/include \
		  -I$(LIBCRYPTO_SRC_DIR)/include \
		  -I$(LIBEXTELF_SRC_DIR)/include \
		  -I$(LIBTSLDR_SRC_DIR)/include

LDFLAGS := -L$(BOARD_DIR)/lib -L$(LIBCRYPTO_BUILD_DIR) -L$(LIBEXTELF_BUILD_DIR) -L$(LIBTSLDR_BUILD_DIR)

LIBS := -lmicrokit -Tmicrokit.ld

# Output files
IMAGE_FILE = $(BUILD_DIR)/loader.img
REPORT_FILE = $(BUILD_DIR)/report.txt

# Default target
all: $(IMAGE_FILE)

$(PRIVATE_KEY_FILE) $(PUBLIC_KEY_FILE): $(KEYS_STAMP)

$(KEYS_STAMP): $(KEYS_GENERATOR)
	@$(info $(shell mkdir -p $(KEYS_GEN_DIR)))
	$(PYTHON) $(KEYS_GENERATOR) $(KEYS_GEN_DIR)

# Compile C source files
$(BUILD_DIR)/%.o: %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

# Assemble assembly source files
$(BUILD_DIR)/%.o: %.s Makefile
	$(AS) -g -mcpu=$(CPU) $< -o $@

# Generate patched ELF files
$(PATCHED_PROTO_CONTAINER_ELF): $(BUILD_DIR)/proto-container.elf $(PRIVATE_KEY_FILE)
	$(PYTHON) patch_elf.py $< $(SYSTEM_HASH) -k $(PRIVATE_KEY_FILE)

$(PATCHED_RECEIVER2_ELF): $(BUILD_DIR)/receiver2.elf $(PRIVATE_KEY_FILE)
	$(PYTHON) patch_elf.py $< $(SYSTEM_HASH) -k $(PRIVATE_KEY_FILE)

$(PATCHED_CLIENT_ELF): $(CLIENT_ELF) $(PRIVATE_KEY_FILE)
	$(PYTHON) patch_elf.py $< $(SYSTEM_HASH) -k $(PRIVATE_KEY_FILE)

# Link trusted_loader.elf
$(BUILD_DIR)/trusted_loader.elf: $(BUILD_DIR)/$(TRUSTED_LOADER_OBJS) \
                                 ${LIBEXTELF} ${LIBCRYPTO} \
                                 $(PACKAGE_PROGS_OBJS)
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/frontend.elf: $(BUILD_DIR)/$(FRONTEND_OBJS) \
 						   ${LIBEXTELF} $(PACKAGE_PROGS_OBJS)
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/sender_loader.elf: $(BUILD_DIR)/$(SENDER_LOADER_OBJS) \
 								  ${LIBEXTELF} $(PACKAGE_PROGS_OBJS)
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

# Link programs.o with patched ELF dependencies
$(PACKAGE_PROGS_OBJS): package_programs.S $(PATCHED_PROTO_CONTAINER_ELF) $(PATCHED_RECEIVER2_ELF) $(PATCHED_CLIENT_ELF)
	$(CC) -c -g3 -x assembler-with-cpp \
		-DPROTO_CONTAINER_PATH=\"$(PATCHED_PROTO_CONTAINER_ELF)\" \
		-DRECEIVER2_PATH=\"$(PATCHED_RECEIVER2_ELF)\" \
		-DCLIENT_PATH=\"$(PATCHED_CLIENT_ELF)\" \
		package_programs.S -o $@

# Link proto-container.elf
$(BUILD_DIR)/proto-container.elf: $(BUILD_DIR)/$(PROTO_CONTAINER_OBJS) \
                            ${LIBEXTELF} $(LIBCRYPTO) $(LIBTSLDR)
	$(LD) $(LDFLAGS) --defsym __sel4_ipc_buffer=0x100000 $^ $(LIBS) -o $@

# Link receiver2.elf
$(BUILD_DIR)/receiver2.elf: $(BUILD_DIR)/$(RECEIVER2_OBJS) \
                            ${LIBEXTELF}
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(CLIENT_ELF): $(BUILD_DIR)/$(CLIENT_OBJS)
	$(LD) $(LDFLAGS) -Ttext=0xB000000 $^ $(LIBS) -o $@

# Generate final image and report
$(IMAGE_FILE) $(REPORT_FILE): $(IMAGES) pd_templates.system
	$(MICROKIT_TOOL) pd_templates.system --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) \
		-o $(IMAGE_FILE) -r $(REPORT_FILE) -p $(PUBLIC_KEY_FILE)

qemu: $(IMAGE_FILE)
	qemu-system-aarch64 \
		-machine virt,virtualization=on \
		-cpu $(CPU) \
		-nographic \
		-serial mon:stdio \
		-device loader,file=$(IMAGE_FILE),addr=0x70000000,cpu-num=0 \
		-device loader,addr=0x90000000,data=0x61,data-len=1 \
		-m size=2G

# Clean target
clean:
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.elf $(IMAGE_FILE) $(REPORT_FILE)

.PHONY: all clean qemu
