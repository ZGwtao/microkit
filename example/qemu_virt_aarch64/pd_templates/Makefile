#
# Copyright 2024, UNSW
#
# SPDX-License-Identifier: BSD-2-Clause
#

# Ensure required variables are specified
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

ifeq ($(strip $(SYSTEM_HASH)),)
$(error SYSTEM_HASH must be specified)
endif

ifeq ($(strip $(PRIVATE_KEY)),)
$(error PRIVATE_KEY must be specified)
endif

ifeq ($(strip $(PUBLIC_KEY)),)
$(error PUBLIC_KEY must be specified)
endif

# Toolchain and compiler settings
TOOLCHAIN := aarch64-none-elf
CPU := cortex-a53

CC := $(TOOLCHAIN)-gcc
LD := $(TOOLCHAIN)-ld
AS := $(TOOLCHAIN)-as

MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit
PYTHON	:= $(PWD)/pyenv/bin/python

LIBCRYPTO_SRC_DIR := $(CURDIR)/crypto
include crypto/Makefile

# Object files
TRUSTED_LOADER_OBJS := trusted_loader.o
RECEIVER_OBJS := receiver.o
RECEIVER2_OBJS := receiver2.o
SENDER_OBJS := sender.o
ELF_UTILS_OBJS := elf_utils.o
# CRYPTO_OBJS := fe.o ge.o key_exchange.o keypair.o sc.o sha512.o sign.o verify.o
RECEIVER_LOADER_OBJS := receiver_loader.o
SENDER_LOADER_OBJS := sender_loader.o

# Board directory
BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

# Patched ELF file names
PATCHED_RECEIVER_ELF := $(BUILD_DIR)/receiver_patched.elf
PATCHED_RECEIVER2_ELF := $(BUILD_DIR)/receiver2_patched.elf
PATCHED_SENDER_ELF := $(BUILD_DIR)/sender_patched.elf

# Images to include patched ELF files
IMAGES := $(BUILD_DIR)/trusted_loader.elf $(PATCHED_RECEIVER_ELF) $(PATCHED_SENDER_ELF) $(PATCHED_RECEIVER2_ELF) $(BUILD_DIR)/receiver_loader.elf $(BUILD_DIR)/sender_loader.elf

# Private key file
PRIVATE_KEY_FILE := $(PRIVATE_KEY)

# Compiler and linker flags
CFLAGS := -mcpu=$(CPU) -mstrict-align -nostdlib -ffreestanding -g -O3 \
          -Wall -Wno-unused-function -Werror \
          -I$(BOARD_DIR)/include

LDFLAGS := -L$(BOARD_DIR)/lib -L$(LIBCRYPTO_BUILD_DIR)

LIBS := -lmicrokit -Tmicrokit.ld

# Output files
IMAGE_FILE = $(BUILD_DIR)/loader.img
REPORT_FILE = $(BUILD_DIR)/report.txt

# Default target
all: $(IMAGE_FILE)

# Compile C source files
$(BUILD_DIR)/%.o: %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

# Assemble assembly source files
$(BUILD_DIR)/%.o: %.s Makefile
	$(AS) -g -mcpu=$(CPU) $< -o $@

# Generate patched ELF files
$(PATCHED_RECEIVER_ELF): $(BUILD_DIR)/receiver.elf
	$(PYTHON) patch_elf.py $< $(SYSTEM_HASH) -k $(PRIVATE_KEY_FILE)

$(PATCHED_RECEIVER2_ELF): $(BUILD_DIR)/receiver2.elf
	$(PYTHON) patch_elf.py $< $(SYSTEM_HASH) -k $(PRIVATE_KEY_FILE)

$(PATCHED_SENDER_ELF): $(BUILD_DIR)/sender.elf
	$(PYTHON) patch_elf.py $< $(SYSTEM_HASH) -k $(PRIVATE_KEY_FILE)

# Link trusted_loader.elf
$(BUILD_DIR)/trusted_loader.elf: $(BUILD_DIR)/$(TRUSTED_LOADER_OBJS) \
                                 $(BUILD_DIR)/$(ELF_UTILS_OBJS) \
								 ${LIBCRYPTO} \
                                 programs.o
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@ -lcrypto

$(BUILD_DIR)/receiver_loader.elf: $(BUILD_DIR)/$(RECEIVER_LOADER_OBJS) \
 								  $(BUILD_DIR)/$(ELF_UTILS_OBJS) \
								  programs.o
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/sender_loader.elf: $(BUILD_DIR)/$(SENDER_LOADER_OBJS) \
 								$(BUILD_DIR)/$(ELF_UTILS_OBJS) \
								programs.o
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

# Link programs.o with patched ELF dependencies
programs.o: package_programs.S $(PATCHED_RECEIVER_ELF) $(PATCHED_SENDER_ELF) $(PATCHED_RECEIVER2_ELF)
	$(CC) -c -g3 -x assembler-with-cpp \
		-DRECEIVER_PATH=\"$(PATCHED_RECEIVER_ELF)\" \
		-DSENDER_PATH=\"$(PATCHED_SENDER_ELF)\" \
		-DRECEIVER2_PATH=\"$(PATCHED_RECEIVER2_ELF)\" \
		package_programs.S -o $@

# Link receiver.elf
$(BUILD_DIR)/receiver.elf: $(BUILD_DIR)/$(RECEIVER_OBJS) \
                            $(BUILD_DIR)/$(ELF_UTILS_OBJS)
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

# Link receiver2.elf
$(BUILD_DIR)/receiver2.elf: $(BUILD_DIR)/$(RECEIVER2_OBJS) \
                            $(BUILD_DIR)/$(ELF_UTILS_OBJS)
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

# Link sender.elf
$(BUILD_DIR)/sender.elf: $(BUILD_DIR)/$(SENDER_OBJS) \
                          $(BUILD_DIR)/$(ELF_UTILS_OBJS)
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

# Generate final image and report
$(IMAGE_FILE) $(REPORT_FILE): $(IMAGES) pd_templates.system
	$(MICROKIT_TOOL) pd_templates.system --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) \
		-o $(IMAGE_FILE) -r $(REPORT_FILE) -p $(PUBLIC_KEY)

# Clean target
clean:
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.elf $(IMAGE_FILE) $(REPORT_FILE)

.PHONY: all clean
