#
# Copyright ...
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

# **New:** Ensure SYSTEM_HASH is specified
ifeq ($(strip $(SYSTEM_HASH)),)
$(error SYSTEM_HASH must be specified)
endif

# Toolchain and compiler settings
TOOLCHAIN := aarch64-none-elf
CPU := cortex-a53

CC := $(TOOLCHAIN)-gcc
LD := $(TOOLCHAIN)-ld
AS := $(TOOLCHAIN)-as

MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit

# Object files
TRUSTED_LOADER_OBJS := trusted_loader.o
RECEIVER_OBJS := receiver.o
SENDER_OBJS := sender.o
ELF_UTILS_OBJS := elf_utils.o

# Board directory
BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

# **New:** Define patched ELF file names
PATCHED_RECEIVER_ELF := $(BUILD_DIR)/receiver_patched.elf
PATCHED_SENDER_ELF := $(BUILD_DIR)/sender_patched.elf

# Define IMAGES to include patched ELF files
IMAGES := trusted_loader.elf receiver_patched.elf sender_patched.elf

# Compiler and linker flags
CFLAGS := -mcpu=$(CPU) -mstrict-align -nostdlib -ffreestanding -g -O3 -Wall -Wno-unused-function -Werror -I$(BOARD_DIR)/include
LDFLAGS := -L$(BOARD_DIR)/lib
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

# **New:** Rule to generate receiver_patched.elf
$(PATCHED_RECEIVER_ELF): $(BUILD_DIR)/receiver.elf
	python patch_elf.py $< $(SYSTEM_HASH)

# **New:** Rule to generate sender_patched.elf
$(PATCHED_SENDER_ELF): $(BUILD_DIR)/sender.elf
	python patch_elf.py $< $(SYSTEM_HASH)

# Link trusted_loader.elf using patched ELF files
$(BUILD_DIR)/trusted_loader.elf: $(addprefix $(BUILD_DIR)/, $(TRUSTED_LOADER_OBJS)) $(addprefix $(BUILD_DIR)/, $(ELF_UTILS_OBJS)) programs.o
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

# **Updated:** programs.o now depends on patched ELF files
programs.o: package_programs.S $(PATCHED_RECEIVER_ELF) $(PATCHED_SENDER_ELF) elf_utils.h
	$(CC) -c -g3 -x assembler-with-cpp \
		-DRECEIVER_PATH=\"$(PATCHED_RECEIVER_ELF)\" \
		-DSENDER_PATH=\"$(PATCHED_SENDER_ELF)\" \
		package_programs.S -o $@

# Link receiver.elf as before
$(BUILD_DIR)/receiver.elf: $(addprefix $(BUILD_DIR)/, $(RECEIVER_OBJS)) $(addprefix $(BUILD_DIR)/, $(ELF_UTILS_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

# Link sender.elf as before
$(BUILD_DIR)/sender.elf: $(addprefix $(BUILD_DIR)/, $(SENDER_OBJS)) $(addprefix $(BUILD_DIR)/, $(ELF_UTILS_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

# Generate the final image and report using patched ELF files
$(IMAGE_FILE) $(REPORT_FILE): $(addprefix $(BUILD_DIR)/, $(IMAGES)) pd_templates.system
	$(MICROKIT_TOOL) pd_templates.system --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) -o $(IMAGE_FILE) -r $(REPORT_FILE)

# Optional: Clean target to remove build artifacts
clean:
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.elf $(IMAGE_FILE) $(REPORT_FILE)

.PHONY: all clean
