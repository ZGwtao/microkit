#
# Copyright 2021, Breakaway Consulting Pty. Ltd.
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

TOOLCHAIN := aarch64-none-elf

CPU := cortex-a53

CC := $(TOOLCHAIN)-gcc
LD := $(TOOLCHAIN)-ld
AS := $(TOOLCHAIN)-as
MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit

TRUSTED_LOADER_OBJS := trusted_loader.o
RECEIVER_OBJS := receiver.o
SENDER_OBJS := sender.o
ELF_UTILS_OBJS := elf_utils.o

BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

IMAGES := trusted_loader.elf receiver.elf sender.elf
CFLAGS := -mcpu=$(CPU) -mstrict-align -nostdlib -ffreestanding -g -O3 -Wall -Wno-unused-function -Werror -I$(BOARD_DIR)/include
LDFLAGS := -L$(BOARD_DIR)/lib
LIBS := -lmicrokit -Tmicrokit.ld

IMAGE_FILE = $(BUILD_DIR)/loader.img
REPORT_FILE = $(BUILD_DIR)/report.txt

all: $(IMAGE_FILE)

$(BUILD_DIR)/%.o: %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.o: %.s Makefile
	$(AS) -g -mcpu=$(CPU) $< -o $@

$(BUILD_DIR)/trusted_loader.elf: $(addprefix $(BUILD_DIR)/, $(TRUSTED_LOADER_OBJS)) $(addprefix $(BUILD_DIR)/, $(ELF_UTILS_OBJS)) programs.o
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

programs.o: package_programs.S $(BUILD_DIR)/receiver.elf elf_utils.h
	$(CC) -c -g3 -x assembler-with-cpp \
		-DRECEIVER_PATH=\"$(BUILD_DIR)/receiver.elf\" \
		package_programs.S -o $@

$(BUILD_DIR)/receiver.elf: $(addprefix $(BUILD_DIR)/, $(RECEIVER_OBJS)) $(addprefix $(BUILD_DIR)/, $(ELF_UTILS_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/sender.elf: $(addprefix $(BUILD_DIR)/, $(SENDER_OBJS)) $(addprefix $(BUILD_DIR)/, $(ELF_UTILS_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(IMAGE_FILE) $(REPORT_FILE): $(addprefix $(BUILD_DIR)/, $(IMAGES)) pd_templates.system
	$(MICROKIT_TOOL) pd_templates.system --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) -o $(IMAGE_FILE) -r $(REPORT_FILE)
