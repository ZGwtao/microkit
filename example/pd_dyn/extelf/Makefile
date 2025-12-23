
ifndef MICROKIT_SDK
$(error MICROKIT_SDK is not set)
endif

ifndef BUILD_DIR 
$(error BUILD_DIR is not set)
endif

ifndef MICROKIT_BOARD 
$(error MICROKIT_BOARD is not set)
endif

ifndef MICROKIT_CONFIG 
$(error MICROKIT_CONFIG is not set)
endif

BOARD_DIR ?= $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

EXTELF_OBJS :=  \
	elfutils.o

LIBEXTELF_SRC_DIR ?= $(CURDIR)
LIBEXTELF_BUILD_DIR := $(BUILD_DIR)/libextelf
LIBEXTELF_OBJS := $(addprefix $(LIBEXTELF_BUILD_DIR)/,$(EXTELF_OBJS))
LIBEXTELF := $(LIBEXTELF_BUILD_DIR)/libextelf.a

LIBEXTELF_CFLAGS ?= -nostdlib -ffreestanding -g -O3 \
          			-Wall -Wno-unused-function -Werror \
          			-I$(BOARD_DIR)/include

all: libextelf_dir $(LIBEXTELF)

.PHONY: libextelf_dir
libextelf_dir: 
	$(info $(shell mkdir -p $(BUILD_DIR)/libextelf))

$(LIBEXTELF_OBJS): $(LIBEXTELF_BUILD_DIR)/%.o : $(LIBEXTELF_SRC_DIR)/%.c
	$(CC) -c $(LIBEXTELF_CFLAGS) $< -o $@

$(LIBEXTELF): $(LIBEXTELF_OBJS)
	$(AR) rcs $@ $^
