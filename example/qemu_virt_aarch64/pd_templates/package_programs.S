/*
 * Copyright 2023, UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * What even is this file?
 *
 * The purpose of this file is to include binaries that the VMM needs to setup,
 * such as the Linux kernel image, the DTB, and the initial RAM disk. What
 * happens is that the assembler includes the binary data in an ELF section
 * that we specify. We can then have global variables that essentially point to
 * where the data has been included.
 *
 * For each ELF section, we define a name and also some configuration. The
 * attributes "aw" is to say that the section is allocatable and that it is
 * writeable. We also have "@progbits", this is to indicate that the section
 * contains data (rather than code or something else).
 *
 */

#if defined(RECEIVER_PATH)
.section .receiver, "aw", @progbits
.global _receiver, _receiver_end
_receiver:
.incbin RECEIVER_PATH
_receiver_end:
#endif

#if defined(RECEIVER2_PATH)
.section .receiver2, "aw", @progbits
.global _receiver2, _receiver2_end
_receiver2:
.incbin RECEIVER2_PATH
_receiver2_end:
#endif
