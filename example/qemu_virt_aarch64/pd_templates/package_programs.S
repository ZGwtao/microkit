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

#if defined(PROTO_CONTAINER_PATH)
.section .proto_container, "aw", @progbits
.global _proto_container, _proto_container_end
_proto_container:
.incbin PROTO_CONTAINER_PATH
_proto_container_end:
#endif

#if defined(TRAMPOLINE_PATH)
.section .trampoline, "aw", @progbits
.global _trampoline, _trampoline_end
_trampoline:
.incbin TRAMPOLINE_PATH
_trampoline_end:
#endif

#if defined(CLIENT_PATH)
.section .client, "aw", @progbits
.global _client, _client_end
_client:
.incbin CLIENT_PATH
_client_end:
#endif

#if defined(TEST_PATH)
.section .test, "aw", @progbits
.global _test, _test_end
_test:
.incbin TEST_PATH
_test_end:
#endif