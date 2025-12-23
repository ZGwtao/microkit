/* 
 * => trusted_loader:
 *  the first elf image execute in the dynamic PD
 *  should be removed as it may contains private information...
 *
 * => trampoline:
 *  the second elf image, which bridges between the trusted world and the client application 
 *  trampoline is simple enough to stay in the memory
 *
 * => client_payload:
 *  the application program
 */

#if defined(TRAMPOLINE_PATH)
.section .trampoline, "aw", @progbits
.global _trampoline, _trampoline_end
_trampoline:
.incbin TRAMPOLINE_PATH
_trampoline_end:
#endif

#if defined(PAYLOAD_PATH)
.section .paylod, "aw", @progbits
.global _payload, _payload_end
_payload:
.incbin PAYLOAD_PATH
_payload_end:
#endif

#if defined(LOADER_PATH)
.section .loader, "aw", @progbits
.global _loader, _loader_end
_loader:
.incbin LOADER_PATH
_loader_end:
#endif
