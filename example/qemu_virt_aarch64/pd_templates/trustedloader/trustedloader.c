
#include <libtrustedlo.h>
#include <string.h>
#include <elf_utils.h>

#define LIB_NAME_MACRO "<libtrustedlo> "

seL4_Error tsldr_populate_rights(trusted_loader_t *loader, const unsigned char *signed_message, size_t len)
{
    if (!loader) {
        microkit_dbg_puts("[trusred loader]: invalid loader pointer given\n");
        return seL4_InvalidArgument;
    }
    /* specify where to store access rights */
    AccessRights *rights = &loader->access_rights;
    custom_memset((void *)rights, 0, sizeof(AccessRights));

    // Calculate the minimum required size: signature + system_hash + num_access_rights
    size_t min_required_size = loader->signature_len + loader->hash_len + NUM_ENTRIES_SIZE;

    if (len < min_required_size) {
        microkit_dbg_puts("[trusted loader]: Signed message length is too short.\n");
        return seL4_InvalidArgument;
    }

    const unsigned char *signature = signed_message;
    const unsigned char *data = signed_message + loader->signature_len;

    custom_memcpy(&rights->system_hash, data, loader->hash_len);
    custom_memcpy(&rights->num_entries, data + loader->hash_len, NUM_ENTRIES_SIZE);

    microkit_dbg_printf(LIB_NAME_MACRO "System hash (from access rights section of ELF file): 0x%x\n", rights->system_hash);
    microkit_dbg_printf(LIB_NAME_MACRO "Number of access rights: %d\n", rights->num_entries);

    // Check if the number of access rights exceeds the maximum allowed
    if (rights->num_entries > MAX_ACCESS_RIGHTS) {
        microkit_dbg_printf(LIB_NAME_MACRO "Number of access rights (%d) exceeds maximum allowed (%d)\n", rights->num_entries, MAX_ACCESS_RIGHTS);
        return seL4_InvalidArgument;
    }

    // Verify system_hash matches
    if (rights->system_hash != loader->system_hash) {
        microkit_dbg_printf(LIB_NAME_MACRO "System hash mismatch: expected 0x%x, found 0x%x\n",
                           (unsigned long)loader->system_hash,
                           (unsigned long)rights->system_hash);
        return seL4_InvalidArgument;
    }

    microkit_dbg_printf(LIB_NAME_MACRO "Extracted system hash and trusted loader's system hash matched successfully\n");

    // Calculate the expected total size based on the number of access rights
    size_t data_size = loader->hash_len + NUM_ENTRIES_SIZE + (rights->num_entries * ACCESS_RIGHT_ENTRY_SIZE);
    
    if (len < loader->signature_len + data_size) {
        microkit_dbg_printf(LIB_NAME_MACRO "Verified data size (%d) is less than expected size (%d)\n", len, loader->signature_len + data_size);
        return seL4_InvalidArgument;
    }

    // Print the public key in hex
    microkit_dbg_printf(LIB_NAME_MACRO "Public key: 0x");
    for (int i = 0; i < PUBLIC_KEY_BYTES; i++) {
        microkit_dbg_printf("%x", loader->public_key[i]);
    }
    microkit_dbg_printf("\n");

    // Print the signature in hex
    microkit_dbg_printf(LIB_NAME_MACRO "Signature: 0x");
    for (int i = 0; i < loader->signature_len; i++) {
        microkit_dbg_printf("%x", signature[i]);
    }
    microkit_dbg_printf("\n");

    // Print the data in hex (optional, can be removed in production)
    microkit_dbg_printf(LIB_NAME_MACRO "Data (size %d bytes): 0x", data_size);
    for (size_t i = 0; i < data_size; i++) {
        microkit_dbg_printf("%x", data[i]);
    }
    microkit_dbg_printf("\n");

    // Perform signature verification
    int valid_signature = loader->verify_func(signature, data, data_size, loader->public_key);

    if (valid_signature != 1) {
        microkit_dbg_printf(LIB_NAME_MACRO "ed25519_verify failed. Invalid signature.\n");
        return seL4_InvalidArgument;
    }

    microkit_dbg_printf(LIB_NAME_MACRO "ed25519_verify succeeded. Signature is valid.\n");

    const unsigned char *access_rights_table = data + loader->hash_len + NUM_ENTRIES_SIZE;

    // Parse each access right entry
    for (uint32_t i = 0; i < rights->num_entries; i++) {
        AccessRightEntry *entry = &rights->entries[i];
        entry->type = (AccessType)*(access_rights_table + i * ACCESS_RIGHT_ENTRY_SIZE);
        entry->data = *((seL4_Word*)(access_rights_table + i * ACCESS_RIGHT_ENTRY_SIZE + sizeof(uint8_t)));
        microkit_dbg_printf(LIB_NAME_MACRO "Parsed access right %d: type=%d, data=0x%x\n", i, entry->type, (unsigned long long)entry->data);
    }

    return seL4_NoError;
}

#if 0
seL4_Error tsldr_populate_allowed(trusted_loader_t *loader)
{
    if (!loader) {
        microkit_dbg_printf(LIB_NAME_MACRO "Invalid loader pointer given\n");
        return seL4_InvalidArgument;
    }
    AccessRights *rights = &loader->access_rights;
    // Reset allowed lists
    custom_memset(loader->allowed_channels, 0, sizeof(loader->allowed_channels));
    custom_memset(loader->allowed_irqs, 0, sizeof(loader->allowed_irqs));
    loader->num_allowed_mappings = 0;

    for (uint32_t i = 0; i < rights->num_entries; i++) {
        const AccessRightEntry *entry = &rights->entries[i];
        switch (entry->type) {
            case ACCESS_TYPE_CHANNEL:
                if (entry->data < MICROKIT_MAX_CHANNELS && channels[entry->data]) {
                    loader->allowed_channels[entry->data] = true;
                    microkit_dbg_printf(PROGNAME "Allowed channel ID: %d\n", (unsigned long long)entry->data);
                } else {
                    microkit_dbg_printf(PROGNAME "Invalid channel ID: %d\n", (unsigned long long)entry->data);
                    return seL4_InvalidArgument;
                }
                break;

            case ACCESS_TYPE_IRQ:
                if (entry->data < MICROKIT_MAX_CHANNELS && irqs[entry->data]) {
                    loader->allowed_irqs[entry->data] = true;
                    microkit_dbg_printf(PROGNAME "Allowed IRQ ID: %d\n", (unsigned long long)entry->data);
                } else {
                    microkit_dbg_printf(PROGNAME "Invalid IRQ ID: %d\n", (unsigned long long)entry->data);
                    return seL4_InvalidArgument;
                }
                break;

            case ACCESS_TYPE_MEMORY:
            /*
                if (loader->num_allowed_mappings < MAX_MAPPINGS) {
                    seL4_Word vaddr = entry->data;
                    MemoryMapping *mapping = find_mapping_by_vaddr(vaddr);
                    if (mapping != NULL) {
                        allowed_mappings[loader->num_allowed_mappings++] = *mapping;
                        microkit_dbg_printf(PROGNAME "Allowed memory vaddr: 0x%x\n", (unsigned long long)vaddr);
                    } else {
                        microkit_dbg_printf(PROGNAME "Mapping not found for vaddr: 0x%x\n", (unsigned long long)vaddr);
                        return seL4_InvalidArgument;
                    }
                } else {
                    microkit_dbg_printf(PROGNAME "Number of allowed mappings exceeded\n");
                    return seL4_InvalidArgument;
                }
            */
                break;

            default:
                microkit_dbg_printf(PROGNAME "Unknown access type: %d\n", (unsigned int)entry->type);
                return seL4_InvalidArgument;
        }
    }

    return seL4_NoError;
}
#endif

void tsldr_init(trusted_loader_t *loader, crypto_verify_fn fn, seL4_Word hash_val, size_t hash_len, size_t signature_len)
{
    if (!loader) {
        microkit_dbg_puts("[trusred loader]: try to init null loader\n");
        return;
    }
    loader->verify_func = fn;
    loader->system_hash = hash_val;
    loader->hash_len = hash_len;
    loader->signature_len = signature_len;
}