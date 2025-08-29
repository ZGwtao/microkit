#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <microkit.h>

/* use ED25519 algorithm for encryption now */
#define PUBLIC_KEY_BYTES        32

#define NUM_ENTRIES_SIZE        sizeof(uint32_t)

/* number of access rights (for seL4 capabilities only) */
#define MAX_ACCESS_RIGHTS       MICROKIT_MAX_CHANNELS * 3

#define ACCESS_RIGHT_ENTRY_SIZE 9

// Access types
typedef enum {
    ACCESS_TYPE_CHANNEL = 0x01,
    ACCESS_TYPE_IRQ     = 0x02,
    ACCESS_TYPE_MEMORY  = 0x03
} AccessType;

// Structure to hold each access right entry
typedef struct {
    AccessType type;
    seL4_Word data; // For CHANNEL and IRQ: ID; For MEMORY: VADDR
} AccessRightEntry;

// Structure to hold all access rights
typedef struct {
    seL4_Word system_hash;
    uint32_t num_entries;
    AccessRightEntry entries[MAX_ACCESS_RIGHTS];
} AccessRights;

// Structure for memory mapping
typedef struct {
    seL4_Word vaddr;
    seL4_Word page;
    seL4_Word number_of_pages;
    seL4_Word page_size;
    seL4_Word rights;
    seL4_Word attrs;
} MemoryMapping;


typedef int (*crypto_verify_fn)(const unsigned char *signature,
                                const unsigned char *data,
                                size_t data_size,
                                const unsigned char *public_key);


/* class of trusted loader */
typedef struct {

    /* access right table */
    AccessRights access_rights;
    /*
     * types of rights:
     *  1. PPC channels
     *  2. IRQ channels
     *  3. Mappings
     */
    bool allowed_channels[MICROKIT_MAX_CHANNELS];
    bool allowed_irqs[MICROKIT_MAX_CHANNELS];
    MemoryMapping allowed_mappings[MICROKIT_MAX_CHANNELS];

    /* mapping bookkeeping */
    int num_allowed_mappings;

    /* restart flag for capabilities */
    bool removed_caps;

    /* crypto */
    seL4_Word system_hash;

    size_t hash_len;
    size_t signature_len;

    unsigned char public_key[PUBLIC_KEY_BYTES];

    /* hook for signature verification function */
    crypto_verify_fn verify_func;

} trusted_loader_t;

/**
 * @brief Populates access rights and verifies signature of the data.
 *
 * @param loader Pointer to where the AccessRights structure to be populated and stored.
 * @param signed_message Pointer to the signed message (signature || data).
 * @param len Length of the signed message in bytes.
 * @return true if the signature is valid, false otherwise.
 */
seL4_Error tsldr_populate_rights(trusted_loader_t *loader, const unsigned char *signed_message, size_t len);

/**
 * @brief Applies access rights to build allowed lists
 *
 * @param loader Pointer to the loader which contains recorded access rights table
 */
seL4_Error tsldr_populate_allowed(trusted_loader_t *loader);

/**
 * @brief Initialise a trusted loader
 *
 * @param loader Pointer to the trusted loader to initialise
 * @param fn Function pointer to the verifying mechanism
 * @param hash_val System hash value
 * @param hash_len Length of the system hash value
 * @param signature_len Length of the access right table signature
 */
void tsldr_init(trusted_loader_t *loader, crypto_verify_fn fn, seL4_Word hash_val, size_t hash_len, size_t signature_len);