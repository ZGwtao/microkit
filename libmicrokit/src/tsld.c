
#include <microkit.h>

// If there is no explicit reference to microkit_trusted_loading_info in code,
// it would require extra LDFLAGS '-u microkit_trusted_loading_info' to keep the symbol (if you need it)
// so that the linker can find the symbol from libmicrokit.a and links tsld.o to monitor PD images

/* Only valid in the 'monitor_protection_domain' configuration */
#define MICROKIT_TRUSTED_LOADING_INFO_LENGTH       (1UL << 16)

/* We use this region to record all dynamic capabilities of template PDs that are controlled by a monitor PD.
 * The monitor PD needs to know which capabilities are valid for a given template PD.
 * When a template PD needs to be instantiated via self-loading, it needs to know what capabilities are valid for
 * it to use within its life-cycle, which means if the template can modify the trusted loading info region,
 * it could be possible that a malicious client could falsify the trusted loading info for the next client and
 * disobey the principle of least privilege. So, we assume only the monitor is trusted and will update the info
 * for the self-loading templates, and the info are parts of the info recorded within the below region.
 * 
 * for now, we assume the maximum number of clients (template PDs) controlled by a monitor is 16,
 * each client has a 4KB page for recording its trusted loading info, that is why the buffer is set to 64KB.
 */
char microkit_trusted_loading_info[MICROKIT_TRUSTED_LOADING_INFO_LENGTH];
