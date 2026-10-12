#ifndef DN_UNHOOK_H
#define DN_UNHOOK_H

#include <windows.h>

/*
 * Dark Nexus - ntdll.dll Unhooking
 *
 * Restores hooked ntdll .text section with a clean copy.
 * Three strategies in order of stealth:
 *   1. KnownDlls section mapping (no filesystem access)
 *   2. Suspended process (no file open on ntdll.dll)
 *   3. Disk read fallback (triggers minifilter but always works)
 */

// Unhook ntdll using the best available method
// Returns TRUE if .text section was restored
BOOL dn_unhook_ntdll(void);

// Individual strategies (called by dn_unhook_ntdll in priority order)
BOOL dn_unhook_via_knowndlls(void);
BOOL dn_unhook_via_suspended_process(void);
BOOL dn_unhook_via_disk(void);

#endif // DN_UNHOOK_H
