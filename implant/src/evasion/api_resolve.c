#include "api_resolve.h"
#include "peb_types.h"

/*
 * Dark Nexus - CRC32B API Resolution Engine
 *
 * Resolves DLL bases and function addresses without touching
 * GetModuleHandle or GetProcAddress. Walks PEB for modules,
 * parses PE export tables for functions, uses CRC32B hashing
 * to avoid plaintext API strings in the binary.
 *
 * Handles forwarded exports (e.g., kernel32!HeapAlloc -> ntdll!RtlAllocateHeap)
 * by recursively resolving through the forwarder chain.
 */

// -------------------------------------------------------------------
// CRC32B lookup table (standard polynomial 0xEDB88320)
// -------------------------------------------------------------------
static const DWORD crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91B, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBB, 0xE7B82D09, 0x90BF1D9F,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
    0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
    0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x21B4F0B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7C89,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
    0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
    0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
    0xDF60EFC3, 0xA8670955, 0x31683918, 0x466D0B8E,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

// -------------------------------------------------------------------
// CRC32B hash functions
// -------------------------------------------------------------------

DWORD dn_crc32b(const char* str) {
    DWORD crc = 0xFFFFFFFF;
    while (*str) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ (BYTE)*str) & 0xFF];
        str++;
    }
    return crc ^ 0xFFFFFFFF;
}

// Wide-string variant, converts to lowercase for case-insensitive DLL matching
DWORD dn_crc32b_wide_lower(const wchar_t* str) {
    DWORD crc = 0xFFFFFFFF;
    while (*str) {
        wchar_t ch = *str;
        // lowercase: A-Z -> a-z
        if (ch >= L'A' && ch <= L'Z')
            ch += 32;

        // hash both bytes of the wide char (little-endian)
        BYTE lo = (BYTE)(ch & 0xFF);
        BYTE hi = (BYTE)((ch >> 8) & 0xFF);

        crc = (crc >> 8) ^ crc32_table[(crc ^ lo) & 0xFF];
        crc = (crc >> 8) ^ crc32_table[(crc ^ hi) & 0xFF];
        str++;
    }
    return crc ^ 0xFFFFFFFF;
}

// -------------------------------------------------------------------
// PEB-walking module resolution
// -------------------------------------------------------------------

PVOID dn_get_module_by_hash(DWORD module_hash) {
    PDN_PEB peb = dn_get_peb();

    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PDN_LDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(
            entry, DN_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks
        );

        if (mod->BaseDllName.Length > 0 && mod->BaseDllName.Buffer != NULL) {
            DWORD hash = dn_crc32b_wide_lower(mod->BaseDllName.Buffer);
            if (hash == module_hash) {
                return mod->DllBase;
            }
        }

        entry = entry->Flink;
    }
    return NULL;
}

// -------------------------------------------------------------------
// PE export table walking with forwarded export support
// -------------------------------------------------------------------

// forward declaration for recursive forwarder resolution
static PVOID resolve_forwarder(const char* forwarder_str);

// PE helpers
static PIMAGE_NT_HEADERS get_nt_headers(PVOID base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    return (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
}

static PIMAGE_EXPORT_DIRECTORY get_export_dir(PVOID base, DWORD* export_size) {
    PIMAGE_NT_HEADERS nt = get_nt_headers(base);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (dir->VirtualAddress == 0)
        return NULL;

    if (export_size)
        *export_size = dir->Size;

    return (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + dir->VirtualAddress);
}

PVOID dn_get_proc_by_hash(PVOID module_base, DWORD func_hash) {
    DWORD export_size = 0;
    PIMAGE_EXPORT_DIRECTORY exports = get_export_dir(module_base, &export_size);
    if (!exports) return NULL;

    DWORD* names    = (DWORD*)((BYTE*)module_base + exports->AddressOfNames);
    WORD*  ordinals = (WORD*)((BYTE*)module_base + exports->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)((BYTE*)module_base + exports->AddressOfFunctions);

    // export directory boundaries for forwarder detection
    BYTE* export_base = (BYTE*)exports;
    BYTE* export_end  = export_base + export_size;

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)module_base + names[i]);
        DWORD hash = dn_crc32b(name);

        if (hash == func_hash) {
            DWORD func_rva = funcs[ordinals[i]];
            BYTE* func_addr = (BYTE*)module_base + func_rva;

            // check if this is a forwarded export
            // forwarded: the RVA points within the export directory itself
            if (func_addr >= export_base && func_addr < export_end) {
                // func_addr is a forwarder string like "NTDLL.RtlAllocateHeap"
                return resolve_forwarder((const char*)func_addr);
            }

            return func_addr;
        }
    }
    return NULL;
}

// -------------------------------------------------------------------
// Forwarded export resolution
// Parse "DLLNAME.FunctionName", resolve the DLL, then the function
// -------------------------------------------------------------------

static PVOID resolve_forwarder(const char* forwarder_str) {
    // copy forwarder string so we can split at the dot
    char buf[256];
    int len = 0;
    while (forwarder_str[len] && len < 255) {
        buf[len] = forwarder_str[len];
        len++;
    }
    buf[len] = 0;

    // find the dot separator
    char* dot = NULL;
    for (int i = 0; i < len; i++) {
        if (buf[i] == '.') {
            dot = &buf[i];
            break;
        }
    }
    if (!dot) return NULL;

    *dot = 0;
    const char* dll_name_a  = buf;
    const char* func_name_a = dot + 1;

    // build wide DLL name with .dll suffix for PEB matching
    wchar_t dll_wide[128];
    int j = 0;
    for (int i = 0; dll_name_a[i] && j < 120; i++, j++)
        dll_wide[j] = (wchar_t)dll_name_a[i];

    // append ".dll"
    dll_wide[j++] = L'.';
    dll_wide[j++] = L'd';
    dll_wide[j++] = L'l';
    dll_wide[j++] = L'l';
    dll_wide[j]   = 0;

    DWORD dll_hash  = dn_crc32b_wide_lower(dll_wide);
    DWORD func_hash = dn_crc32b(func_name_a);

    PVOID mod = dn_get_module_by_hash(dll_hash);
    if (!mod) return NULL;

    return dn_get_proc_by_hash(mod, func_hash);
}

// -------------------------------------------------------------------
// Combined resolution: module hash + function hash -> address
// -------------------------------------------------------------------

PVOID dn_resolve(DWORD module_hash, DWORD func_hash) {
    PVOID mod = dn_get_module_by_hash(module_hash);
    if (!mod) return NULL;
    return dn_get_proc_by_hash(mod, func_hash);
}
