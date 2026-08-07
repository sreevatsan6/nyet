// nyet.c — DNS proxy / sinkhole for Windows
//
// recv query -> parse domain -> check radix-tree blocklist (BLOCKED /
// ALLOWED / REVIEW, suffix-matched) -> block, or forward to whichever
// upstream (WireGuard / home LAN) last proved reachable, with automatic
// sticky fallback -> relay reply -> log.
//
// Architecture:
//   - IOCP + a pool of worker threads (see worker_thread_proc/
//     iocp_worker_loop), not single-threaded -- one thread per query in
//     flight, not one query at a time.
//   - Radix tree keyed root->TLD->...->most-specific label, so blocking
//     a domain blocks every subdomain under it for free via suffix match.
//   - New/unknown domains get an async, rate-limited cross-check against
//     the Pi-hole gravity list (see query_pi_gravity/queue_gravity_check)
//     and, separately, a cheap advisory heuristic score (see
//     heuristics.c) -- the heuristics NEVER block or clear anything on
//     their own, they only decide what's worth a human's attention in
//     review.tsv. The deterministic blocklist + Pi-hole cross-check +
//     human curation loop is the actual decision-making system.
//   - No DNS response cache (every allowed query round-trips to the real
//     upstream resolver every time; only the BLOCKED/ALLOWED/REVIEW
//     *decision* is cached, not the resolved IP).
//   - Can run in the foreground (console visible, live [heur] lines and
//     a shutdown summary -- use this for debugging) or fully detached in
//     the background via --background (see main()).
//
// Build (mingw-w64), from the project root, with heuristics.h/heuristics.c
// in the same directory as this file:
//   gcc src/nyet.c -o nyet.exe -lws2_32 -lkernel32 -lmsvcrt -lwinhttp
//   (mingw's #pragma comment(lib,...) support is inconsistent -- pass
//    -lwinhttp explicitly or the Pi gravity-check linker symbols won't resolve)
//
// uthash.h is included but NOT actually used anywhere in this file --
// kept around in case it's wanted later, safe to omit if you'd rather not
// carry the dependency.
//
// Run (as Administrator — binding port 53 requires it):
//   nyet.exe [--background] <wg_ip> <home_ip> <blocklist_path> <log_path>
//   nyet.exe 192.0.2.1 198.51.100.2 lists/blocklist.tsv nyet.log
//   nyet.exe --background 192.0.2.1 198.51.100.2 lists/blocklist.tsv nyet.log
// Omit --background for console/foreground mode (visible [heur] lines and
// shutdown summary -- use this for live debugging). With --background,
// the process relaunches itself fully detached (no console, survives the
// launching terminal closing) and the original invocation exits.

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>  // offsetof(), used by create_blocked_response's TTL overwrite
#include <stdalign.h> // alignas(), used by QueryContext's raw_query buffer below --
                      // without this include, GCC doesn't recognize `alignas` as a
                      // keyword/macro at all and silently mis-parses the struct member
                      // right out of existence (see QueryContext), which then blows up
                      // every ctx->raw_query use site with "no member named raw_query"
                      // far away from the real cause.
#include <stdbool.h> // bool/true/false, used by is_all_digits() below. This
                      // was previously only available here as a side effect
                      // of #include "heuristics.c" (further down) itself
                      // including <stdbool.h> -- worked, since it's a single
                      // translation unit, but relying on another file's
                      // include to satisfy this one's own types is fragile:
                      // if heuristics.c ever stopped needing stdbool, this
                      // file would break with no local signal why. Included
                      // directly now regardless of what heuristics.c does.
#include <ctype.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>   // Pi gravity-list lookup (see query_pi_gravity)
#include <process.h>
#include <sys/stat.h> // _stat, for reload_thread_proc's mtime polling
// #include "uthash.h" -- see top-of-file note: not actually used anywhere.
#include "heuristics.h" // compute_heuristic_score() -- declaration only
#include "heuristics.c" // ...and its implementation -- advisory-only
#include "radix_tree.h" // real .c compiled+linked separately, see Makefile
#include "dns_cache.h"  // ditto
#include "answer_cache.h" // ditto

#ifdef _MSC_VER
    #pragma comment(lib, "Ws2_32.lib")
#else
    #define _stricmp strcasecmp

    #ifndef _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES
        static inline char* my_strdup(const char *s) { return strdup(s); }
        #define _strdup my_strdup
    #endif
#endif


#define DNS_PORT        53
#define BUFFER_SIZE     4096
#define MAX_DOMAIN_LEN  256

// Per-domain label-count cap (why 128, not some smaller number) lives in
// radix_tree.c next to split_domain_rtl() now, not here.
#define UPSTREAM_TIMEOUT_MS 2000
#define UPSTREAM_FALLBACK_TIMEOUT_MS 300  // hairpin failure is a hard vanish, not a slow reply
// My Epoch = UNIX Epoch + 50 Years
#define DNS_EPOCH 1577836800

// Default TTL handed back on a blocked response, in seconds. Per-domain
// overrides live in the blocklist TSV's `ttl` column (radix_entry_t.ttl,
// see radix_tree.h); 0 there means "not set, use this default" -- see
// create_blocked_response.
#define DEFAULT_BLOCK_TTL_SECONDS 60

// Poll granularity for recv_matching_reply()'s SO_RCVTIMEO -- set once per
// call rather than recomputed on every discarded/mismatched reply. See
// that function for the actual tradeoff.
#define RECV_POLL_INTERVAL_MS 100
// ============================================================
// Data structures
// ============================================================

typedef enum {
    STATUS_BLOCKED,
    STATUS_ALLOWED,
    STATUS_REVIEW
} EntryStatus;

typedef enum {
    SOURCE_STATIC,      // loaded from file at startup
    SOURCE_HEURISTIC,   // auto-flagged at runtime
    SOURCE_MANUAL,       // promoted by hand during review
    SOURCE_PI_GRAVITY    // confirmed against the Pi's gravity list
} EntrySource;

// BlockEntry used to live here -- it's gone. Every entry now lives as a
// radix_entry_t inside radix_tree.c's own tree nodes (see radix_tree.h),
// which is the actual replacement for what this struct + the old inline
// RadixNode tree used to do together. Nothing in this file allocates,
// frees, or passes around a BlockEntry* anymore; load_blocklist(),
// flag_for_review(), and gravity_check_thread() all talk to the tree
// directly via radix_insert()/radix_tree_insert_live() with plain
// scalar arguments instead.

typedef struct {
    // 1. MUST be at the top for CONTAINING_RECORD to work
    WSAOVERLAPPED overlapped;

    // 2. Used by WSARecv to know where to write the data
    WSABUF wsa_buf;

    // 3. Metadata
    struct sockaddr_in client_addr;
    int client_addr_len;
    uint32_t received_at;
    int query_len;            // length of the raw query, filled in after WSARecv completes
    uint16_t qtype;
    char domain[MAX_DOMAIN_LEN];

    // 4. Cache-aligned buffer for the packet data
    alignas(64) unsigned char raw_query[BUFFER_SIZE];
} QueryContext;

typedef enum {
    RESULT_BLOCKED,
    RESULT_ALLOWED,
    RESULT_REVIEW,
    RESULT_FORWARDED,
    RESULT_CACHED,  // answered straight from dns_answer_cache -- no
                     // upstream round-trip at all for this query. See
                     // process_request's cache-hit path.
    RESULT_ERROR
} QueryResult;

typedef enum {
    MATCH_HASH_EXACT,
    MATCH_HASH_SUFFIX,
    MATCH_HEURISTIC,
    MATCH_NONE          // forwarded, no local match at all
} MatchSource;

typedef struct {
    char *data;         // The massive buffer
    size_t capacity;    // Max size (e.g., 65536)
    size_t length;      // Current usage
    time_t last_flush_time; // see flush_log_if_stale() -- the size-based
                            // watermark alone can leave real data sitting
                            // unflushed for a very long time at low query
                            // volume (empirically: over an hour on this
                            // proxy's actual home-network traffic), making
                            // `tail -f` on the log file effectively useless
                            // for live troubleshooting.
} LogBuffer;


// ---- "Have we already asked the Pi about this domain" cache ----
// Simple chained hash set, now with a PENDING/DONE state instead of a bare
// "seen it" flag. Purpose is twofold:
//   1. Stop a hot/noisy domain (e.g. a chatty telemetry host at 20k+ hits)
//      from generating a gravity-list HTTP call on every single query.
//   2. Allow a domain whose ONLY gravity check so far failed with "Pi
//      unreachable" (result == -1) to be retried later, instead of being
//      permanently stuck un-askable for the rest of the process's life.
//      A -1 is not the same claim as "confirmed clean" and shouldn't be
//      cached with the same permanence.
#define ASKED_CACHE_BUCKETS 4096

typedef enum { ASKED_PENDING, ASKED_DONE } AskedState;

typedef struct AskedCacheNode {
    char *domain;
    AskedState state;
    struct AskedCacheNode *next;
} AskedCacheNode;

typedef struct {
    AskedCacheNode *buckets[ASKED_CACHE_BUCKETS];
    CRITICAL_SECTION lock;
} AskedCache;

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

// Call before firing a gravity check. Returns 1 if the caller should go
// ahead and check this domain now (and marks it PENDING so a second,
// concurrent occurrence of the same hot domain doesn't also fire), 0 if
// a check is already in flight OR already completed for this domain.
int asked_cache_try_claim(AskedCache *cache, const char *domain) {
    uint32_t idx = fnv1a(domain) % ASKED_CACHE_BUCKETS;
    int should_fire = 0;

    EnterCriticalSection(&cache->lock);
    AskedCacheNode *n = cache->buckets[idx];
    for (; n; n = n->next) {
        if (strcmp(n->domain, domain) == 0) break;
    }
    if (!n) {
        // Both allocations checked: an unhandled failure here would either
        // crash on a NULL deref or, if it somehow didn't crash, leave the
        // critical section held forever on the way out -- either way every
        // other thread touching this cache deadlocks behind it. Bail out
        // cleanly and release the lock on either failure instead.
        AskedCacheNode *new_node = (AskedCacheNode*)malloc(sizeof(AskedCacheNode));
        if (!new_node) {
            LeaveCriticalSection(&cache->lock);
            return 0; // OOM: treat as "don't fire" rather than crash/deadlock
        }
        new_node->domain = _strdup(domain);
        if (!new_node->domain) {
            free(new_node);
            LeaveCriticalSection(&cache->lock);
            return 0;
        }
        new_node->state = ASKED_PENDING;
        new_node->next = cache->buckets[idx];
        cache->buckets[idx] = new_node;
        should_fire = 1;
    }
    // else: node already exists, whether PENDING (in flight) or DONE
    // (already resolved) -- either way, don't fire again.
    LeaveCriticalSection(&cache->lock);

    return should_fire;
}

// Call after a gravity check completes. `succeeded` should be 0 only for
// the "Pi unreachable" case (query_pi_gravity returned -1) -- a confirmed
// BLOCKED or confirmed CLEAN result both count as succeeded=1, since both
// are real answers that shouldn't be re-asked. On failure, the node is
// removed entirely so the next occurrence of this domain is treated as
// brand new and gets a fresh attempt.
void asked_cache_mark_done(AskedCache *cache, const char *domain, int succeeded) {
    uint32_t idx = fnv1a(domain) % ASKED_CACHE_BUCKETS;

    EnterCriticalSection(&cache->lock);
    AskedCacheNode **link = &cache->buckets[idx];
    while (*link) {
        if (strcmp((*link)->domain, domain) == 0) {
            if (succeeded) {
                (*link)->state = ASKED_DONE;
            } else {
                AskedCacheNode *dead = *link;
                *link = dead->next;
                free(dead->domain);
                free(dead);
            }
            break;
        }
        link = &(*link)->next;
    }
    LeaveCriticalSection(&cache->lock);
}

// ---- Top-level proxy state ----
typedef struct {
    SOCKET local_socket;
    SOCKET upstream_socket;

    // Two upstream resolvers: WireGuard address always works (home or away);
    // home LAN address is faster when actually on the home network, but
    // hairpin NAT means it silently fails when you're elsewhere. Index 0 is
    // WireGuard (safe default), index 1 is home LAN.
    struct sockaddr_in upstream_addrs[2];
    #define UPSTREAM_WG   0
    #define UPSTREAM_HOME 1

    // Which one worked last time. Plain volatile int, not Interlocked --
    // worst case under a race is one query reads a half-updated preference
    // and falls through to the timeout+retry path same as a cold start
    // would. Never a correctness bug, just an occasional wasted retry.
    volatile int preferred_upstream;

    // Real radix_tree_t (radix_tree.c) instead of the inline RadixNode
    // tree -- owns its own SRWLOCK internally, so a separate blocklist
    // lock isn't needed here. Builder/publish/swap model is what makes
    // hot-reload possible: reload_thread_proc() polls blocklist_path's
    // mtime every 5s and calls radix_tree_swap() when it changes (see
    // that function, wired up in main()). Every swap is immediately
    // followed by dns_cache_clear(query_cache) and answer_cache_clear
    // (see below) there too -- without both, a domain you just un-blocked
    // (or re-blocked) via an edited blocklist.tsv would keep serving
    // whatever verdict/answer was cached from the PREVIOUS tree
    // generation until that cache entry's own TTL expired, silently
    // ignoring the reload for however long that takes.
    radix_tree_t blocklist_tree;

    // Verdict cache (BLOCKED/ALLOWED only, never REVIEW/unmatched -- see
    // check_domain) in front of the tree for hot lookups. Genuinely
    // optional -- proxy_init() treats dns_cache_init() failure as
    // non-fatal and leaves this NULL, and every use site below checks
    // for that.
    dns_cache_t *query_cache;

    // Real resolved *answers* (not verdicts) for ALLOWED domains -- see
    // answer_cache.h for the full contract and why this is a separate
    // cache from query_cache above. Also optional/NULL-safe the same way.
    // Populated by process_request() on a real upstream round-trip for
    // an ALLOWED domain; served straight from here on repeat queries
    // without ever touching the upstream resolver again until the real
    // TTL expires. Cleared on every hot-reload swap and on any
    // ALLOWED->BLOCKED transition (gravity promotion), same reasoning as
    // query_cache above -- see reload_thread_proc and
    // gravity_check_thread.
    answer_cache_t *dns_answer_cache;
    char blocklist_path[512]; // retained so the reload thread can re-read it
    char learned_path[512];   // derived from blocklist_path's directory (see proxy_init) --
                              // NOT hardcoded, so a clone with a different blocklist_path
                              // doesn't silently write learned entries into this repo's lists/
    char review_path[512];    // same deal as learned_path above

    HANDLE iocp_handle;
    CRITICAL_SECTION log_lock;
    CRITICAL_SECTION review_lock;
    LogBuffer* log_buffer;
    FILE *log_file;

    // For the Pi-gravity "ask once, cache indefinitely" lookup (see below)
    // (No separate pi_api_host: the gravity check derives its target from
    // upstream_addrs[preferred_upstream] at call time -- see query_pi_gravity.
    // Same physical Pi, same hairpin-NAT reachability story as DNS, so
    // there's no case where they'd need to point at different addresses.)
    AskedCache asked_cache;
} DNSProxy;
// ============================================================
// Small helpers
// ============================================================

// Full 256-entry lowercase lookup table (identity-mapped for non-letters)
// instead of a branch per byte (e.g. `if (c >= 'A' && c <= 'Z') ...`) --
// one array load, no branch to mispredict on mixed-case input.
static const unsigned char LOWER[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
    '@', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '[', '\\', ']', '^', '_',
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

static EntryStatus parse_status(char c) {
    switch (c) {
        case 'B': return STATUS_BLOCKED;
        case 'A': return STATUS_ALLOWED;
        default:  return STATUS_REVIEW;
    }
}

static char status_to_char(EntryStatus s) {
    switch (s) {
        case STATUS_BLOCKED: return 'B';
        case STATUS_ALLOWED: return 'A';
        default:             return 'R';
    }
}

static EntrySource parse_source(char c) {
    switch (c) {
        case 'S': return SOURCE_STATIC;
        case 'H': return SOURCE_HEURISTIC;
        case 'G': return SOURCE_PI_GRAVITY;
        default:  return SOURCE_MANUAL;
    }
}

static char source_to_char(EntrySource s) {
    switch (s) {
        case SOURCE_STATIC:     return 'S';
        case SOURCE_HEURISTIC:  return 'H';
        case SOURCE_PI_GRAVITY: return 'G';
        default:                return 'M';
    }
}

// Used by load_blocklist() to distinguish an optional `ttl` column from
// the free-form `note` column when parsing a blocklist TSV line -- see
// the comment at that call site. Empty string is deliberately NOT
// "all digits" (there's nothing to parse as a TTL there).
static bool is_all_digits(const char *s) {
    if (!s || !s[0]) return false;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) return false;
    }
    return true;
}

// ============================================================
// DNS packet parsing / crafting
// ============================================================

// Parses the question name + qtype out of a raw DNS query packet.
// Returns 1 on success, 0 on malformed packet.
int parse_query(const unsigned char *packet, int size, char *out_domain, int max_len, uint16_t *out_qtype) {
    if (size < 12) return 0;

    const unsigned char *p = packet + 12; // Start after header
    const unsigned char *limit = packet + size;
    char *dst = out_domain;
    char *end = out_domain + max_len - 1; // Reserve space for null terminator

    // Handle the first label specially to avoid the leading dot check
    while (p < limit && *p != 0) {
        int len = *p++;

        // Bounds check once per label. Compares remaining BYTE COUNTS
        // (limit - p, end - dst), not raw pointer addresses -- `len` comes
        // straight from an attacker-controlled packet byte (0-255), and
        // `p + len` on a pointer is undefined behavior if it could ever
        // overflow. Comparing "how many bytes remain" instead of "where do
        // the addresses land" avoids relying on pointer overflow not
        // happening in the first place.
        if (len >= (limit - p) || len >= (end - dst)) return 0;

        // If not the first label, add a dot
        if (dst != out_domain) *dst++ = '.';

        for (int i = 0; i < len; i++) {
            unsigned char lowered = LOWER[*p++];
            // Defense-in-depth on top of the log/path-injection fixes
            // downstream (sanitize_log_field, query_pi_gravity's percent
            // encoding): reject the query outright if any label byte
            // falls outside [a-z0-9-.] once lowercased. This closes the
            // root cause -- unrestricted wire bytes reaching domain
            // strings -- rather than only patching each place that string
            // later gets used. Every real domain seen in practice through
            // this proxy (in-addr.arpa PTRs, hyphenated hostnames, hex
            // CDN prefixes) fits this set; anything that doesn't gets
            // silently dropped (no response) rather than resolved.
            int is_valid = (lowered >= 'a' && lowered <= 'z') ||
                            (lowered >= '0' && lowered <= '9') ||
                            lowered == '-';
            if (!is_valid) return 0;
            *dst++ = (char)lowered;
        }
    }
    *dst = '\0';

    p++; // Skip the terminating zero
    if (p + 2 > limit) return 0;

    // Use memcpy to avoid alignment issues (compiler optimizes this to a single mov anyway)
    uint16_t qtype_raw;
    memcpy(&qtype_raw, p, 2);
    *out_qtype = ntohs(qtype_raw);

    return 1;
}

// Precomputed big-endian constants — no htons() call needed, ever.
// These get embedded as immediate stores by the compiler.
static const uint16_t FLAGS_BE   = 0x8081; // wire bytes: 81 80
static const uint16_t ANSWERS_BE = 0x0100; // wire bytes: 00 01

// Precompute the whole answer payload as a single struct so it's one
// contiguous store instead of a local array + memcpy from stack.
#pragma pack(push, 1)
typedef struct {
    uint16_t name_ptr;   // 0xc0, 0x0c
    uint16_t type;       // 0x00, 0x01
    uint16_t class_;     // 0x00, 0x01
    uint32_t ttl;        // 0x3c
    uint16_t rdlength;   // 0x00, 0x04
    uint32_t addr;       // 0.0.0.0
} dns_answer_t;
#pragma pack(pop)

static const dns_answer_t BLOCKED_ANSWER = {
    .name_ptr = 0x0cc0,        // c0 0c
    .type     = 0x0100,        // 00 01
    .class_   = 0x0100,        // 00 01
    .ttl      = 0x3c000000,    // 00 00 00 3c (60 seconds; )
    .rdlength = 0x0400,        // 00 04
    .addr     = 0x00000000     // 00 00 00 00
};

int create_blocked_response(const unsigned char *restrict request,
                             int request_size,
                             unsigned char *restrict out_response,
                             uint32_t ttl_seconds) {
    memcpy(out_response, request, (size_t)request_size);

    // Single 2-byte immediate stores, no function call, no htons.
    memcpy(out_response + 2, &FLAGS_BE, 2);
    memcpy(out_response + 6, &ANSWERS_BE, 2);

    // One 16-byte store instead of building a local array on the stack
    // and copying it. Still the fast path for the overwhelming majority
    // of blocked queries, which use the default TTL baked into this
    // template.
    memcpy(out_response + request_size, &BLOCKED_ANSWER, sizeof(BLOCKED_ANSWER));

    // Only the chatty-offender minority (TSV `ttl` column set) pays for
    // an extra 4-byte overwrite here -- one branch + one store, still
    // far cheaper than building the whole answer from scratch per query.
    if (ttl_seconds != DEFAULT_BLOCK_TTL_SECONDS) {
        uint32_t ttl_be = htonl(ttl_seconds);
        memcpy(out_response + request_size + offsetof(dns_answer_t, ttl), &ttl_be, sizeof(ttl_be));
    }

    return request_size + (int)sizeof(BLOCKED_ANSWER);
}

// Skips over one (possibly compressed) DNS name and returns the position
// just past it, or NULL if the name runs past `limit`. Only used to find
// where the NEXT field starts in a packet we're walking -- never
// dereferences/follows a compression pointer to resolve what it actually
// points at, so pointer loops (a concern for anything that DOES follow
// them) aren't a concern here.
static const unsigned char *skip_dns_name(const unsigned char *p, const unsigned char *limit) {
    while (p < limit) {
        int len = *p;
        if ((len & 0xC0) == 0xC0) {           // compression pointer: 2 bytes, always ends the name
            return (p + 2 <= limit) ? p + 2 : NULL;
        }
        if (len == 0) return p + 1;           // root label -- name ends here
        p += 1 + len;
    }
    return NULL;
}

// Walks a real upstream reply's answer section looking for A/AAAA records
// matching qtype, for answer_cache_insert. Only ever called for domains
// that already passed the ALLOWED/unmatched-forwarded gate in
// process_request -- this function has no opinion on blocking, it just
// extracts what the upstream actually said. Returns false (and leaves
// *out untouched) if the reply's RCODE isn't NOERROR, if no record
// actually matches qtype/class IN, or if every matching record's TTL
// somehow came back as 0 (answer_cache_insert would reject that anyway --
// checking here avoids the wasted parse-then-reject round-trip).
static bool parse_answer_records(const unsigned char *reply, int reply_len,
                                  uint16_t qtype, answer_cache_answer_t *out) {
    if (reply_len < 12) return false;

    uint8_t rcode = reply[3] & 0x0F;
    if (rcode != 0) return false; // NXDOMAIN/SERVFAIL/etc -- never cache these

    uint16_t qdcount, ancount;
    memcpy(&qdcount, reply + 4, 2); qdcount = ntohs(qdcount);
    memcpy(&ancount, reply + 6, 2); ancount = ntohs(ancount);
    if (ancount == 0) return false;

    const unsigned char *p = reply + 12;
    const unsigned char *limit = reply + reply_len;

    // Skip the question section (the reply echoes what we sent -- qdcount
    // is essentially always 1, but walk whatever the reply actually claims
    // rather than assuming).
    for (uint16_t i = 0; i < qdcount; i++) {
        p = skip_dns_name(p, limit);
        if (!p || p + 4 > limit) return false; // qtype(2) + qclass(2)
        p += 4;
    }

    uint8_t expected_bytes = (qtype == 28) ? 16 : 4; // AAAA=16B, A=4B -- see answer_cache.h
    uint32_t min_ttl = UINT32_MAX;
    uint8_t count = 0;

    for (uint16_t i = 0; i < ancount && count < ANSWER_CACHE_MAX_RECORDS; i++) {
        p = skip_dns_name(p, limit);
        if (!p || p + 10 > limit) break; // type(2)+class(2)+ttl(4)+rdlength(2)

        uint16_t rtype, rclass, rdlength;
        uint32_t rttl;
        memcpy(&rtype, p, 2);      rtype = ntohs(rtype);       p += 2;
        memcpy(&rclass, p, 2);     rclass = ntohs(rclass);     p += 2;
        memcpy(&rttl, p, 4);       rttl = ntohl(rttl);         p += 4;
        memcpy(&rdlength, p, 2);   rdlength = ntohs(rdlength); p += 2;

        if (p + rdlength > limit) break; // malformed -- stop, keep whatever matched so far

        // Only records matching this exact query's qtype get cached --
        // e.g. a CNAME interleaved in the answer chain is skipped over
        // (still need to advance past its rdata below) but never stored.
        if (rtype == qtype && rclass == 1 && rdlength == expected_bytes) {
            memcpy(out->records[count], p, expected_bytes);
            if (rttl < min_ttl) min_ttl = rttl;
            count++;
        }
        p += rdlength;
    }

    if (count == 0 || min_ttl == 0 || min_ttl == UINT32_MAX) return false;

    out->num_records  = count;
    out->record_bytes = expected_bytes;
    out->ttl_seconds  = min_ttl;
    return true;
}

// Synthesizes a DNS response straight from a dns_answer_cache hit --
// same "copy the question section verbatim, append answers" shape
// create_blocked_response uses, generalized to a variable number of real
// records instead of one fixed sinkhole address. Returns the response
// length, or 0 if it wouldn't fit in out_capacity (shouldn't happen in
// practice: ANSWER_CACHE_MAX_RECORDS=8 records at 16B/record is nowhere
// near BUFFER_SIZE, but checked rather than assumed).
static int create_cached_answer_response(const unsigned char *request, int request_size,
                                          unsigned char *out_response, size_t out_capacity,
                                          uint16_t qtype, const answer_cache_answer_t *answer) {
    size_t per_record = 2 + 2 + 2 + 4 + 2 + answer->record_bytes; // name_ptr+type+class+ttl+rdlength+rdata
    size_t needed = (size_t)request_size + (size_t)answer->num_records * per_record;
    if (needed > out_capacity) return 0;

    memcpy(out_response, request, (size_t)request_size);
    memcpy(out_response + 2, &FLAGS_BE, 2);

    uint16_t ancount_be = htons(answer->num_records);
    memcpy(out_response + 6, &ancount_be, 2);

    unsigned char *p = out_response + request_size;
    uint16_t name_ptr_be = 0x0cc0; // c0 0c on the wire -- same compression
                                    // pointer create_blocked_response uses,
                                    // pointing back at the question name
                                    // this packet already carries at offset 12
    uint16_t type_be     = htons(qtype);
    uint16_t class_be    = htons(1); // IN
    uint32_t ttl_be      = htonl(answer->ttl_seconds);
    uint16_t rdlength_be = htons(answer->record_bytes);

    for (int i = 0; i < answer->num_records; i++) {
        memcpy(p, &name_ptr_be, 2); p += 2;
        memcpy(p, &type_be, 2);     p += 2;
        memcpy(p, &class_be, 2);    p += 2;
        memcpy(p, &ttl_be, 4);      p += 4;
        memcpy(p, &rdlength_be, 2); p += 2;
        memcpy(p, answer->records[i], answer->record_bytes); p += answer->record_bytes;
    }

    return (int)(p - out_response);
}


// ============================================================
// Blocklist lookup
// ============================================================

typedef struct {
    EntryStatus status;
    int matched;
    char matched_domain[MAX_DOMAIN_LEN];
    MatchSource source;
    float ml_score;  // Only meaningful when status == STATUS_REVIEW; 0.0
                      // for BLOCKED/ALLOWED entries, which were never
                      // scored by the heuristics pipeline.
    uint32_t ttl;     // Only meaningful when status == STATUS_BLOCKED. 0
                      // means "matched entry had no TTL override" -- caller
                      // is responsible for falling back to
                      // DEFAULT_BLOCK_TTL_SECONDS, this struct just carries
                      // whatever the entry actually said.
} CheckResult;

// How long a cached ALLOWED verdict is trusted for, in seconds. Distinct
// from DEFAULT_BLOCK_TTL_SECONDS/radix_entry_t.ttl on purpose -- that ttl
// means "what TTL to put in the DNS response for a BLOCKED domain," a
// completely different concept from "how long can query_cache trust this
// verdict before re-checking the tree." They happen to share a field name
// (both called "ttl") in dns_cache_insert, but conflating them would mean
// caching ALLOWED verdicts forever (ALLOWED entries always carry ttl=0 in
// this codebase, and dns_cache_insert flatly rejects ttl=0 to avoid an
// immediate-expiry race) -- so ALLOWED gets its own real duration here
// instead of reusing a field that doesn't apply to it.
#define QUERY_CACHE_TTL_SECONDS 300

// dns_answer_cache capacity -- must be a power of 2 (see answer_cache_init).
// 4096 entries * 256B/entry = 1MB, comfortably generous for anything a
// home network has genuinely "hot" at once.
#define ANSWER_CACHE_CAPACITY 4096

CheckResult check_domain(DNSProxy *proxy, const char *raw_domain) {
    CheckResult result = {0};
    result.source = MATCH_NONE;

    // Cache-in-front-of-the-tree, checked first. Only ever populated
    // below for BLOCKED/ALLOWED matches -- REVIEW and "no match at all"
    // are deliberately never cached (see DNSProxy's own comment on
    // query_cache for why: a domain flag_for_review()/gravity_check_thread()
    // promotes moments after this query must never get served a stale
    // "not blocked" answer from here). So a cache hit unambiguously means
    // BLOCKED or ALLOWED -- nothing else to handle.
    if (proxy->query_cache) {
        dns_cache_action_t cached_action;
        uint32_t cached_ttl;
        if (dns_cache_lookup(proxy->query_cache, raw_domain, &cached_action, &cached_ttl)) {
            result.matched = 1;
            result.status  = (cached_action == DNS_ACTION_BLOCK) ? STATUS_BLOCKED : STATUS_ALLOWED;
            // Cache-hit path intentionally does NOT report the tree's
            // own per-domain ttl override here -- cached_ttl is the
            // CACHE's validity duration (see QUERY_CACHE_TTL_SECONDS),
            // not necessarily the same number as the tree entry's
            // response-ttl. For BLOCKED, that's fine: create_blocked_response
            // just needs *a* reasonable ttl, and this is only ever the
            // real per-domain override or DEFAULT_BLOCK_TTL_SECONDS (see
            // where this got inserted below) -- never QUERY_CACHE_TTL_SECONDS
            // itself for a BLOCKED entry.
            result.ttl = (cached_action == DNS_ACTION_BLOCK) ? cached_ttl : 0;
            strncpy_s(result.matched_domain, sizeof(result.matched_domain), raw_domain, _TRUNCATE);
            result.source = MATCH_HASH_SUFFIX;
            // NOTE (known, accepted tradeoff): cache hits do NOT bump the
            // underlying tree entry's hit_count/last_seen -- those only
            // update on an actual radix_lookup() call, which a cache hit
            // skips entirely by design. Once the cache is warm, hit_count
            // undercounts true query volume. Acceptable: hit_count/
            // last_seen were always advisory bookkeeping, never
            // decision-making inputs, and nothing in this codebase reads
            // them to make a blocking decision.
            return result;
        }
    }

    // All tokenization, tree-walking, precedence logic, and hit_count/
    // last_seen atomic bookkeeping now lives in radix_tree.c's
    // radix_lookup() -- independently stress-tested (concurrent
    // readers against a continuously-swapped tree, fault-injected OOM
    // during insert, ASan-clean) rather than reproduced here. This
    // function's whole job now is translating radix_lookup_result_t
    // into this file's own CheckResult shape.
    radix_lookup_result_t r = radix_lookup(&proxy->blocklist_tree, raw_domain);

    if (!r.matched) {
        return result; // matched=0, source=MATCH_NONE, everything else zeroed
                        // -- and NOT cached, on purpose (see above).
    }

    result.matched  = 1;
    result.status   = (EntryStatus)r.status; // enums intentionally share
                                              // numeric values (BLOCKED=0,
                                              // ALLOWED=1, REVIEW=2 on both
                                              // sides) -- see radix_status_t.
    result.ml_score = r.ml_score;
    result.ttl      = r.ttl;

    // matched_domain/source (MatchSource, the e/s/h/n log column) aren't
    // part of radix_lookup_result_t -- they're log-formatting concerns
    // derived from context the caller already has, not tree state.
    // MATCH_HASH_SUFFIX vs MATCH_HASH_EXACT would need radix_lookup to
    // additionally report whether the match was on the full query domain
    // or a shorter ancestor; not threaded through yet, so this collapses
    // both to MATCH_HASH_SUFFIX for now -- fine for logging, doesn't
    // affect blocking behavior at all, which only depends on r.status.
    strncpy_s(result.matched_domain, sizeof(result.matched_domain), raw_domain, _TRUNCATE);
    result.source = MATCH_HASH_SUFFIX;

    // Populate the cache -- BLOCKED/ALLOWED only, never REVIEW (see the
    // cache-hit branch above for why). r.ttl==0 for a BLOCKED entry means
    // "no per-domain override, use the default" (see radix_entry_t.ttl) --
    // resolve that sentinel to the real number here, since dns_cache_insert
    // rejects ttl==0 outright to avoid an immediate-expiry race. ALLOWED
    // entries always carry ttl==0 in this codebase (the field doesn't
    // apply to them at all) -- give those QUERY_CACHE_TTL_SECONDS instead,
    // a genuinely different number for a genuinely different meaning.
    if (proxy->query_cache && result.status != STATUS_REVIEW) {
        dns_cache_action_t action = (result.status == STATUS_BLOCKED) ? DNS_ACTION_BLOCK : DNS_ACTION_ALLOW;
        uint32_t cache_ttl = (result.status == STATUS_BLOCKED)
                                 ? (r.ttl ? r.ttl : DEFAULT_BLOCK_TTL_SECONDS)
                                 : QUERY_CACHE_TTL_SECONDS;
        dns_cache_insert(proxy->query_cache, raw_domain, action, cache_ttl);
        // Return value ignored: a failed insert (e.g. domain longer than
        // dns_cache's MAX_DOMAIN_LEN=253, vs this file's own 256) just
        // means this one domain doesn't get the fast path -- radix_lookup
        // still ran and returned the correct answer either way.
    }

    return result;
}
// ============================================================
// Heuristics (entropy-based flagging) — logs only, never blocks
// ============================================================

// Amazon device telemetry is a known adversarial case for this heuristic:
// it uses long hex-encoded device IDs as the leftmost label, e.g.
// <64-hex-chars>.us-east-1.prod.service.minerva.devices.a2z.com -- note
// the label goes past the usual 63-char DNS limit by using hex characters
// densely rather than base32/base36, which is what HEX_THRESHOLDS below
// is specifically tuned to catch.

// Threshold = floor(0.9 * len)
// Accessing HEX_THRESHOLDS[len] gives you the max hex_count allowed.
// If hex_count > HEX_THRESHOLDS[len], it's telemetry.
static const unsigned char HEX_THRESHOLDS[] = {
    0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 9, 10, 11, 12, 13,
    14, 15, 16, 17, 18, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 54, 55, 56,
    57, 58, 59, 60, 61, 62, 63, 63, 64, 65, 66, 67, 68, 69, 70, 71,
    72, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 81, 82, 83, 84, 85,
    86, 87, 88, 89, 90, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 99,
    100, 101, 102, 103, 104, 105, 106, 107, 108, 108, 109, 110, 111, 112, 113, 114,
    115, 116, 117, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 126, 127, 128,
    129, 130, 131, 132, 133, 134, 135, 135, 136, 137, 138, 139, 140, 141, 142, 143,
    144, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 153, 154, 155, 156, 157,
    158, 159, 160, 161, 162, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 171,
    172, 173, 174, 175, 176, 177, 178, 179, 180, 180, 181, 182, 183, 184, 185, 186,
    187, 188, 189, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 198, 199, 200,
    201, 202, 203, 204, 205, 206, 207, 207, 208, 209, 210, 211, 212, 213, 214, 215,
    216, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 225, 226, 227, 228, 229
};

int is_hex_telemetry(const char *label) {
    unsigned long long len = 0;
    unsigned long long hex_count = 0;

    for (const unsigned char *p = (const unsigned char *)label; *p; p++) {
        len++;
        if (isxdigit(*p)) {
            hex_count++;
        }
    }

    if (len > 30 && len < 256 && hex_count > HEX_THRESHOLDS[len]) {
        return 1;
    }
    return 0;
}


// Precomputed values: log2(n) * 1,048,576
// Using unsigned long long ensures 64-bit width everywhere.
// Floating point math is too expensive
static const unsigned long long L_LOG2[] = {
    0, 0, 1048576, 1661953, 2097152, 2434718, 2710529, 2943724, 3145728, 3323907, 3483294, 3627476, 3759105, 3880192, 3992300, 4096671,
    4194304, 4286015, 4372483, 4454274, 4531870, 4605678, 4676052, 4743298, 4807681, 4869436, 4928768, 4985860, 5040876, 5093962, 5145247, 5194851,
    5242880, 5289430, 5334591, 5378443, 5421059, 5462507, 5502850, 5542145, 5580446, 5617800, 5654254, 5689850, 5724628, 5758625, 5791874, 5824408,
    5856257, 5887449, 5918012, 5947969, 5977344, 6006159, 6034436, 6062195, 6089452, 6116228, 6142538, 6168398, 6193823, 6218828, 6243427, 6267632
};



int is_suspicious_label(const char *label) {
    unsigned char present[64];
    unsigned int freq[256] = {0}; // Frequencies won't exceed 63, int is fine here
    unsigned long long unique_chars = 0;
    unsigned long long len = 0;

    for (const unsigned char *p = (const unsigned char *)label; *p; p++) {
        if (freq[*p] == 0) {
            present[unique_chars++] = *p;
        }
        freq[*p]++;
        len++;
    }

    // RFC 1035 compliance and sanity checks
    if (len < 12) return 0;
    if (len >= 63) return 1; // You decided 63+ is hostile by default

    // Using unsigned long long accumulators for 64-bit register optimization
    unsigned long long sum_f_log2 = 0;
    for (unsigned long long i = 0; i < unique_chars; i++) {
        unsigned long long f = freq[present[i]];
        sum_f_log2 += f * L_LOG2[f];
    }

    // Formula: H = log2(len) - (1/len) * sum(f * log2(f))
    // 3.5 * 1,048,576 = 3670016
    unsigned long long entropy_scaled = L_LOG2[len] - (sum_f_log2 / len);

    return (entropy_scaled > 3670016);
}

// Forward declaration: real definition is further down, next to log_query
// (its original/primary use site), but flag_for_review and
// append_learned_entry both need it earlier in the file.
static void sanitize_log_field(char *out, const char *in, size_t out_size);

#define REVIEW_THRESHOLD 0.5f

void flag_for_review(DNSProxy *proxy, const char *domain, const char *reason, float ml_score) {
    // Only surface to the human-facing review.tsv when the combined score
    // actually crosses the threshold -- a domain that scored low still
    // gets cached below (so it's never re-scored again), just without
    // cluttering review.tsv with things that don't need your attention.
    if (ml_score >= REVIEW_THRESHOLD) {
        // domain is attacker-controlled wire data (see sanitize_log_field's
        // comment near log_query) -- without this, a crafted query could
        // inject extra tab-separated fields or forge additional lines into
        // review.tsv.
        char safe_domain[MAX_DOMAIN_LEN];
        sanitize_log_field(safe_domain, domain, sizeof(safe_domain));

        EnterCriticalSection(&proxy->review_lock);
        FILE *f = fopen(proxy->review_path, "a");
        if (f) {
            time_t now = time(NULL);
            fprintf(f, "REVIEW\t%s\theuristic\t%lld\t%lld\t1\t%s\n",
                    safe_domain, (long long)now, (long long)now, reason);
            fclose(f);
        }
        LeaveCriticalSection(&proxy->review_lock);
    }

    // Always cache the verdict in the tree, high score or low -- this is
    // what actually stops the heuristics pipeline (entropy/consonant/
    // vowel/digit checks + frequent_words) from re-running on every
    // future query for this domain. check_domain already matches BLOCKED
    // *or* REVIEW entries (see its own comment), so this is purely
    // additive; no changes needed there.
    //
    // radix_tree_insert_live(), not radix_insert()+radix_publish() --
    // this is ONE domain being added to the ALREADY-LIVE tree during
    // normal traffic, not a full reload. See radix_tree.h's comment on
    // that function for exactly why the two are different operations.
    // No BlockEntry to alloc/free either: radix_insert_live copies
    // `note` internally (strdup'd inside radix_tree.c), and the caller
    // (here) never owns any heap object that needs cleanup on any path,
    // success or failure.
    uint32_t now = (uint32_t)(time(NULL) - DNS_EPOCH);
    radix_tree_insert_live(&proxy->blocklist_tree, domain, RADIX_STATUS_REVIEW,
                           0, 1, now, SOURCE_HEURISTIC, ml_score, reason);
    // Return value intentionally ignored here, same as the old
    // insert_path call sites' documented OOM-only leak tradeoff: on
    // failure (OOM), this domain just doesn't get cached and will be
    // re-scored on its next query. Not worth handling further -- if
    // allocation is failing, the process has bigger problems than one
    // domain re-running the heuristics pipeline once more.
}

// ---- Overnight debug instrumentation (stdout only, separate from
// dns_queries.log entirely) ----
// Not performance-sensitive by design -- this is meant to be redirected
// via `nyet.exe ... *> debug.log` for a completely independent stream of
// whatever's useful for reviewing how the heuristic ensemble performed
// on real overnight traffic, unconstrained by dns_queries.log's dense
// machine-parseable format.
static CRITICAL_SECTION g_stdout_lock; // guards stdout so concurrent
                                        // worker threads can't interleave
                                        // /garble printed lines

// ============================================================
// Per-source rate limiting -- anti reflection/amplification
// ============================================================
// nyet binds INADDR_ANY:53 and relays replies to whatever source address
// was on the incoming UDP packet -- trivially spoofable, and nothing
// upstream of this caps queries per source. That's the open-resolver
// shape: spoof a victim's IP, this reflects (and for large records,
// amplifies) the answer at them, for perfectly ordinary domains that
// resolve normally -- independent of whether the blocklist itself is
// airtight. This is a minimum-viable per-source token bucket, not full
// DNS Response Rate Limiting (RRL, which throttles by destination +
// answer-similarity and is the real textbook fix -- see BIND/PowerDNS/
// Knot). Good enough to stop a casual/opportunistic reflection attempt;
// a dedicated attacker distributing across many spoofed source IPs
// would still get through per-bucket, since this throttles each source
// independently, not the aggregate.
#define RL_BUCKETS 8192
#define RL_MAX_TOKENS 20        // burst allowance
#define RL_REFILL_PER_SEC 10    // steady-state queries/sec per source IP

// Aggregate cap, independent of source IP -- the per-source bucket above
// throttles each source individually, so a flood spread across many
// distinct (real or spoofed) source IPs, each individually staying under
// RL_REFILL_PER_SEC, sails straight through it. This catches that case.
// 200/sec is comfortably above any real household's DNS traffic (see the
// actual log-derived numbers from troubleshooting this proxy -- normal
// use is nowhere close) but low enough to actually cap CPU burn under a
// genuine flood. Deliberately generous: connecting to public wifi with a
// phone/laptop/etc. doing its own background chatter should never trip
// this, only a real flood should.
#define RL_GLOBAL_MAX_TOKENS 500
#define RL_GLOBAL_REFILL_PER_SEC 200

typedef struct {
    uint32_t ip;
    int tokens;
    uint32_t last_refill;
} RateLimitEntry;

static RateLimitEntry g_rl_table[RL_BUCKETS];
static CRITICAL_SECTION g_rl_lock;
static volatile LONG g_rl_dropped = 0; // for the shutdown summary only

// Global bucket state -- guarded by the same g_rl_lock as the per-source
// table below, not a separate lock. One more check under a lock we're
// already taking on every query, not a new source of contention.
static int g_rl_global_tokens = RL_GLOBAL_MAX_TOKENS;
static uint32_t g_rl_global_last_refill = 0;

// 1 = allow (consumes a token from both the global AND per-source
// buckets), 0 = drop. Hash collisions in the per-source table share a
// budget between whichever source IPs land in the same bucket --
// stricter than true per-IP under collision, never more permissive,
// which is the safe direction for this to fail in.
static int rate_limit_allow(uint32_t src_ip) {
    uint32_t idx = src_ip % RL_BUCKETS;
    uint32_t now = (uint32_t)time(NULL);
    int allow;

    EnterCriticalSection(&g_rl_lock);

    // Global cap checked first and cheaply -- this is what actually stops
    // "many distinct sources, each individually under the radar" style
    // floods, which the per-source bucket alone can't catch. Rejecting
    // here also means a flood doesn't even touch the per-source hash
    // table once the aggregate budget is spent.
    if (now != g_rl_global_last_refill) {
        int refill = (int)(now - g_rl_global_last_refill) * RL_GLOBAL_REFILL_PER_SEC;
        g_rl_global_tokens = (g_rl_global_tokens + refill > RL_GLOBAL_MAX_TOKENS)
                                  ? RL_GLOBAL_MAX_TOKENS : g_rl_global_tokens + refill;
        g_rl_global_last_refill = now;
    }
    if (g_rl_global_tokens <= 0) {
        LeaveCriticalSection(&g_rl_lock);
        return 0;
    }

    RateLimitEntry *e = &g_rl_table[idx];
    if (e->ip != src_ip) {
        // First packet from this source in this bucket (or a collision
        // evicting whoever was here before) -- reset to a fresh bucket
        // rather than inheriting a stranger's token count.
        e->ip = src_ip;
        e->tokens = RL_MAX_TOKENS;
        e->last_refill = now;
    } else if (now != e->last_refill) {
        int refill = (int)(now - e->last_refill) * RL_REFILL_PER_SEC;
        e->tokens = (e->tokens + refill > RL_MAX_TOKENS) ? RL_MAX_TOKENS : e->tokens + refill;
        e->last_refill = now;
    }
    allow = e->tokens > 0;
    if (allow) {
        e->tokens--;
        g_rl_global_tokens--; // only spend a global token if the query
                               // actually gets through both checks
    }
    LeaveCriticalSection(&g_rl_lock);

    return allow;
}

static volatile LONG g_heuristic_total_scored     = 0;
static volatile LONG g_heuristic_flagged_review   = 0;
static volatile LONG g_score_histogram[10]        = {0}; // buckets: [0]=0.0-0.1 ... [9]=0.9-1.0

// Runs the full combined heuristic/ML pipeline (see heuristics.c) on the
// WHOLE domain -- not just its leftmost label anymore. compute_heuristic_score()
// now scores every non-TLD label itself (and several domain-wide shape
// signals besides), so truncating to the first label here would just
// throw away everything past the first dot before it ever reached the
// engine. Only runs on queries that already missed the blocklist AND
// have no existing tree entry at all (see process_request's gate), so
// this never re-runs for a domain once it's been scored -- flag_for_review
// caches the verdict regardless of score.
void run_heuristics(DNSProxy *proxy, const char *domain) {
    char reason[220];
    float score = compute_heuristic_score(domain, reason, sizeof(reason));

    // ---- Overnight debug instrumentation (stdout, NOT dns_queries.log) ----
    // This is the one place every never-before-seen domain gets scored,
    // exactly once -- ideal spot for a per-domain event line, since
    // volume is naturally bounded by unique domains, not query volume.
    // reason already contains the full per-signal breakdown
    // (entropy=.. consonant=.. vowel=.. digit=.. words=.. final=..) --
    // previously that only ever reached review.tsv, and only for domains
    // crossing REVIEW_THRESHOLD. Printing it here for EVERY scored domain
    // is what actually lets you see which specific check is responsible
    // when the ensemble gets something wrong, not just the final number.
    InterlockedIncrement(&g_heuristic_total_scored);
    int bucket = (int)(score * 10.0f);
    if (bucket > 9) bucket = 9;
    if (bucket < 0) bucket = 0;
    InterlockedIncrement(&g_score_histogram[bucket]);
    int crosses_threshold = (score >= REVIEW_THRESHOLD);
    if (crosses_threshold) InterlockedIncrement(&g_heuristic_flagged_review);

    EnterCriticalSection(&g_stdout_lock);
    printf("[heur] %-45s %s | %s\n", domain,
           crosses_threshold ? "REVIEW" : "clean ", reason);
    LeaveCriticalSection(&g_stdout_lock);

    flag_for_review(proxy, domain, reason, score);
}

// ============================================================
// Pi gravity-list cross-reference ("ask once, cache indefinitely")
// ============================================================
// Runs entirely off the query hot path: queue_gravity_check spawns a
// short-lived thread per NEW domain (deduped by asked_cache, so this is
// genuinely once-per-domain, not once-per-query) that does one blocking
// HTTP call to the Pi and, if confirmed, promotes the domain to BLOCKED
// in the live radix tree. Nothing here ever runs inline between recvfrom
// and sendto for an actual DNS query.
//
// NOTE: the exact request path/response shape below targets Pi-hole's API
// -- verify against your actual Pi-hole major version (v5's admin/api.php
// vs v6's /api/ have different routes and response JSON) and adjust the
// path + the strstr check accordingly before relying on this.
typedef struct {
    DNSProxy *proxy;
    char domain[MAX_DOMAIN_LEN];
} GravityCheckArgs;

// Small hand-rolled check: is the named JSON array present-and-non-empty in
// this response? Not a real parser -- just enough to answer one boolean
// question without pulling in a JSON library for it. Tolerates an optional
// space after the colon since we don't know for certain whether FTL's
// output is always fully compact.
static int json_array_nonempty(const char *json, const char *key) {
    char needle[32];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *pos = strstr(json, needle);
    if (!pos) return 0; // key not found at all -- treat as "no match"

    pos += strlen(needle);
    while (*pos == ' ') pos++;
    if (*pos != '[') return 0;
    pos++;
    while (*pos == ' ') pos++;
    return *pos != ']'; // non-empty iff something appears before the close
}

// Returns 1 if the Pi's gravity/exact/regex lists match this domain, 0 if
// confirmed clean, -1 if the Pi couldn't be reached at all (network down,
// Pi rebooting, etc -- NOT the same as "confirmed clean", so callers must
// not treat -1 as allow).
//
// Uses /api/search/<domain> (path segment, NOT ?term=<domain> as a query
// param -- confirmed by hand against a real Pi-hole instance, see below),
// which Pi-hole v6 documents as unauthenticated --
// no login/SID/session handling needed for this read-only lookup.
//
// Target host is derived from proxy->upstream_addrs[preferred_upstream] --
// same address DNS forwarding has already proven reachable right now, since
// the hairpin-NAT reachability story is identical for UDP:53 and HTTP:80
// against the same physical Pi. No separate "API host" config needed.
int query_pi_gravity(DNSProxy *proxy, const char *domain) {
    int result = -1;

    char pi_api_host[INET_ADDRSTRLEN];
    struct sockaddr_in *addr = &proxy->upstream_addrs[proxy->preferred_upstream];
    inet_ntop(AF_INET, &addr->sin_addr, pi_api_host, sizeof(pi_api_host));

    HINTERNET hSession = WinHttpOpen(L"nyet-gravity-check/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return -1;

    // Deliberately short: this must never stall the caller thread for long,
    // and it's already off the DNS hot path so there's no rush either way.
    WinHttpSetTimeouts(hSession, 1000, 1000, 1000, 1000);

    wchar_t wide_host[INET_ADDRSTRLEN];
    MultiByteToWideChar(CP_UTF8, 0, pi_api_host, -1, wide_host, INET_ADDRSTRLEN);

    HINTERNET hConnect = WinHttpConnect(hSession, wide_host, INTERNET_DEFAULT_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return -1; }

    // domain comes from parse_query, which bounds LENGTH but not which
    // BYTE VALUES a label may contain (see parse_query's comments) -- a
    // crafted query can produce a domain string containing '/', '?', '..',
    // etc. Unescaped, that could restructure the request path (e.g. a
    // domain containing "../" reaching an unintended endpoint on this same
    // Pi-hole instance -- WinHttpConnect already pins host+port so this
    // can't pivot to a DIFFERENT server, but it's not sandboxed to just
    // the search endpoint either without this). Percent-encode only the
    // bytes that could actually restructure the path/query (/ ? # % \ and
    // non-ASCII/control bytes) -- confirmed via direct curl testing that
    // dots and normal domain characters need no encoding for this specific
    // endpoint, so this targets exactly the injection-capable bytes rather
    // than over-encoding everything.
    char encoded_domain[MAX_DOMAIN_LEN * 3]; // worst case: every byte escapes to %XX
    size_t enc_len = 0;
    for (const char *s = domain; *s && enc_len + 4 < sizeof(encoded_domain); s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '/' || c == '?' || c == '#' || c == '%' || c == '\\' ||
            c < 0x20 || c > 0x7E) {
            enc_len += snprintf(encoded_domain + enc_len, 4, "%%%02X", c);
        } else {
            encoded_domain[enc_len++] = (char)c;
        }
    }
    encoded_domain[enc_len] = '\0';

    wchar_t wide_domain[MAX_DOMAIN_LEN * 3];
    MultiByteToWideChar(CP_UTF8, 0, encoded_domain, -1, wide_domain, MAX_DOMAIN_LEN * 3);

    wchar_t path[MAX_DOMAIN_LEN * 3 + 32];
    // Confirmed against the real Pi-hole instance: /api/search?term=... is
    // NOT the actual endpoint (always returns "No search term provided",
    // regardless of encoding -- the docs describing ?term= were wrong/for
    // a different version). The real endpoint takes the domain as a path
    // segment: /api/search/<domain>, dots included, no encoding needed.
    _snwprintf_s(path, sizeof(path) / sizeof(path[0]), _TRUNCATE, L"/api/search/%s", wide_domain);

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return -1; }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        && WinHttpReceiveResponse(hRequest, NULL)) {
        char buffer[4096];
        DWORD bytes_read = 0;
        if (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytes_read)) {
            buffer[bytes_read] = '\0';
            // Matched if ANY of the three arrays actually has entries.
            // (We don't currently distinguish gravity vs exact/regex --
            // both mean "the Pi considers this blocked" for our purposes.
            // Worth splitting later if you want SOURCE_PI_GRAVITY to only
            // mean "caught by a subscribed list" specifically.)
            // Real response shape (confirmed against the actual Pi, not
            // just the docs): {"search":{"domains":[...],"gravity":[...],
            // "results":{"domains":{"exact":N,"regex":N},...}}}. "exact"
            // and "regex" only ever appear as COUNTS nested under results,
            // never as arrays -- checking for them as array keys (the
            // docs' framing) never matches anything. The two real arrays
            // to check are "domains" (custom exact/regex list matches) and
            // "gravity" (subscribed blocklist matches).
            result = (json_array_nonempty(buffer, "domains") ||
                      json_array_nonempty(buffer, "gravity")) ? 1 : 0;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

// Append one confirmed-by-Pi entry to the permanent learned list, in the
// same tab-separated shape load_blocklist() already knows how to read.
// Kept as its own file (not blocklist.tsv) so auto-learned entries never
// mix with your hand-curated ones -- source_to_char already tags these
// 'G' so even if you later cat them together, the provenance survives.
void append_learned_entry(DNSProxy *proxy, EntryStatus status, EntrySource source,
                          uint32_t first_seen, uint32_t last_seen, uint32_t hit_count,
                          uint32_t ttl, const char *domain) {
    // Especially important here vs review.tsv: this file gets loaded back
    // automatically by load_blocklist() on the NEXT startup and its
    // entries are trusted as real blocklist data. An unsanitized newline
    // here could forge an entirely fabricated extra line that silently
    // becomes a trusted SOURCE_PI_GRAVITY entry after a restart.
    char safe_domain[MAX_DOMAIN_LEN];
    sanitize_log_field(safe_domain, domain, sizeof(safe_domain));

    EnterCriticalSection(&proxy->review_lock); // reused: both are rare, small, file-append ops
    FILE *f = fopen(proxy->learned_path, "a");
    if (f) {
        // Includes the `ttl` column (see the blocklist TSV format doc)
        // so this file round-trips through the same parser correctly.
        // Gravity-confirmed entries never set a TTL override, so this is
        // always 0 ("use DEFAULT_BLOCK_TTL_SECONDS") today -- written
        // explicitly rather than omitted so the column position stays
        // fixed for any future entry that does carry a real value.
        fprintf(f, "%c\t%s\t%c\t%lld\t%lld\t%u\t%u\t%s\n",
                status_to_char(status), safe_domain,
                source_to_char(source),
                (long long)first_seen, (long long)last_seen,
                hit_count, ttl, "pi_gravity_confirmed");
        fclose(f);
    }
    LeaveCriticalSection(&proxy->review_lock);
}

// Bounds how many gravity_check_thread instances can be in flight at once.
// Without this, every distinct new domain (trivially generated by anything
// that can send this proxy DNS queries, e.g. random1.evil.com,
// random2.evil.com, ...) spins up a brand new OS thread with no cap --
// asked_cache dedupes REPEATS of the same domain, but does nothing to
// bound how many DIFFERENT domains can have threads in flight
// simultaneously. Each thread reserves real stack + kernel object
// overhead; a burst of many distinct new subdomains could exhaust that
// fast. A counting semaphore blocks (briefly, on the caller's own thread
// pool worker, not forever) rather than creating unboundedly.
#define MAX_CONCURRENT_GRAVITY_CHECKS 8
static HANDLE g_gravity_check_semaphore = NULL; // initialized in proxy_init

unsigned __stdcall gravity_check_thread(void *arg) {
    GravityCheckArgs *args = (GravityCheckArgs*)arg;

    int result = query_pi_gravity(args->proxy, args->domain);

    if (result == 1) {
        uint32_t now = (uint32_t)(time(NULL) - DNS_EPOCH);

        // radix_tree_insert_live(), same as flag_for_review -- one
        // domain, added to the ALREADY-LIVE tree mid-traffic, not a
        // full reload. No BlockEntry alloc needed: note is NULL here
        // (gravity confirmations never carry a note), and every other
        // field is a plain scalar passed straight through.
        int rc = radix_tree_insert_live(&args->proxy->blocklist_tree, args->domain,
                                        RADIX_STATUS_BLOCKED, 0, 1, now,
                                        SOURCE_PI_GRAVITY, 0.0f, NULL);

        // This domain may have already been serving cached answers out of
        // dns_answer_cache (it was unmatched/forwarded right up until this
        // exact moment) -- without this, an in-flight promotion to
        // BLOCKED wouldn't take effect for this domain until whatever
        // answer was already cached hit its own real TTL and expired on
        // its own, silently ignoring the promotion for however long that is.
        if (args->proxy->dns_answer_cache) {
            answer_cache_invalidate(args->proxy->dns_answer_cache, args->domain);
        }

        if (rc == 0) {
            // Persist so this survives past this run -- see load_blocklist(proxy, proxy->learned_path)
            // call in proxy_init, which reloads this file alongside the main blocklist at startup.
            append_learned_entry(args->proxy, STATUS_BLOCKED, SOURCE_PI_GRAVITY,
                                 now, now, 1, 0, args->domain);
        }
        // rc != 0 (OOM): same acceptable tradeoff as before -- this one
        // domain doesn't get promoted this time, no BlockEntry to leak
        // since none was ever allocated to begin with.
    }

    // result == 1 (blocked, handled above) or 0 (confirmed clean): this is
    // a real answer, mark DONE so we never ask again.
    // result == -1 (Pi unreachable, e.g. asked while WireGuard was still
    // preferred right before a fallback to home LAN): NOT a real answer --
    // remove from asked_cache entirely so the next occurrence of this
    // domain gets a fresh attempt, likely against whichever upstream is
    // preferred by then.
    asked_cache_mark_done(&args->proxy->asked_cache, args->domain, result != -1);

    free(args);
    ReleaseSemaphore(g_gravity_check_semaphore, 1, NULL); // matches the WaitForSingleObject in queue_gravity_check
    return 0;
}

// Fire-and-forget: spawns a thread and returns immediately. Never called
// from the hot path directly -- always gated by asked_cache_try_claim
// so it only fires once per unique domain per process lifetime.
void queue_gravity_check(DNSProxy *proxy, const char *domain) {
    // Non-blocking check: if we're already at the cap, skip this occurrence
    // entirely rather than stalling the calling worker thread (which is
    // also busy serving live DNS traffic). asked_cache_mark_done was never
    // called for this domain since we never actually claimed/attempted it,
    // so it stays PENDING... actually it WAS claimed via asked_cache_try_claim
    // before this function is ever called (see process_request) -- so on
    // a skip here, explicitly release that claim so the domain gets a
    // fresh attempt next time it's seen, instead of being stuck PENDING
    // forever with no thread ever actually running for it.
    if (WaitForSingleObject(g_gravity_check_semaphore, 0) != WAIT_OBJECT_0) {
        asked_cache_mark_done(&proxy->asked_cache, domain, 0); // 0 = not succeeded -> retry later
        return;
    }

    GravityCheckArgs *args = (GravityCheckArgs*)malloc(sizeof(GravityCheckArgs));
    if (!args) {
        ReleaseSemaphore(g_gravity_check_semaphore, 1, NULL);
        return;
    }

    args->proxy = proxy;
    strncpy_s(args->domain, sizeof(args->domain), domain, _TRUNCATE);

    HANDLE h = (HANDLE)_beginthreadex(NULL, 0, gravity_check_thread, args, 0, NULL);
    if (h) {
        CloseHandle(h); // detach; thread frees `args` itself when done
    } else {
        free(args);
        ReleaseSemaphore(g_gravity_check_semaphore, 1, NULL);
    }
}

// Sequential file read -- runs once at startup, not a hot path (the
// actual per-query cost is dominated by syscalls/locks, not blocklist
// loading), so multithreading this wouldn't meaningfully help. Left
// single-threaded on purpose, not as an open TODO.
// Parses one TSV file (blocklist.tsv OR learned.tsv -- same format) and
// inserts every row into `builder` via radix_insert(). Deliberately does
// NOT touch a live DNSProxy/radix_tree_t or call radix_publish()/
// radix_tree_swap() itself: this function gets called TWICE at startup
// (once for blocklist.tsv, once for learned.tsv) into the SAME builder,
// and the whole point is both files end up in one tree published/swapped
// ONCE, not two separate trees where the second call's publish would
// discard the first. The caller (proxy_init at startup, and separately
// reload_thread_proc for hot-reload -- see that function) owns exactly
// one radix_publish()/radix_tree_swap() call after both loads finish.
int load_blocklist(radix_tree_builder_t *builder, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[1024];
    int loaded = 0;

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        // fgets stops at 1023 chars + null if a line is longer than that --
        // it doesn't error, it just silently hands back a truncated line,
        // which strtok_s would then happily mis-parse as if it were a
        // complete (but malformed) record. A missing trailing '\n' after a
        // full read means this line was cut off; warn and skip the
        // leftover remainder so it isn't misread as the start of the next
        // record.
        size_t line_len = strlen(line);
        if (line_len == sizeof(line) - 1 && line[line_len - 1] != '\n') {
            fprintf(stderr, "[nyet] warning: %s has a line longer than %zu bytes, truncated -- skipping\n",
                    path, sizeof(line) - 1);
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n') {} // consume the rest of this oversized line
            continue;
        }

        char *next_token;
        char *status_s = strtok_s(line, "\t", &next_token);
        char *domain_s = strtok_s(NULL, "\t", &next_token);
        char *source_s = strtok_s(NULL, "\t", &next_token);
        char *first_s  = strtok_s(NULL, "\t", &next_token); // parsed for compat but not
                                                             // stored anywhere anymore --
                                                             // see radix_entry_t; first_seen
                                                             // was never read back out of a
                                                             // live tree entry, only ever
                                                             // written to a fresh row at
                                                             // insert time, so it doesn't
                                                             // need to round-trip through
                                                             // the tree at all.
        char *last_s   = strtok_s(NULL, "\t", &next_token);
        char *hits_s   = strtok_s(NULL, "\t", &next_token);

        // Optional `ttl` column, inserted between hit_count and note.
        // Sniffed rather than assumed present, so old-format TSVs (six
        // columns, no ttl) still load correctly: grab the next
        // \t-delimited token and check whether it's purely digits. If so,
        // it's the ttl column and note is whatever comes after (captured
        // to end-of-line, preserving any tabs it might legitimately
        // contain). If not (or it's empty/missing), there was never a ttl
        // column on this line -- that token is the FIRST FRAGMENT of the
        // note, cut short at whatever tab (if any) happens to be inside
        // it, since it was already pulled out with a \t-delimited
        // strtok_s above before we knew there was no ttl column to find.
        // Reattach whatever comes after that tab rather than silently
        // dropping it -- the old parser (strtok_s(NULL, "\r\n", ...)
        // directly, no \t split at all) never truncated a note this way,
        // so this has to reconstruct that same behavior, not just avoid
        // making it worse.
        char *ttl_s  = NULL;
        char *note_s = NULL;
        char note_buf[512];
        char *next_field = strtok_s(NULL, "\t", &next_token);
        if (next_field && is_all_digits(next_field)) {
            ttl_s  = next_field;
            note_s = strtok_s(NULL, "\r\n", &next_token);
        } else if (next_field) {
            char *note_rest = strtok_s(NULL, "\r\n", &next_token);
            if (note_rest) {
                // There was a literal tab inside this old-format note --
                // strtok_s already ate it as the delimiter, so put it
                // back rather than lose everything after it.
                _snprintf_s(note_buf, sizeof(note_buf), _TRUNCATE, "%s\t%s", next_field, note_rest);
                note_s = note_buf;
            } else {
                note_s = next_field; // no tab was actually in this note
            }
        }

        if (!status_s || !domain_s) continue;

        EntryStatus status = parse_status(status_s[0]);
        EntrySource source = source_s ? parse_source(source_s[0]) : SOURCE_STATIC;
        uint32_t last_seen  = last_s  ? (uint32_t)atoll(last_s)  : (uint32_t)(time(NULL) - DNS_EPOCH);
        uint32_t hit_count  = hits_s  ? (uint32_t)atoi(hits_s)   : 0;
        uint32_t ttl        = ttl_s   ? (uint32_t)atoll(ttl_s)   : 0; // 0 == "use DEFAULT_BLOCK_TTL_SECONDS"
        (void)first_s; // see comment above -- parsed, deliberately discarded

        // No _strdup here anymore: radix_insert() copies `note` internally
        // (see radix_tree.c's insert_path) -- passing note_s straight
        // through avoids an extra allocation this file used to do for
        // no reason other than the OLD tree's unowned-note contract.
        radix_insert(builder, domain_s, (radix_status_t)status, ttl,
                    hit_count, last_seen, (uint8_t)source, 0.0f,
                    (note_s && note_s[0]) ? note_s : NULL);

        loaded++;
    }

    fclose(f);
    return loaded;
}


// ============================================================
// Logging
// ============================================================

// QueryPerformanceFrequency is constant for the life of the process (per
// MS docs) -- cache it once instead of a syscall on every single latency
// calculation. Set in main() before any query processing begins.
static LARGE_INTEGER g_qpc_frequency;

// Was a deliberate stub (return 0) since early in this file's history --
// every latency in the log has read 0.0 because of it, not because of
// anything more interesting. Implemented for real now: elapsed time in
// whole MICROSECONDS (not fractional milliseconds), computed with pure
// integer math against the cached g_qpc_frequency, consistent with the
// no-floats-on-the-hot-path discipline used elsewhere (recv_matching_reply,
// etc). Multiplying by 1,000,000 before dividing (rather than dividing
// first) avoids losing precision to integer truncation.
long long calculate_latency(LARGE_INTEGER t_start, LARGE_INTEGER t_end) {
    if (g_qpc_frequency.QuadPart == 0) return 0; // frequency not yet initialized
    long long elapsed_ticks = t_end.QuadPart - t_start.QuadPart;
    return (elapsed_ticks * 1000000LL) / g_qpc_frequency.QuadPart;
}

// Pre-allocate these buffers at startup
// How long real (unflushed) log data is allowed to sit in memory before
// a flush happens regardless of the size watermark. 60s by default --
// edit this one constant if you want tighter/looser live-tailing
// latency; nothing else needs to change.
#define LOG_FLUSH_INTERVAL_SECONDS 60

void init_log_buffer(LogBuffer *buf, size_t capacity) {
    buf->data = (char*)malloc(capacity);
    buf->capacity = capacity;
    buf->length = 0;
    buf->last_flush_time = time(NULL);
}

// Thread-safe append to the big buffer
// NOTE: proxy->log_buffer is a LogBuffer* (see DNSProxy struct), so this uses
// -> throughout, not . — using . on a pointer is a compile error in C.
void append_log(DNSProxy *proxy, const char *formatted_log) {
    size_t len = strlen(formatted_log);

    EnterCriticalSection(&proxy->log_lock);

    // Flush if we don't have enough space for the new log + buffer (keep a safety margin)
    if (proxy->log_buffer->length + len >= proxy->log_buffer->capacity - 128) {
        // "One combined big dump"
        fprintf(proxy->log_file, "%s", proxy->log_buffer->data);
        fflush(proxy->log_file);
        proxy->log_buffer->length = 0;
        proxy->log_buffer->last_flush_time = time(NULL);
    }

    memcpy(proxy->log_buffer->data + proxy->log_buffer->length, formatted_log, len);
    proxy->log_buffer->length += len;
    proxy->log_buffer->data[proxy->log_buffer->length] = '\0'; // Keep null terminated

    LeaveCriticalSection(&proxy->log_lock);
}

// Time-based flush, complementing append_log's size-based one above.
// Meant to be polled periodically (see reload_thread_proc's loop) rather
// than triggered per-query -- this is a "is it stale, flush if so" check,
// cheap enough to call every few seconds without it mattering.
//
// Skips the flush entirely when length==0 (nothing to write, don't
// bother touching the file/lock for no reason) -- this also means
// last_flush_time only ever advances when there's real unflushed data
// sitting around, not on every poll, which is exactly what we want: an
// idle proxy with nothing new to log shouldn't reset the clock on data
// that's actually still waiting to be written.
void flush_log_if_stale(DNSProxy *proxy) {
    EnterCriticalSection(&proxy->log_lock);

    if (proxy->log_buffer->length > 0 &&
        (time(NULL) - proxy->log_buffer->last_flush_time) >= LOG_FLUSH_INTERVAL_SECONDS) {
        fprintf(proxy->log_file, "%s", proxy->log_buffer->data);
        fflush(proxy->log_file);
        proxy->log_buffer->length = 0;
        proxy->log_buffer->last_flush_time = time(NULL);
    }

    LeaveCriticalSection(&proxy->log_lock);
}

// domain (and, less critically, client_ip) come from attacker-controlled
// wire data -- parse_query's length-prefixed label decoding doesn't
// restrict label bytes to printable ASCII. Without this, a crafted query
// containing a raw newline in a "domain" label could forge an entire fake
// log line after it (classic log injection). Escapes control characters
// visibly (\n, \t, \xHH) rather than silently collapsing them to '.', so
// something genuinely weird in a query is still visible for triage instead
// of being indistinguishable from a normal dot.
static void sanitize_log_field(char *out, const char *in, size_t out_size) {
    size_t written = 0;
    for (; *in && written + 1 < out_size; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '\n') {
            if (written + 2 >= out_size) break;
            out[written++] = '\\'; out[written++] = 'n';
        } else if (c == '\r') {
            if (written + 2 >= out_size) break;
            out[written++] = '\\'; out[written++] = 'r';
        } else if (c == '\t') {
            if (written + 2 >= out_size) break;
            out[written++] = '\\'; out[written++] = 't';
        } else if (isprint(c)) {
            out[written++] = (char)c;
        } else {
            if (written + 4 >= out_size) break;
            written += snprintf(out + written, 5, "\\x%02X", c);
        }
    }
    out[written] = '\0';
}

// Dense, machine-first log format -- not meant to be read directly, meant
// to be small and cheap to both write and later parse with a script.
// Tab-separated fixed fields, single-char status/source codes, unix epoch
// instead of a formatted date string (skips strftime entirely), integer
// microseconds instead of a float millisecond string. Schema (one line,
// written once when the log file is first opened, not per-entry):
//   epoch<TAB>client_ip<TAB>domain<TAB>qtype<TAB>status<TAB>source<TAB>reason<TAB>latency_us
// status: B=blocked A=allowed R=review F=forwarded C=cached_answer E=error
// source: e=hash_exact s=hash_suffix h=heuristic n=none
void log_query(DNSProxy *proxy, const char *client_ip, const char *domain,
               uint16_t qtype, QueryResult result, MatchSource source,
               const char *reason, long long latency_us) {
    if (!proxy->log_file) return;

    char result_c;
    switch (result) {
        case RESULT_BLOCKED:   result_c = 'B'; break;
        case RESULT_ALLOWED:   result_c = 'A'; break;
        case RESULT_REVIEW:    result_c = 'R'; break;
        case RESULT_FORWARDED: result_c = 'F'; break;
        case RESULT_CACHED:    result_c = 'C'; break;
        default:                result_c = 'E'; break;
    }

    char source_c;
    switch (source) {
        case MATCH_HASH_EXACT:  source_c = 'e'; break;
        case MATCH_HASH_SUFFIX: source_c = 's'; break;
        case MATCH_HEURISTIC:   source_c = 'h'; break;
        default:                source_c = 'n'; break;
    }

    // domain and client_ip are attacker-influenceable (see
    // sanitize_log_field above) -- reason is not (it's always one of our
    // own fixed strings, never wire data), so it's left as-is.
    char safe_domain[MAX_DOMAIN_LEN];
    char safe_ip[INET_ADDRSTRLEN * 2]; // headroom for escape sequences
    sanitize_log_field(safe_domain, domain, sizeof(safe_domain));
    sanitize_log_field(safe_ip, client_ip, sizeof(safe_ip));

    char log_entry[512];
    int n = snprintf(log_entry, sizeof(log_entry),
            "%lld\t%s\t%s\t%u\t%c\t%c\t%s\t%lld\n",
            (long long)time(NULL), safe_ip, safe_domain, qtype, result_c, source_c,
            (reason ? reason : ""), latency_us);

    // 2. Lock Hot: Just copy the memory to the batcher (fast, thread-safe)
    if (n > 0) {
        append_log(proxy, log_entry);
    }
}


// ============================================================
// Core request handling -- called once per completed receive, from
// whichever IOCP worker thread picked it up (see iocp_worker_loop). Each
// individual call runs sequentially top-to-bottom; concurrency comes from
// multiple worker threads each running this function for different
// queries at once, not from anything inside this function itself.
// ============================================================
// Forward declarations: bodies are defined further down the file, but the
// worker loop below calls them first. 'running' is likewise defined near
// main() at the bottom but referenced here — declare it now, define it once.
extern volatile int running;
void process_request(DNSProxy *proxy, QueryContext *ctx);
void post_recv(DNSProxy *proxy, QueryContext *ctx);
void queue_gravity_check(DNSProxy *proxy, const char *domain);

void iocp_worker_loop(DNSProxy *proxy, HANDLE iocp_handle) {
    DWORD bytes;
    ULONG_PTR key;
    LPOVERLAPPED overlapped;

    while (running) {
        // This is the new "blocking" point.
        // No threads are busy-waiting, they are suspended by the kernel.
        BOOL success = GetQueuedCompletionStatus(iocp_handle, &bytes, &key, &overlapped, INFINITE);

        // A NULL overlapped means GQCS itself failed before dequeuing
        // anything (e.g. the IOCP handle was closed) -- there's no ctx to
        // recover in that case, so this is the one situation where skipping
        // is actually correct.
        if (overlapped == NULL) continue;

        // Retrieve the context that the kernel just finished with -- this
        // MUST happen before the success/bytes check below. Every ctx we
        // don't re-post via post_recv() permanently removes one of the
        // ~50 pre-allocated receive slots from rotation. A transient
        // failure here (network blip, adapter change during the WG/home
        // switch, laptop sleep/wake) used to silently drain the pool one
        // slot at a time; once all 50 are gone, GetQueuedCompletionStatus
        // has nothing left to ever deliver again and the proxy goes
        // silently, fully dead -- exactly the "runs fine for ~15 min then
        // stops routing, no crash log, restart fixes it" symptom.
        QueryContext *ctx = CONTAINING_RECORD(overlapped, QueryContext, overlapped);

        if (!success || bytes == 0) {
            post_recv(proxy, ctx); // re-arm the slot instead of abandoning it
            continue;
        }

        ctx->query_len = bytes;

        // Business Logic
        process_request(proxy, ctx);

        // Crucial: Re-prime the socket for the next packet
        post_recv(proxy, ctx);
    }
}

// Each worker thread gets its OWN upstream socket instead of sharing
// proxy->upstream_socket. With N threads all blocking on recvfrom() against
// one shared socket, a reply can be handed to whichever thread's recvfrom()
// happens to wake up first -- not necessarily the thread that sent the
// matching query. Under load with many worker threads, that shows up as
// queries timing out on the client side while the upstream resolver's own
// logs show it answered every query fine: it genuinely did answer, the
// reply just went to the wrong waiting thread, whose own recvfrom() then
// timed out for real.
//
// A thread-local socket per worker sidesteps this with no protocol changes:
// each thread's sendto/recvfrom pair only ever talks to itself. (Matching
// replies by DNS transaction ID is the fully-correct fix if this ever moves
// to async IOCP-style forwarding, but a socket-per-thread is enough here
// since each thread's request/reply IS already strictly serialized.)
__thread SOCKET tls_upstream_socket = INVALID_SOCKET;

// Lazily create this thread's upstream socket the first time it's needed.
SOCKET get_thread_upstream_socket(void) {
    if (tls_upstream_socket == INVALID_SOCKET) {
        tls_upstream_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (tls_upstream_socket != INVALID_SOCKET) {
            DWORD timeout = UPSTREAM_TIMEOUT_MS;
            setsockopt(tls_upstream_socket, SOL_SOCKET, SO_RCVTIMEO,
                       (const char*)&timeout, sizeof(timeout));
        }
    }
    return tls_upstream_socket;
}

// Reads from `sock` until either a reply whose DNS transaction ID matches
// `expected_id` arrives, or `timeout_budget_ms` elapses IN TOTAL (not per
// read). A mismatched reply means a stale straggler from some earlier,
// unrelated query landed in this thread's reused socket buffer -- discard
// it and keep reading with whatever budget remains, rather than either
// blindly trusting the first packet or giving up on the first mismatch.
// Expected to loop exactly once in the overwhelming majority of calls;
// this exists to close off a rare late-straggler case, not because
// mismatches are common. Uses GetTickCount64 (integer ms, monotonic) --
// deliberately not QueryPerformanceCounter here, no need for its
// precision or the float division that'd come with converting it, and
// this stays consistent with keeping float math off the hot path.
// `expected_upstream` is who we actually sent this query to -- a reply is
// only trusted if BOTH the transaction ID matches AND it genuinely came
// from that address. ID alone isn't enough: it's only 16 bits, trivially
// guessable/brute-forceable by anything else on the LAN capable of sending
// us UDP packets, so an ID-only check is spoofable. This is a distinct
// check from ID validation, not a subset of it -- ID catches "reply to the
// wrong query", source-address catches "reply that didn't even come from
// the resolver we asked".
int recv_matching_reply(SOCKET sock, unsigned char *buf, int buf_size,
                         uint16_t expected_id, struct sockaddr_in expected_upstream,
                         DWORD timeout_budget_ms) {
    ULONGLONG deadline = GetTickCount64() + timeout_budget_ms;

    // Previously: recompute `remaining` and call setsockopt(SO_RCVTIMEO)
    // on every loop iteration, i.e. once per discarded/mismatched packet.
    // In the overwhelmingly common case (first reply matches) that's still
    // one syscall either way, but a source spamming stale/spoofed replies
    // used to cost one setsockopt() per discard on top of the recvfrom().
    // Set it ONCE, to a small bounded poll interval, and just re-check the
    // real deadline after each wakeup instead. Trades a little timing
    // precision on the genuine-timeout path (up to one poll interval of
    // overshoot) for zero repeated setsockopt calls on the discard path --
    // a trade very much worth making here.
    DWORD poll_interval_ms = timeout_budget_ms < RECV_POLL_INTERVAL_MS
                                  ? timeout_budget_ms
                                  : RECV_POLL_INTERVAL_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&poll_interval_ms, sizeof(poll_interval_ms));

    for (;;) {
        struct sockaddr_in from;
        int from_len = sizeof(from);
        int n = recvfrom(sock, (char*)buf, buf_size, 0, (struct sockaddr*)&from, &from_len);

        if (n == SOCKET_ERROR) {
            // Could be the real deadline, or just this poll interval
            // elapsing with nothing to show for it yet -- only the
            // former should actually give up.
            if (GetTickCount64() >= deadline) return SOCKET_ERROR;
            continue;
        }

        if (from.sin_addr.s_addr != expected_upstream.sin_addr.s_addr ||
            from.sin_port != expected_upstream.sin_port) {
            if (GetTickCount64() >= deadline) return SOCKET_ERROR;
            continue; // didn't come from the resolver we actually queried -- discard
        }

        if (n >= 2) {
            uint16_t got_id;
            memcpy(&got_id, buf, sizeof(got_id));
            if (got_id == expected_id) return n; // matches this query -- done
            // else: stale reply from an earlier, unrelated query on this
            // same reused socket. Discard and keep waiting on the budget.
        }
        // n < 2: too short to even contain an ID, discard and keep waiting.
        if (GetTickCount64() >= deadline) return SOCKET_ERROR;
    }
}

void process_request(DNSProxy *proxy, QueryContext *ctx) {
    // Real client IP, computed once and reused for every log_query call
    // below. Previously this was a hardcoded "..." placeholder at every
    // call site -- the buffering/watermark-flush machinery was already
    // built and working, it just never had real data plugged into this
    // field.
    // Reflection/amplification guard -- checked before anything else in
    // this function, not just before forwarding, since a blocked-response
    // reflection is still a reflection. Deliberately DROPS rather than
    // replying with any kind of error: an error reply still reflects a
    // packet at the (possibly spoofed) source, which defeats the entire
    // point. No log line here either -- logging every drop would let a
    // flood attacker use log I/O itself as a secondary amplification/DoS
    // vector; the dropped count is tracked in g_rl_dropped and surfaces
    // in the shutdown summary instead.
    if (!rate_limit_allow(ctx->client_addr.sin_addr.s_addr)) {
        InterlockedIncrement(&g_rl_dropped);
        return;
    }

    char client_ip_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &ctx->client_addr.sin_addr, client_ip_str, sizeof(client_ip_str))) {
        // Practically unreachable given a fixed AF_INET + correctly-sized
        // buffer, but leaving this uninitialized on failure would otherwise
        // feed stack garbage into logging/sanitize_log_field below.
        strncpy_s(client_ip_str, sizeof(client_ip_str), "unknown", _TRUNCATE);
    }

    // 1. Parsing (The raw_query is already populated)
    if (!parse_query(ctx->raw_query, ctx->query_len, ctx->domain, sizeof(ctx->domain), &ctx->qtype)) {
        log_query(proxy, client_ip_str, "(unparseable)", 0, RESULT_ERROR, MATCH_NONE, "malformed", 0);
        return;
    }

    LARGE_INTEGER t_start, t_end;
    QueryPerformanceCounter(&t_start);

    // 2. Radix Tree Lookup
    CheckResult check = check_domain(proxy, ctx->domain);

    // 3. Block Path
    if (check.matched && check.status == STATUS_BLOCKED) {
        unsigned char response[BUFFER_SIZE + 32];
        uint32_t ttl_seconds = check.ttl ? check.ttl : DEFAULT_BLOCK_TTL_SECONDS;
        int res_len = create_blocked_response(ctx->raw_query, ctx->query_len, response, ttl_seconds);

        sendto(proxy->local_socket, (const char*)response, res_len, 0,
               (struct sockaddr*)&ctx->client_addr, ctx->client_addr_len);

        QueryPerformanceCounter(&t_end);
        log_query(proxy, client_ip_str, ctx->domain, ctx->qtype, RESULT_BLOCKED, check.source, check.matched_domain, calculate_latency(t_start, t_end));
        return;
    }

    // 4. Heuristics & Forwarding
    // Only score a domain if it has NO entry in the tree at all yet --
    // BLOCKED already returned early above, and ALLOWED/REVIEW entries
    // both mean this domain has already been scored once (REVIEW entries
    // are inserted by flag_for_review below, specifically so this guard
    // catches them and skips re-running the whole heuristics pipeline on
    // every subsequent query for the same still-unclassified domain).
    if (!check.matched) {
        run_heuristics(proxy, ctx->domain);

        // First time we've EVER seen this exact domain locally (not just
        // "not in our blocklist" -- genuinely first sighting): ask the Pi's
        // gravity list about it, once, off the hot path. If it says yes,
        // we auto-promote to BLOCKED locally so this domain never has to
        // round-trip to the Pi again.
        if (asked_cache_try_claim(&proxy->asked_cache, ctx->domain)) {
            queue_gravity_check(proxy, ctx->domain);
        }
    }

    // 4b. Answer cache -- only for domains nothing has flagged as
    // suspicious (ALLOWED, or genuinely unmatched/first-seen -- NOT
    // REVIEW; see answer_cache.h's contract, enforced here by the
    // caller). Only A/AAAA queries are supported, the only shapes this
    // module knows how to store. A hit here answers straight from local
    // memory with zero upstream round-trip -- without this, every single
    // non-blocked query pays the full client -> nyet -> Pi ->
    // [gravity check] -> Pi -> nyet -> client round-trip, even for the
    // exact same domain queried seconds apart (e.g. a phone on WireGuard
    // re-resolving something it already resolved moments ago).
    bool cache_eligible = (ctx->qtype == 1 || ctx->qtype == 28) &&
                          ((check.matched && check.status == STATUS_ALLOWED) || !check.matched);

    if (cache_eligible && proxy->dns_answer_cache) {
        answer_cache_answer_t cached;
        if (answer_cache_lookup(proxy->dns_answer_cache, ctx->domain, ctx->qtype, &cached)) {
            unsigned char response[BUFFER_SIZE + 32];
            int res_len = create_cached_answer_response(ctx->raw_query, ctx->query_len,
                                                          response, sizeof(response),
                                                          ctx->qtype, &cached);
            if (res_len > 0) {
                sendto(proxy->local_socket, (const char*)response, res_len, 0,
                       (struct sockaddr*)&ctx->client_addr, ctx->client_addr_len);

                QueryPerformanceCounter(&t_end);
                log_query(proxy, client_ip_str, ctx->domain, ctx->qtype, RESULT_CACHED,
                          check.source, check.matched ? check.matched_domain : NULL,
                          calculate_latency(t_start, t_end));
                return;
            }
            // res_len == 0: response somehow wouldn't fit (shouldn't
            // happen -- see create_cached_answer_response's own comment)
            // -- fall through to a real upstream query rather than
            // silently dropping this one.
        }
    }

    // Upstream forward is a blocking sendto/recvfrom pair, not async IOCP
    // -- deliberate, not a shortcut: each worker thread already owns one
    // exclusive upstream socket (see get_thread_upstream_socket) and only
    // ever has one query in flight on it at a time, so there's nothing
    // for async I/O to overlap here. Going async would need a second
    // IOCP completion path plus per-query state to correlate replies
    // back to the right client, for no latency win at this proxy's
    // actual query volume.
    SOCKET my_upstream = get_thread_upstream_socket();
    if (my_upstream == INVALID_SOCKET) {
        QueryPerformanceCounter(&t_end);
        log_query(proxy, client_ip_str, ctx->domain, ctx->qtype, RESULT_FORWARDED, check.source,
                  check.matched ? check.matched_domain : NULL, calculate_latency(t_start, t_end));
        return;
    }

    // Sequential fallback, sticky on success. Try whichever upstream won
    // last time first (starts as WireGuard, which always works). If that
    // one times out, it's specifically because you've changed networks
    // (hairpin NAT failure is a hard vanish, not a slow reply, so a short
    // fallback timeout is safe) -- try the other one, and if IT works,
    // make it the new preferred upstream so every subsequent query goes
    // straight there without re-paying the timeout.
    //
    // Each worker thread's socket is reused across every query it ever
    // handles for the life of the process. A reply matching THIS query's
    // primary->fallback pair can't be cross-domain (both sends carry the
    // same raw_query, hence the same transaction ID and question), but a
    // genuinely stale straggler reply from an EARLIER, unrelated query on
    // this same socket could still be sitting in the receive buffer when
    // we call recvfrom -- and that one WOULD be for the wrong domain.
    // Validate the transaction ID before trusting a reply; if it doesn't
    // match, discard and read again within the same timeout budget rather
    // than relaying an answer that isn't actually for this question.
    uint16_t sent_id;
    memcpy(&sent_id, ctx->raw_query, sizeof(sent_id)); // DNS header: ID is the first 2 bytes

    int primary = proxy->preferred_upstream;
    unsigned char reply[BUFFER_SIZE];
    int reply_len;

    sendto(my_upstream, (const char*)ctx->raw_query, ctx->query_len, 0,
           (struct sockaddr*)&proxy->upstream_addrs[primary], sizeof(proxy->upstream_addrs[primary]));
    reply_len = recv_matching_reply(my_upstream, reply, sizeof(reply), sent_id,
                                     proxy->upstream_addrs[primary], UPSTREAM_TIMEOUT_MS);

    if (reply_len == SOCKET_ERROR) {
        int fallback = 1 - primary;

        sendto(my_upstream, (const char*)ctx->raw_query, ctx->query_len, 0,
               (struct sockaddr*)&proxy->upstream_addrs[fallback], sizeof(proxy->upstream_addrs[fallback]));
        reply_len = recv_matching_reply(my_upstream, reply, sizeof(reply), sent_id,
                                         proxy->upstream_addrs[fallback], UPSTREAM_FALLBACK_TIMEOUT_MS);

        if (reply_len != SOCKET_ERROR) {
            proxy->preferred_upstream = fallback; // sticky: skip the timeout next time
        }
    }

    QueryPerformanceCounter(&t_end);

    if (reply_len > 0) {
        sendto(proxy->local_socket, (const char*)reply, reply_len, 0,
               (struct sockaddr*)&ctx->client_addr, ctx->client_addr_len);

        // Populate the answer cache from this real round-trip, so the
        // NEXT query for this same domain (very likely seconds away) can
        // be served straight from answer_cache_lookup above instead of
        // repeating the whole upstream round-trip. Same cache_eligible
        // gate as the lookup above -- a domain that wasn't safe to serve
        // from cache isn't safe to populate the cache from either.
        if (cache_eligible && proxy->dns_answer_cache) {
            answer_cache_answer_t parsed;
            if (parse_answer_records(reply, reply_len, ctx->qtype, &parsed)) {
                answer_cache_insert(proxy->dns_answer_cache, ctx->domain, ctx->qtype, &parsed);
            }
        }
    }

    QueryResult log_result;
    const char *log_reason;
    char score_buf[16];

    if (check.matched && check.status == STATUS_ALLOWED) {
        log_result = RESULT_ALLOWED;
        log_reason = check.matched_domain;
    } else if (check.matched && check.status == STATUS_REVIEW) {
        // Previously fell through to RESULT_FORWARDED, indistinguishable
        // from a domain that was never scored at all -- distinguishing
        // this is the whole point of tonight's run: shows up as status=R
        // in dns_queries.log now, with the actual ml_score as the reason
        // field (matched_domain is always empty currently regardless of
        // status -- see check_domain -- so this is a net improvement for
        // this case specifically, not a loss of other info).
        log_result = RESULT_REVIEW;
        snprintf(score_buf, sizeof(score_buf), "score=%.2f", check.ml_score);
        log_reason = score_buf;
    } else {
        log_result = RESULT_FORWARDED;
        log_reason = check.matched ? check.matched_domain : NULL;
    }

    log_query(proxy, client_ip_str, ctx->domain, ctx->qtype,
              log_result, check.source, log_reason, calculate_latency(t_start, t_end));
}
void post_recv(DNSProxy *proxy, QueryContext *ctx) {
    DWORD flags = 0;
    ctx->wsa_buf.buf = (char*)ctx->raw_query;
    ctx->wsa_buf.len = BUFFER_SIZE;

    // MUST reset this before every call: WSARecvFrom only writes as many
    // bytes into client_addr as this says is available, and shrinks it to
    // the actual size written. If left stale from a previous completion
    // it can undersize the write or just carry stale data forward.
    ctx->client_addr_len = sizeof(ctx->client_addr);

    // Asynchronous read. The kernel will write to ctx->raw_query
    // when a packet arrives -- and, using RecvFrom instead of Recv,
    // will also fill in ctx->client_addr with who actually sent it.
    // Plain WSARecv has no sender-address parameter at all, so on an
    // unconnected UDP socket it can receive the payload just fine while
    // leaving client_addr untouched -- which is why replies were going
    // out to a stale/zeroed address instead of back to nslookup.
    WSARecvFrom(proxy->local_socket, &ctx->wsa_buf, 1, NULL, &flags,
                (struct sockaddr*)&ctx->client_addr, &ctx->client_addr_len,
                &ctx->overlapped, NULL);
}


// ============================================================
// Setup / teardown
// ============================================================

// Does two unrelated but both-cheap periodic jobs off the same 5s wake
// cycle, rather than spawning a separate thread for each:
//
// 1. Polls blocklist_path's mtime; on change, rebuilds the WHOLE tree
//    fresh (blocklist.tsv + learned.tsv, same as startup) into a new
//    builder, then radix_tree_swap()s it in. Closes the landmine flagged
//    in DNSProxy's own query_cache/dns_answer_cache comments:
//    dns_cache_clear() and answer_cache_clear() both run immediately
//    after the swap, so a hot-reloaded blocklist can never be silently
//    ignored by stale verdict or answer cache entries.
//
// 2. Calls flush_log_if_stale() every wake, unconditionally -- the log
//    buffer's size-based watermark alone can leave real data sitting
//    unflushed for over an hour at this proxy's actual query volume,
//    making `tail -f` on the log effectively useless for live
//    troubleshooting. See LOG_FLUSH_INTERVAL_SECONDS.
unsigned __stdcall reload_thread_proc(void *arg) {
    DNSProxy *proxy = (DNSProxy*)arg;
    struct _stat last_stat = {0};
    _stat(proxy->blocklist_path, &last_stat);
    time_t last_mtime = last_stat.st_mtime;

    while (running) {
        Sleep(5000);

        // Piggybacking the log-flush check on this thread's existing 5s
        // wake cycle rather than spawning a whole separate thread for
        // something this cheap. Must run BEFORE the blocklist-unchanged
        // early-continue below -- otherwise a quiet period with no
        // blocklist edits would also mean no log flushing, which is
        // exactly the staleness problem this exists to fix.
        flush_log_if_stale(proxy);

        struct _stat st;
        if (_stat(proxy->blocklist_path, &st) != 0 || st.st_mtime == last_mtime) {
            continue; // unreadable or unchanged -- nothing to do
        }
        last_mtime = st.st_mtime;

        radix_tree_builder_t builder;
        if (radix_builder_init(&builder) != 0) {
            fprintf(stderr, "[nyet] reload: OOM building new tree, keeping old one\n");
            continue;
        }
        int n1 = load_blocklist(&builder, proxy->blocklist_path);
        int n2 = load_blocklist(&builder, proxy->learned_path);
        radix_tree_swap(&proxy->blocklist_tree, &builder);
        radix_builder_free(&builder); // no-op: swap already zeroed builder.root

        if (proxy->query_cache) dns_cache_clear(proxy->query_cache);
        if (proxy->dns_answer_cache) answer_cache_clear(proxy->dns_answer_cache);

        fprintf(stderr, "[nyet] reloaded blocklist: %d + %d entries (cache flushed)\n", n1, n2);
    }
    return 0;
}

// Builds "<directory containing base_path>/<filename>" into out. Used so
// learned.tsv/review.tsv live alongside whatever blocklist_path the caller
// passed in, instead of a fixed "lists/..." that only matches THIS repo's
// layout. If base_path has no directory component, filename is used as-is
// (current working directory), same behavior as the old hardcoded paths.
static void derive_sibling_path(char *out, size_t out_size,
                                 const char *base_path, const char *filename) {
    const char *slash1 = strrchr(base_path, '/');
    const char *slash2 = strrchr(base_path, '\\');
    const char *slash = (slash2 > slash1) ? slash2 : slash1;

    if (!slash) {
        strncpy_s(out, out_size, filename, _TRUNCATE);
        return;
    }
    size_t dir_len = (size_t)(slash - base_path) + 1; // include the slash itself
    if (dir_len >= out_size) dir_len = out_size - 1;
    memcpy(out, base_path, dir_len);
    out[dir_len] = '\0';
    strncat_s(out, out_size, filename, _TRUNCATE);
}

int proxy_init(DNSProxy *proxy, const char *wg_ip, const char *home_ip,
                const char *blocklist_path, const char *log_path) {
    memset(proxy, 0, sizeof(*proxy));

    // 1. Locks
    InitializeCriticalSection(&proxy->log_lock);
    InitializeCriticalSection(&proxy->review_lock);
    InitializeCriticalSection(&proxy->asked_cache.lock);
    InitializeCriticalSection(&g_rl_lock);
    // g_rl_table itself is zero-initialized by static storage duration --
    // every bucket starts with ip=0, tokens=0, which correctly forces the
    // "first packet from this source" branch in rate_limit_allow() on
    // first use rather than accidentally granting free tokens.
    // g_rl_global_last_refill, on the other hand, MUST be seeded to the
    // current time here rather than left at its zero default: the first
    // rate_limit_allow() call would otherwise compute
    // (now - 0) * RL_GLOBAL_REFILL_PER_SEC -- (now - epoch-0) is on the
    // order of 1.7 billion seconds, and multiplying that by 200 overflows
    // a 32-bit int (signed overflow, UB in C). The clamp-to-max afterward
    // doesn't save you: the overflow already happened before the clamp
    // gets a chance to run.
    g_rl_global_last_refill = (uint32_t)time(NULL);
    // g_rl_global_tokens is NOT reset here out of necessity -- its
    // declaration (`static int g_rl_global_tokens = RL_GLOBAL_MAX_TOKENS;`)
    // already gives it that value at program load, before main() ever
    // runs, same as any other initialized static. Setting it again here
    // is redundant, not corrective -- purely so the next person reading
    // proxy_init doesn't have to go check the declaration to convince
    // themselves this isn't the zero-init footgun it might look like at
    // a glance.
    g_rl_global_tokens = RL_GLOBAL_MAX_TOKENS;

    g_gravity_check_semaphore = CreateSemaphore(NULL, MAX_CONCURRENT_GRAVITY_CHECKS,
                                                 MAX_CONCURRENT_GRAVITY_CHECKS, NULL);
    if (!g_gravity_check_semaphore) {
        fprintf(stderr, "[nyet] failed to create gravity-check semaphore\n");
        return 0;
    }

    // 2. IOCP Setup
    proxy->iocp_handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

    // 3. Sockets
    proxy->local_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    proxy->upstream_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Associate the local socket with IOCP
    CreateIoCompletionPort((HANDLE)proxy->local_socket, proxy->iocp_handle, (ULONG_PTR)proxy, 0);

    if (proxy->local_socket == INVALID_SOCKET || proxy->upstream_socket == INVALID_SOCKET) {
        fprintf(stderr, "[nyet] socket creation failed: %d\n", WSAGetLastError());
        return 0;
    }

    // timeout on upstream recv so a lost/ignored packet doesn't hang forever
    DWORD timeout = UPSTREAM_TIMEOUT_MS;
    setsockopt(proxy->upstream_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(DNS_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0 — reachable from LAN + WireGuard

    if (bind(proxy->local_socket, (struct sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[nyet] bind failed: %d (are you running as Administrator? port 53 needs it)\n", WSAGetLastError());
        return 0;
    }

    memset(&proxy->upstream_addrs[UPSTREAM_WG], 0, sizeof(proxy->upstream_addrs[UPSTREAM_WG]));
    proxy->upstream_addrs[UPSTREAM_WG].sin_family = AF_INET;
    proxy->upstream_addrs[UPSTREAM_WG].sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, wg_ip, &proxy->upstream_addrs[UPSTREAM_WG].sin_addr);

    memset(&proxy->upstream_addrs[UPSTREAM_HOME], 0, sizeof(proxy->upstream_addrs[UPSTREAM_HOME]));
    proxy->upstream_addrs[UPSTREAM_HOME].sin_family = AF_INET;
    proxy->upstream_addrs[UPSTREAM_HOME].sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, home_ip, &proxy->upstream_addrs[UPSTREAM_HOME].sin_addr);

    // WireGuard always works (home or away) so it's the safe cold-start
    // default; the sticky fallback logic in process_request will flip this
    // to UPSTREAM_HOME automatically once it proves reachable.
    proxy->preferred_upstream = UPSTREAM_WG;


    // 4. Radix Tree
    // radix_tree_init() just sets up the SRWLock + a NULL root -- the
    // tree isn't actually "live" (readable) until radix_publish() below.
    // Build BOTH blocklist.tsv and learned.tsv into the SAME builder
    // before publishing once -- load_blocklist() itself doesn't publish
    // (see its own comment); if it did, the second call here would
    // silently discard everything the first call just built.
    radix_tree_init(&proxy->blocklist_tree);

    radix_tree_builder_t builder;
    if (radix_builder_init(&builder) != 0) {
        fprintf(stderr, "[nyet] failed to allocate radix tree root (OOM at startup)\n");
        return 0; // fail proxy_init cleanly -- every query handler assumes
                  // proxy->blocklist_tree has a published root and would
                  // crash (or silently never-match) on first use otherwise
    }
    strncpy_s(proxy->blocklist_path, sizeof(proxy->blocklist_path), blocklist_path, _TRUNCATE);
    derive_sibling_path(proxy->learned_path, sizeof(proxy->learned_path), blocklist_path, "learned.tsv");
    derive_sibling_path(proxy->review_path, sizeof(proxy->review_path), blocklist_path, "review.tsv");
    load_blocklist(&builder, blocklist_path);
    load_blocklist(&builder, proxy->learned_path); // ok if this doesn't exist yet -- fopen just fails quietly
    radix_publish(&proxy->blocklist_tree, &builder);

    // 5. Query cache (optional -- see DNSProxy's own comment on this field)
    // 4096 entries: comfortably generous for anything a home network will
    // ever have "hot" at once, and the whole cache is well under 2MB
    // regardless. Failure here is deliberately non-fatal -- this cache
    // exists purely to skip a tree walk that's already fast at this
    // proxy's actual traffic volume (see the CPU-time math from earlier
    // in this project's history); losing it costs a little CPU, not
    // correctness. Every use site checks for NULL.
    proxy->query_cache = dns_cache_init(4096);
    if (!proxy->query_cache) {
        fprintf(stderr, "[nyet] warning: query cache allocation failed, continuing without it\n");
    }

    // 5b. Answer cache (optional -- see DNSProxy's own comment, and
    // answer_cache.h). 4096 entries * 256B/entry = 1MB, same reasoning as
    // query_cache above for the size pick. Also non-fatal on failure --
    // losing this just means every repeat query for an allowed domain
    // goes back to a real upstream round-trip instead of being served
    // locally, not a correctness issue.
    proxy->dns_answer_cache = answer_cache_init(ANSWER_CACHE_CAPACITY);
    if (!proxy->dns_answer_cache) {
        fprintf(stderr, "[nyet] warning: answer cache allocation failed, continuing without it\n");
    }

    // 5. Logging Buffer
    proxy->log_buffer = (LogBuffer*)malloc(sizeof(LogBuffer));
    init_log_buffer(proxy->log_buffer, 65536); // 64KB buffer
    proxy->log_file = fopen(log_path, "a");

    return 1;
}


void proxy_destroy(DNSProxy *proxy) {
    // Assumes the caller (main(), see its shutdown sequence) has already
    // set running=0 and waited for every worker/reload thread to actually
    // exit before calling this -- proxy_destroy itself doesn't touch
    // `running` or wait on anything, it just frees what's left.

    DeleteCriticalSection(&proxy->asked_cache.lock);
    if (g_gravity_check_semaphore) CloseHandle(g_gravity_check_semaphore);

    // 2. Cleanup I/O
    closesocket(proxy->local_socket);
    closesocket(proxy->upstream_socket);
    CloseHandle(proxy->iocp_handle); // Must close the port

    // 3. Cleanup Radix Tree
    // radix_tree_free() takes the exclusive lock itself and recursively
    // frees the whole tree (nodes, entries, and now the owned note
    // strings too -- see radix_tree.c's node_free). No separate
    // blocklist_lock to delete afterward: radix_tree_t owns its SRWLOCK
    // internally now, and SRWLOCKs don't need explicit deletion anyway
    // (same as the old one didn't).
    radix_tree_free(&proxy->blocklist_tree);

    // dns_cache_free() already no-ops on NULL, so this is safe whether or
    // not dns_cache_init() succeeded back in proxy_init().
    dns_cache_free(proxy->query_cache);
    answer_cache_free(proxy->dns_answer_cache); // same NULL-safety

    // 4. Cleanup Logs
    if (proxy->log_file) {
        // Final flush of remaining buffer
        fprintf(proxy->log_file, "%s", proxy->log_buffer->data);
        fclose(proxy->log_file);
    }
    free(proxy->log_buffer->data);
    free(proxy->log_buffer);

    // 5. Cleanup Locks
    // SRWLOCK does not require deletion, but CriticalSections do
    DeleteCriticalSection(&proxy->log_lock);
    DeleteCriticalSection(&proxy->review_lock);
}

// ============================================================
// main
// ============================================================

#include <process.h> // for _beginthreadex

volatile int running = 1; // Global flag for shutdown

// Catches Ctrl+C, console window close, and logoff/shutdown -- flushes the
// log buffer and flags worker threads to stop instead of just vanishing.
// NOT a substitute for anything -- there is no way to catch a hard kill
// (SIGKILL / taskkill /F) on any OS; that's what makes it a hard kill.
// This only helps for a normal Ctrl+C in the terminal you're running from.
BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            running = 0;
            return TRUE; // handled
        default:
            return FALSE;
    }
}

// The thread routine that all your workers run
unsigned __stdcall worker_thread_proc(void* arg) {
    DNSProxy *proxy = (DNSProxy*)arg;
    iocp_worker_loop(proxy, proxy->iocp_handle);
    if (tls_upstream_socket != INVALID_SOCKET) {
        closesocket(tls_upstream_socket);
        tls_upstream_socket = INVALID_SOCKET;
    }
    return 0;
}

int main(int argc, char **argv) {
    // ---- Flag scan (before positional parsing) ----
    // --background : relaunch fully detached (no console at all) and exit
    //                the foreground process immediately. Default (this
    //                flag absent) is unchanged: console stays visible,
    //                which is exactly what you want for live debugging
    //                (e.g. watching [heur] lines or dns_queries.log
    //                activity in real time while troubleshooting why a
    //                device can't reach this as its DNS server).
    // --_detached   : internal-only marker set by the relaunch below so
    //                 the detached child doesn't try to relaunch itself
    //                 again. Not meant to be passed by hand.
    int background_mode = 0;
    int already_detached = 0;

    // Positional args (wg_ip/home_ip/blocklist_path/log_path) can appear
    // in any order relative to the flags above -- filter flags out first,
    // then parse whatever's left positionally, same as before. Unlike
    // before, fewer than 4 positional args is no longer an error by
    // itself: each missing slot falls back to its WG_IP/HOME_IP/
    // BLOCKLIST_PATH/LOG_PATH environment variable (see config.example.bat
    // at repo root -- `call`ing your own config.local.bat before running
    // nyet.exe sets these once instead of retyping them every launch).
    // A CLI arg in a given slot always wins over the env var for that
    // same slot; it's still only an error if BOTH are missing for some
    // slot.
    char *positional[16];
    int positional_count = 0;

    for (int i = 1; i < argc && positional_count < 16; i++) {
        if (strcmp(argv[i], "--background") == 0) {
            background_mode = 1;
        } else if (strcmp(argv[i], "--_detached") == 0) {
            already_detached = 1;
        } else {
            positional[positional_count++] = argv[i];
        }
    }

    const char *wg_ip          = (positional_count > 0) ? positional[0] : getenv("WG_IP");
    const char *home_ip        = (positional_count > 1) ? positional[1] : getenv("HOME_IP");
    const char *blocklist_path = (positional_count > 2) ? positional[2] : getenv("BLOCKLIST_PATH");
    const char *log_path       = (positional_count > 3) ? positional[3] : getenv("LOG_PATH");

    if (!wg_ip || !home_ip || !blocklist_path || !log_path) {
        fprintf(stderr,
            "usage: nyet.exe [--background] [<wg_ip> <home_ip> <blocklist_path> <log_path>]\n"
            "  Each of the 4 values above can come from a CLI arg (as shown) OR from an\n"
            "  environment variable of the same name (WG_IP / HOME_IP / BLOCKLIST_PATH /\n"
            "  LOG_PATH) -- e.g. via `call config.local.bat` before running nyet.exe.\n"
            "  A CLI arg always overrides the matching env var. Still missing:\n");
        if (!wg_ip)          fprintf(stderr, "    - wg_ip (arg 1, or WG_IP env var)\n");
        if (!home_ip)        fprintf(stderr, "    - home_ip (arg 2, or HOME_IP env var)\n");
        if (!blocklist_path) fprintf(stderr, "    - blocklist_path (arg 3, or BLOCKLIST_PATH env var)\n");
        if (!log_path)       fprintf(stderr, "    - log_path (arg 4, or LOG_PATH env var)\n");
        fprintf(stderr,
            "\n"
            "  wg_ip        WireGuard address of the Pi (e.g. 192.0.2.1) -- always reachable\n"
            "  home_ip      Home-LAN address of the Pi (e.g. 198.51.100.2) -- faster, but only\n"
            "               reachable when actually on the home network (hairpin NAT)\n"
            "               Also used for the Pi-hole gravity-list HTTP lookup -- whichever\n"
            "               of wg_ip/home_ip is currently working for DNS is used for that too.\n"
            "  --background Relaunch fully detached (no console window, survives closing\n"
            "               the terminal that launched it). Omit this for normal foreground/\n"
            "               console mode -- useful for live debugging.\n");
        return 1;
    }

    if (background_mode && !already_detached) {
        // Relaunch self fully detached, then exit THIS process immediately.
        // A plain FreeConsole()/ShowWindow(SW_HIDE) approach only hides
        // the window -- the process still dies if the launching terminal
        // closes. CreateProcess with DETACHED_PROCESS spawns a genuinely
        // independent process with no console at all, which keeps running
        // regardless of what happens to the terminal that started this one.
        char exe_path[MAX_PATH];
        if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) == 0) {
            fprintf(stderr, "[nyet] GetModuleFileNameA failed, continuing in foreground.\n");
        } else {
            char cmdline[4096];
            int written = snprintf(cmdline, sizeof(cmdline), "\"%s\"", exe_path);
            for (int i = 1; i < argc && written < (int)sizeof(cmdline); i++) {
                if (strcmp(argv[i], "--background") == 0) continue; // don't propagate; child is already the detached instance
                written += snprintf(cmdline + written, sizeof(cmdline) - written, " \"%s\"", argv[i]);
            }
            written += snprintf(cmdline + written, sizeof(cmdline) - written, " --_detached");

            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            ZeroMemory(&pi, sizeof(pi));

            if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                                DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                                NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                fprintf(stderr, "[nyet] relaunched detached (check Task Manager for nyet.exe) -- exiting foreground process.\n");
                return 0;
            }
            fprintf(stderr, "[nyet] CreateProcessA failed (error %lu), continuing in foreground instead.\n", GetLastError());
        }
        // Fall through to run in foreground if the relaunch attempt failed --
        // better to run visibly than not run at all.
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[nyet] WSAStartup failed.\n");
        return 1;
    }

    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
    QueryPerformanceFrequency(&g_qpc_frequency);
    InitializeCriticalSection(&g_stdout_lock);

    DNSProxy proxy;
    if (!proxy_init(&proxy, wg_ip, home_ip, blocklist_path, log_path)) {
        WSACleanup();
        return 1;
    }

    // 1. Initialize Context Pool (e.g., 50 concurrent requests)
    const int POOL_SIZE = 50;
    QueryContext *pool = (QueryContext*)calloc(POOL_SIZE, sizeof(QueryContext));

    // 2. Prime the Pump: Post all reads to the kernel IMMEDIATELY
    // The kernel will now hold these buffers and fill them as packets arrive
    for (int i = 0; i < POOL_SIZE; i++) {
        post_recv(&proxy, &pool[i]);
    }

    // 3. Spawn Thread Pool (one worker per core -- this is a bursty,
    // low-QPS home DNS proxy, not a saturated server; 2x per core was
    // pure headroom nobody needed, and the elastic growth logic on top
    // of that already handles genuine bursts by spinning up more.)
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    int num_threads = sysinfo.dwNumberOfProcessors;
    HANDLE *threads = malloc(sizeof(HANDLE) * num_threads);
    if (!threads) {
        fprintf(stderr, "[nyet] failed to allocate thread handle array (OOM at startup)\n");
        return 1;
    }

    fprintf(stderr, "[nyet] spawning %d worker threads\n", num_threads);
    for (int i = 0; i < num_threads; i++) {
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, worker_thread_proc, &proxy, 0, NULL);
    }

    HANDLE reload_handle = (HANDLE)_beginthreadex(NULL, 0, reload_thread_proc, &proxy, 0, NULL);

    // 4. Main loop: Just wait for shutdown
    fprintf(stderr, "[nyet] proxy running. Press Ctrl+C to stop.\n");
    while (running) {
        Sleep(1000); // Main thread stays idle
    }

    // 5. Cleanup
    fprintf(stderr, "[nyet] shutting down, waiting for worker threads...\n");

    // Worker threads are almost certainly still parked in
    // GetQueuedCompletionStatus(..., INFINITE) right now -- running=0 alone
    // doesn't wake them, they only re-check it on their next loop
    // iteration, which may never come if no real traffic arrives. Post one
    // dummy completion per thread (overlapped=NULL) to force each one to
    // wake up, hit iocp_worker_loop's "if (overlapped == NULL) continue;"
    // branch, and re-check running -- which is now 0, so they exit.
    for (int i = 0; i < num_threads; i++) {
        PostQueuedCompletionStatus(proxy.iocp_handle, 0, 0, NULL);
    }

    // MUST actually wait for threads to finish, not just close our handle
    // to them. CloseHandle() on a thread handle does NOT stop the thread
    // or wait for it -- it only releases our reference. Without this wait,
    // proxy_destroy()/free(pool) below can free memory (sockets, the IOCP
    // handle, the QueryContext pool) that a worker thread is still actively
    // using, mid-iteration -- a use-after-free racing the shutdown path.
    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);
    // Same reasoning, same hazard, for the reload thread specifically:
    // it touches proxy->blocklist_tree/query_cache directly (swap +
    // cache clear), so it MUST be done before proxy_destroy() frees both.
    WaitForSingleObject(reload_handle, INFINITE);

    // Overnight debug summary -- printed once all worker threads have
    // actually stopped, so this is a clean snapshot with no other thread
    // still incrementing the counters underneath it. Separate entirely
    // from dns_queries.log; this only ever goes to stdout.
    printf("\n========== overnight heuristic summary ==========\n");
    printf("Total domains scored : %ld\n", g_heuristic_total_scored);
    printf("Flagged for review    : %ld (score >= %.2f)\n", g_heuristic_flagged_review, REVIEW_THRESHOLD);
    printf("Rate-limit drops      : %ld (per-source + global buckets, see RL_* constants)\n", g_rl_dropped);
    printf("Score distribution:\n");
    for (int i = 0; i < 10; i++) {
        printf("  [%.1f-%.1f) %ld\n", i / 10.0f, (i + 1) / 10.0f, g_score_histogram[i]);
    }
    printf("===================================================\n\n");

    if (proxy.dns_answer_cache) {
        uint64_t ac_hits, ac_misses, ac_evictions, ac_inserts, ac_count;
        answer_cache_get_stats(proxy.dns_answer_cache, &ac_hits, &ac_misses,
                                &ac_evictions, &ac_inserts, &ac_count);
        uint64_t ac_total = ac_hits + ac_misses;
        printf("========== answer cache summary ==========\n");
        printf("Hits / misses  : %llu / %llu", (unsigned long long)ac_hits, (unsigned long long)ac_misses);
        if (ac_total > 0) {
            printf(" (%.1f%% hit rate -- each hit is one query that never left this machine)\n",
                   100.0 * (double)ac_hits / (double)ac_total);
        } else {
            printf("\n");
        }
        printf("Inserts        : %llu\n", (unsigned long long)ac_inserts);
        printf("Evictions      : %llu (probe window full, oldest live entry replaced)\n", (unsigned long long)ac_evictions);
        printf("Entries live   : %llu / %d (%.1f%% utilization)\n",
               (unsigned long long)ac_count, ANSWER_CACHE_CAPACITY,
               100.0 * answer_cache_utilization(proxy.dns_answer_cache));
        printf("============================================\n\n");
    }

    for (int i = 0; i < num_threads; i++) {
        CloseHandle(threads[i]);
    }
    CloseHandle(reload_handle);

    proxy_destroy(&proxy);
    free(pool);
    free(threads);
    DeleteCriticalSection(&g_stdout_lock);
    DeleteCriticalSection(&g_rl_lock);
    WSACleanup();
    return 0;
}