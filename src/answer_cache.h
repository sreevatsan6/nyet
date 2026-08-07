#ifndef ANSWER_CACHE_H
#define ANSWER_CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// answer_cache — caches actual resolved DNS *answers* for ALLOWED domains,
// so repeat queries can be served straight from local memory without ever
// forwarding to the upstream (Pi) resolver.
//
// This is deliberately a SEPARATE cache from dns_cache (the existing
// verdict cache in query_cache): dns_cache answers "is this domain
// blocked/allowed", answer_cache answers "what IP did this domain resolve
// to, and is that still fresh". Different key shape (domain+qtype, not
// just domain), different lifetime source (the real upstream TTL, not a
// locally-chosen policy constant), different population trigger (a real
// upstream round-trip, not a blocklist lookup). Do not merge them.
//
// Scope/contract this module assumes, enforced by the CALLER, not in here:
//   - Only ever insert domains that were already verdicted ALLOWED. This
//     module has no opinion on blocking and will happily cache anything
//     it's handed -- keeping it dumb and general-purpose is the point.
//   - Only domains <= ANSWER_CACHE_MAX_DOMAIN_LEN chars get cached; longer
//     ones are the caller's job to skip (real-world ALLOWED traffic is
//     overwhelmingly <=63 bytes -- see project notes). insert() rejects
//     anything over the limit outright rather than silently truncating.
//   - Only A/AAAA-shaped answers (fixed-width, <=16 bytes/record) belong
//     here. This module stores raw record bytes, not parsed RDATA -- it
//     doesn't know or care about the RR type beyond byte width, so mixing
//     in variable-length RR types (CNAME, TXT, MX...) is a caller error,
//     not something this module can detect.

#define ANSWER_CACHE_MAX_DOMAIN_LEN 95   // + 1 for null terminator = 96
#define ANSWER_CACHE_MAX_RECORDS    8
#define ANSWER_CACHE_RECORD_BYTES   16   // wide enough for AAAA (16B); A
                                          // records (4B) just use the first
                                          // 4 and leave the rest unused

typedef struct answer_cache answer_cache_t;

// capacity MUST be a power of 2 (bounded-probe indexing relies on
// hash & (capacity-1)), and reasonably >= 64 so the probe neighborhood
// (fixed at compile time internally) has room to make sense. Returns NULL
// on bad capacity or allocation failure.
answer_cache_t* answer_cache_init(size_t capacity);
void answer_cache_free(answer_cache_t* cache);

// One resolved answer, as the caller (and the caller's DNS-answer walker)
// sees it: up to ANSWER_CACHE_MAX_RECORDS fixed-width record payloads
// (raw RDATA bytes -- 4B for an A record, 16B for AAAA, caller decides
// which via record_bytes) plus the TTL that should govern freshness.
typedef struct {
    uint8_t  records[ANSWER_CACHE_MAX_RECORDS][ANSWER_CACHE_RECORD_BYTES];
    uint8_t  num_records;   // how many of the above are populated
    uint8_t  record_bytes;  // 4 for A, 16 for AAAA -- same for every
                             // record in a single answer, since qtype is
                             // fixed per query
    uint32_t ttl_seconds;   // minimum TTL across the real answer's RRs;
                             // caller computes this, module just stores it
} answer_cache_answer_t;

// domain must be <= ANSWER_CACHE_MAX_DOMAIN_LEN chars (see contract note
// above) or this returns false without inserting. qtype is whatever raw
// DNS QTYPE value the query used (1=A, 28=AAAA, ...) -- this module treats
// it as an opaque key component, not something it interprets.
bool answer_cache_insert(answer_cache_t* cache, const char* domain,
                          uint16_t qtype, const answer_cache_answer_t* answer);

// Lazy-expiry lookup: internally checks the stored TTL against wall time
// and reports a miss (without the caller needing a separate "is this
// stale" call) if the entry's aged out. A hit copies the answer into
// *out_answer; the cache's own storage is never handed out by pointer, so
// the caller is free to use *out_answer after releasing whatever lock it
// holds elsewhere.
bool answer_cache_lookup(answer_cache_t* cache, const char* domain,
                          uint16_t qtype, answer_cache_answer_t* out_answer);

// Explicit invalidation for the two cases that can't wait for lazy expiry:
// blocklist hot-reload (a domain that flips ALLOWED->BLOCKED must not keep
// serving a stale cached IP) and gravity-promotion (same reasoning,
// mid-flight). Single-domain form removes every qtype's entry for that
// domain (A and AAAA both, if present) since both need invalidating
// together whenever the verdict itself changes.
bool answer_cache_invalidate(answer_cache_t* cache, const char* domain);
void answer_cache_clear(answer_cache_t* cache);

// Housekeeping / observability, same shape as dns_cache's equivalents so
// existing periodic-maintenance code (5s wake cycle, shutdown summary
// print) can treat both caches uniformly.
size_t answer_cache_prune_expired(answer_cache_t* cache, uint64_t current_time_ns);
void answer_cache_debug_print(answer_cache_t* cache);
void answer_cache_get_stats(answer_cache_t* cache, uint64_t* hits, uint64_t* misses,
                             uint64_t* evictions, uint64_t* inserts, uint64_t* count);
double answer_cache_utilization(answer_cache_t* cache);

// Exposes sizeof(the internal per-entry struct) without exposing the
// struct itself -- exists so a test harness can assert the layout came
// out to the intended size (256B, see design notes) without needing
// friend-class-style access into answer_cache.c.
size_t answer_cache_entry_size(void);

#ifdef __cplusplus
}
#endif

#endif