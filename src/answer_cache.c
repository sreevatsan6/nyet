/*
 * src/answer_cache.c — Fixed Answer Cache
 *
 * Caches real resolved DNS answers (not verdicts -- see answer_cache.h for
 * how this differs from dns_cache) keyed on (domain, qtype).
 *
 * Indexing: unlike dns_cache's full linear scan (fine there at ~300B/entry,
 * not fine here at 256B/entry -- scanning the whole table per lookup would
 * pull megabytes through cache on every query, including misses), this
 * hashes straight to a starting slot and probes a small bounded
 * neighborhood forward. Lookup cost stays flat regardless of capacity.
 *
 * Expiry is lazy: no sweep thread. A lookup that finds an expired slot
 * marks it invalid on the spot and reports a miss; an insert that lands on
 * an expired slot just overwrites it. answer_cache_prune_expired() exists
 * for callers that want to reclaim slots proactively (e.g. off the same
 * periodic tick that already prunes dns_cache), but correctness never
 * depends on it running.
 */

#include "answer_cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

// How many consecutive slots (starting from the hashed index) a lookup or
// insert is willing to examine before giving up / evicting. Bounded on
// purpose -- this is the knob that keeps lookup O(1)-ish instead of O(n).
// 8 is generous relative to expected load factor; raise it only if
// answer_cache_get_stats() shows eviction churn that a wider window would
// meaningfully reduce.
#define PROBE_WINDOW 8


typedef struct {
    volatile LONG64 timestamp_ns;
    uint64_t   hash;
    uint32_t   ttl_seconds;
    uint16_t   qtype;
    uint8_t    num_records;
    uint8_t    record_bytes;
    volatile LONG valid;
    char       domain[ANSWER_CACHE_MAX_DOMAIN_LEN + 1];
    uint8_t    records[ANSWER_CACHE_MAX_RECORDS][ANSWER_CACHE_RECORD_BYTES];
} __attribute__((aligned(64))) answer_cache_entry_t;


// Fixed fields: 28B, domain: 96B, records: 128B = 252B data, rounds to
// 256B (align(64)) -- 4B trailing pad. Deliberately ordered largest-
// alignment-first so the compiler doesn't insert gaps between fields; see
// design notes for why 256 specifically.




struct answer_cache {
    answer_cache_entry_t* entries;
    size_t capacity;      // power of 2 -- required for hash & (capacity-1)
    volatile LONG64 count;
    SRWLOCK lock;
    volatile LONG64 hits, misses, evictions, inserts;
};

// 64-bit FNV-1a over domain bytes, then qtype folded in separately (not
// just concatenated into the same byte stream) so "a1.com"/A and
// "a1.com"+some-byte-that-looks-like-qtype can't accidentally collide the
// same way string concatenation could.
static uint64_t hash_key(const char* domain, uint16_t qtype) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (const unsigned char* p = (const unsigned char*)domain; *p; p++) {
        hash ^= *p;
        hash *= 0x100000001b3ULL;
    }
    hash ^= qtype;
    hash *= 0x100000001b3ULL;
    return hash;
}

static uint64_t get_timestamp_ns(void) {
    static LARGE_INTEGER freq = {0};
    if (freq.QuadPart == 0) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        InterlockedCompareExchange64(&freq.QuadPart, f.QuadPart, 0);
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (uint64_t)((now.QuadPart * 1000000000ULL) / freq.QuadPart);
}

static bool is_power_of_2(size_t n) {
    return n > 0 && (n & (n - 1)) == 0;
}

static bool entry_expired(const answer_cache_entry_t* entry, uint64_t now) {
    uint64_t ts = entry->timestamp_ns;
    return ts + (uint64_t)entry->ttl_seconds * 1000000000ULL < now;
}

answer_cache_t* answer_cache_init(size_t capacity) {
    if (!is_power_of_2(capacity) || capacity < 64) {
        return NULL;
    }

    answer_cache_t* cache = (answer_cache_t*)malloc(sizeof(answer_cache_t));
    if (!cache) return NULL;

    cache->entries = (answer_cache_entry_t*)_aligned_malloc(
        capacity * sizeof(answer_cache_entry_t), 64);
    if (!cache->entries) {
        free(cache);
        return NULL;
    }

    memset(cache->entries, 0, capacity * sizeof(answer_cache_entry_t));

    cache->capacity = capacity;
    cache->count = 0;
    InitializeSRWLock(&cache->lock);

    cache->hits = 0;
    cache->misses = 0;
    cache->evictions = 0;
    cache->inserts = 0;

    return cache;
}

void answer_cache_free(answer_cache_t* cache) {
    if (!cache) return;
    if (cache->entries) {
        _aligned_free(cache->entries);
    }
    free(cache);
}

static void copy_out(const answer_cache_entry_t* entry, answer_cache_answer_t* out) {
    memcpy(out->records, entry->records, sizeof(out->records));
    out->num_records  = entry->num_records;
    out->record_bytes = entry->record_bytes;
    out->ttl_seconds  = entry->ttl_seconds;
}

bool answer_cache_lookup(answer_cache_t* cache, const char* domain,
                          uint16_t qtype, answer_cache_answer_t* out_answer) {
    if (!cache || !domain || !out_answer) return false;
    if (strlen(domain) > ANSWER_CACHE_MAX_DOMAIN_LEN) return false;

    uint64_t hash = hash_key(domain, qtype);
    size_t start = (size_t)(hash & (cache->capacity - 1));

    AcquireSRWLockShared(&cache->lock);
    uint64_t now = get_timestamp_ns();

    for (size_t step = 0; step < PROBE_WINDOW && step < cache->capacity; step++) {
        size_t idx = (start + step) & (cache->capacity - 1);
        answer_cache_entry_t* entry = &cache->entries[idx];

        if (!entry->valid) continue; // empty slot -- keep probing, this
                                      // isn't necessarily the end of the
                                      // chain (a later insert may have
                                      // landed past a slot that's since
                                      // been vacated)

        if (entry->hash != hash) continue;
        if (entry->qtype != qtype) continue;
        if (strcmp(entry->domain, domain) != 0) continue;

        if (entry_expired(entry, now)) {
            // Lazy eviction: found our match, but it's stale. Drop it here
            // rather than leaving it for a future insert to trip over.
            InterlockedExchange(&entry->valid, 0);
            InterlockedDecrement64(&cache->count);
            ReleaseSRWLockShared(&cache->lock);
            InterlockedIncrement64(&cache->misses);
            return false;
        }

        copy_out(entry, out_answer);

        // Touch timestamp forward on hit, same monotonic-CAS pattern as
        // dns_cache -- cheap approximate LRU signal for eviction ordering,
        // without needing a real LRU list.
        uint64_t ts = entry->timestamp_ns;
        if (ts < now) {
            InterlockedCompareExchange64(&entry->timestamp_ns, now, ts);
        }

        ReleaseSRWLockShared(&cache->lock);
        InterlockedIncrement64(&cache->hits);
        return true;
    }

    ReleaseSRWLockShared(&cache->lock);
    InterlockedIncrement64(&cache->misses);
    return false;
}

bool answer_cache_insert(answer_cache_t* cache, const char* domain,
                          uint16_t qtype, const answer_cache_answer_t* answer) {
    if (!cache || !domain || !answer) return false;
    if (answer->ttl_seconds == 0) return false; // same immediate-expiry
                                                  // race dns_cache guards
                                                  // against
    size_t domain_len = strlen(domain);
    if (domain_len > ANSWER_CACHE_MAX_DOMAIN_LEN) return false;
    if (answer->num_records == 0 || answer->num_records > ANSWER_CACHE_MAX_RECORDS) return false;
    if (answer->record_bytes == 0 || answer->record_bytes > ANSWER_CACHE_RECORD_BYTES) return false;

    uint64_t hash = hash_key(domain, qtype);
    size_t start = (size_t)(hash & (cache->capacity - 1));

    AcquireSRWLockExclusive(&cache->lock);
    uint64_t now = get_timestamp_ns();

    size_t target_idx = (size_t)-1;
    bool target_is_fresh_slot = false; // true = empty/expired (count++),
                                        // false = evicting a live entry
                                        // (count unchanged, evictions++)
    uint64_t oldest_time = UINT64_MAX;
    size_t oldest_idx = start;

    for (size_t step = 0; step < PROBE_WINDOW && step < cache->capacity; step++) {
        size_t idx = (start + step) & (cache->capacity - 1);
        answer_cache_entry_t* entry = &cache->entries[idx];

        if (!entry->valid) {
            if (target_idx == (size_t)-1) {
                target_idx = idx;
                target_is_fresh_slot = true;
            }
            continue;
        }

        if (entry_expired(entry, now)) {
            InterlockedDecrement64(&cache->count);
            memset(entry, 0, sizeof(*entry));
            if (target_idx == (size_t)-1) {
                target_idx = idx;
                target_is_fresh_slot = true;
            }
            continue;
        }

        // Exact match already cached (e.g. TTL refresh on a re-query
        // before expiry) -- overwrite in place, not a new insert.
        if (entry->hash == hash && entry->qtype == qtype &&
            strcmp(entry->domain, domain) == 0) {
            entry->num_records  = answer->num_records;
            entry->record_bytes = answer->record_bytes;
            entry->ttl_seconds  = answer->ttl_seconds;
            memcpy(entry->records, answer->records, sizeof(entry->records));
            entry->timestamp_ns = now;
            ReleaseSRWLockExclusive(&cache->lock);
            return true;
        }

        if (entry->timestamp_ns < oldest_time) {
            oldest_time = entry->timestamp_ns;
            oldest_idx = idx;
        }
    }

    if (target_idx == (size_t)-1) {
        // No empty/expired slot in the probe window -- evict the oldest
        // live entry we saw within that same window (bounded LRU-ish, not
        // global LRU; fine, this is advisory, not correctness-critical).
        target_idx = oldest_idx;
        target_is_fresh_slot = false;
    }

    answer_cache_entry_t* entry = &cache->entries[target_idx];
    if (!target_is_fresh_slot) {
        InterlockedIncrement64(&cache->evictions);
        memset(entry, 0, sizeof(*entry));
    }

    strncpy(entry->domain, domain, ANSWER_CACHE_MAX_DOMAIN_LEN);
    entry->domain[ANSWER_CACHE_MAX_DOMAIN_LEN] = '\0';
    entry->hash          = hash;
    entry->qtype         = qtype;
    entry->num_records    = answer->num_records;
    entry->record_bytes  = answer->record_bytes;
    entry->ttl_seconds   = answer->ttl_seconds;
    memcpy(entry->records, answer->records, sizeof(entry->records));
    entry->timestamp_ns  = now;
    _WriteBarrier();
    entry->valid = 1;

    if (target_is_fresh_slot) {
        InterlockedIncrement64(&cache->count);
    }

    ReleaseSRWLockExclusive(&cache->lock);
    InterlockedIncrement64(&cache->inserts);
    return true;
}

// This module only ever stores A (1) and AAAA (28) answers per the
// contract in answer_cache.h -- invalidate-by-domain has no single slot to
// start from (the hash depends on qtype too), so it probes both known
// qtypes' neighborhoods explicitly rather than falling back to a full
// table scan.
static const uint16_t INVALIDATE_QTYPES[] = { 1, 28 };

bool answer_cache_invalidate(answer_cache_t* cache, const char* domain) {
    if (!cache || !domain) return false;
    if (strlen(domain) > ANSWER_CACHE_MAX_DOMAIN_LEN) return false;

    bool removed_any = false;

    AcquireSRWLockExclusive(&cache->lock);
    for (size_t q = 0; q < sizeof(INVALIDATE_QTYPES) / sizeof(INVALIDATE_QTYPES[0]); q++) {
        uint64_t hash = hash_key(domain, INVALIDATE_QTYPES[q]);
        size_t start = (size_t)(hash & (cache->capacity - 1));

        for (size_t step = 0; step < PROBE_WINDOW && step < cache->capacity; step++) {
            size_t idx = (start + step) & (cache->capacity - 1);
            answer_cache_entry_t* entry = &cache->entries[idx];

            if (entry->valid && entry->hash == hash &&
                entry->qtype == INVALIDATE_QTYPES[q] &&
                strcmp(entry->domain, domain) == 0) {
                InterlockedDecrement64(&cache->count);
                memset(entry, 0, sizeof(*entry));
                removed_any = true;
                break; // only one slot can hold this exact (domain,qtype)
            }
        }
    }
    ReleaseSRWLockExclusive(&cache->lock);
    return removed_any;
}

void answer_cache_clear(answer_cache_t* cache) {
    if (!cache) return;

    AcquireSRWLockExclusive(&cache->lock);
    memset(cache->entries, 0, cache->capacity * sizeof(answer_cache_entry_t));
    InterlockedExchange64(&cache->count, 0);
    ReleaseSRWLockExclusive(&cache->lock);
}

size_t answer_cache_prune_expired(answer_cache_t* cache, uint64_t current_time_ns) {
    if (!cache) return 0;
    size_t pruned = 0;

    AcquireSRWLockExclusive(&cache->lock);
    for (size_t i = 0; i < cache->capacity; i++) {
        answer_cache_entry_t* entry = &cache->entries[i];
        if (entry->valid && entry_expired(entry, current_time_ns)) {
            InterlockedDecrement64(&cache->count);
            memset(entry, 0, sizeof(*entry));
            pruned++;
        }
    }
    ReleaseSRWLockExclusive(&cache->lock);
    return pruned;
}

void answer_cache_debug_print(answer_cache_t* cache) {
    if (!cache) return;

    AcquireSRWLockShared(&cache->lock);

    printf("AnswerCache: capacity=%zu, count=%llu\n",
           cache->capacity, (unsigned long long)cache->count);

    for (size_t i = 0; i < cache->capacity; i++) {
        answer_cache_entry_t* entry = &cache->entries[i];
        if (entry->valid) {
            printf("  [%zu] %s qtype=%u records=%u ttl=%u\n",
                   i, entry->domain, entry->qtype, entry->num_records, entry->ttl_seconds);
        }
    }

    ReleaseSRWLockShared(&cache->lock);
}

void answer_cache_get_stats(answer_cache_t* cache, uint64_t* hits, uint64_t* misses,
                             uint64_t* evictions, uint64_t* inserts, uint64_t* count) {
    if (!cache) return;
    if (hits) *hits = cache->hits;
    if (misses) *misses = cache->misses;
    if (evictions) *evictions = cache->evictions;
    if (inserts) *inserts = cache->inserts;
    if (count) *count = cache->count;
}

double answer_cache_utilization(answer_cache_t* cache) {
    if (!cache || cache->capacity == 0) return 0.0;
    uint64_t current_count = cache->count;
    return (double)current_count / (double)cache->capacity;
}

size_t answer_cache_entry_size(void) {
    return sizeof(answer_cache_entry_t);
}