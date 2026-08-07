/*
 * src/dns_cache.c — Fixed DNS Cache
 */

#include "dns_cache.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#define MAX_DOMAIN_LEN 253 // RFC 1035 max 253 chars

/* Cache-line aligned to prevent false sharing */
typedef struct __declspec(align(64)) {
    volatile LONG64 timestamp_ns;
    uint32_t hash;
    uint32_t ttl;
    dns_cache_action_t action;
    volatile LONG valid; /* 0 = invalid, 1 = valid */
    char domain[MAX_DOMAIN_LEN + 1];
} dns_cache_entry_t;

struct dns_cache {
    dns_cache_entry_t* entries;     
    size_t capacity;                
    
    volatile LONG64 count;          
    SRWLOCK lock;                   
    
    /* Statistics (modified atomically) */
    volatile LONG64 hits;
    volatile LONG64 misses;
    volatile LONG64 evictions;
    volatile LONG64 inserts;
};

static uint32_t fnv1a_hash(const char* str) {
    uint32_t hash = 0x811c9dc5;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 0x01000193; // 16777619
    }
    return hash;
}

static uint64_t get_timestamp_ns(void) {
    static LARGE_INTEGER freq = {0};
    /* Lock-free initialization of frequency */
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

dns_cache_t* dns_cache_init(size_t capacity) {
    if (!is_power_of_2(capacity) || capacity < 64) {
        return NULL;
    }

    dns_cache_t* cache = (dns_cache_t*)malloc(sizeof(dns_cache_t));
    if (!cache) return NULL;

    cache->entries = (dns_cache_entry_t*)_aligned_malloc(
        capacity * sizeof(dns_cache_entry_t), 64);
    if (!cache->entries) {
        free(cache);
        return NULL;
    }

    memset(cache->entries, 0, capacity * sizeof(dns_cache_entry_t));
    
    cache->capacity = capacity;
    cache->count = 0;
    InitializeSRWLock(&cache->lock);
    
    cache->hits = 0;
    cache->misses = 0;
    cache->evictions = 0;
    cache->inserts = 0;

    return cache;
}

void dns_cache_free(dns_cache_t* cache) {
    if (!cache) return;
    /* FIX: Must use _aligned_free to prevent heap corruption */
    if (cache->entries) {
        _aligned_free(cache->entries);
    }
    free(cache);
}

bool dns_cache_lookup(dns_cache_t* cache, const char* domain,
                      dns_cache_action_t* action, uint32_t* ttl) {
    if (!cache || !domain || !action || !ttl) return false;
    
    size_t domain_len = strlen(domain);
    /* FIX: Reject over-long domains to prevent hash/key mismatch */
    if (domain_len > MAX_DOMAIN_LEN) return false;

    uint32_t hash = fnv1a_hash(domain); 
    
    AcquireSRWLockShared(&cache->lock);
    /* FIX: Capture timestamp INSIDE the lock to prevent stale TTL checks */
    uint64_t now = get_timestamp_ns();
    
    for (size_t i = 0; i < cache->capacity; i++) {
        dns_cache_entry_t* entry = &cache->entries[i];
        
        if (entry->valid) {
            if (entry->hash == hash) { 
                if (strcmp(entry->domain, domain) == 0) { 
                    
                    uint64_t ts = entry->timestamp_ns;
                    if (ts + (uint64_t)entry->ttl * 1000000000ULL < now) {
                        ReleaseSRWLockShared(&cache->lock);
                        InterlockedIncrement64(&cache->misses); 
                        return false;
                    }
                    
                    *action = entry->action; 
                    *ttl = entry->ttl;       
                    
                    /* FIX: Monotonic LRU touch via CAS loop */
                    if (ts < now) {
                        InterlockedCompareExchange64(&entry->timestamp_ns, now, ts);
                    }
                    
                    ReleaseSRWLockShared(&cache->lock);
                    InterlockedIncrement64(&cache->hits); 
                    return true;
                }
            }
        }
    }
    
    ReleaseSRWLockShared(&cache->lock);
    InterlockedIncrement64(&cache->misses); 
    return false;
}

bool dns_cache_insert(dns_cache_t* cache, const char* domain,
                      dns_cache_action_t action, uint32_t ttl) {
    if (!cache || !domain) return false;
    /* FIX: ttl=0 causes immediate expiration races. Reject it. */
    if (ttl == 0) return false;
    
    size_t domain_len = strlen(domain);
    if (domain_len > MAX_DOMAIN_LEN) return false;
    
    uint32_t hash = fnv1a_hash(domain); 
    
    AcquireSRWLockExclusive(&cache->lock);
    uint64_t now = get_timestamp_ns();  
    
    size_t empty_idx = (size_t)-1;
    size_t lru_idx = 0;
    uint64_t oldest_time = UINT64_MAX;
    
    for (size_t i = 0; i < cache->capacity; i++) {
        dns_cache_entry_t* entry = &cache->entries[i];
        
        if (!entry->valid) {
            if (empty_idx == (size_t)-1) empty_idx = i;
            continue;
        }
        
        if (entry->timestamp_ns + (uint64_t)entry->ttl * 1000000000ULL < now) {
            /* FIX: Use atomic decrement for lock-free stat readers */
            InterlockedDecrement64(&cache->count);
            if (empty_idx == (size_t)-1) empty_idx = i;
            /* FIX: Wipe entry to prevent stale data lingering */
            memset(entry, 0, sizeof(*entry));
            continue;
        }
        
        if (entry->hash == hash && strcmp(entry->domain, domain) == 0) { 
            entry->action = action;
            entry->ttl = ttl;
            entry->timestamp_ns = now;
            ReleaseSRWLockExclusive(&cache->lock);
            return true;
        }
        
        if (entry->timestamp_ns < oldest_time) {
            oldest_time = entry->timestamp_ns;
            lru_idx = i;
        }
    }
    
    size_t target_idx;
    if (empty_idx != (size_t)-1) {
        target_idx = empty_idx;
        InterlockedIncrement64(&cache->count);
    } else {
        target_idx = lru_idx;
        cache->evictions++;
        memset(&cache->entries[target_idx], 0, sizeof(dns_cache_entry_t));
    }
    
    dns_cache_entry_t* entry = &cache->entries[target_idx];
    strncpy(entry->domain, domain, MAX_DOMAIN_LEN);
    entry->domain[MAX_DOMAIN_LEN] = '\0';
    entry->action = action;
    entry->ttl = ttl;
    entry->timestamp_ns = now;
    entry->hash = hash;
    /* Issue write barrier before marking valid */
    _WriteBarrier();
    entry->valid = 1;
    
    ReleaseSRWLockExclusive(&cache->lock);
    InterlockedIncrement64(&cache->inserts); 
    return true;
}

bool dns_cache_invalidate(dns_cache_t* cache, const char* domain) {
    if (!cache || !domain) return false;
    size_t domain_len = strlen(domain);
    if (domain_len > MAX_DOMAIN_LEN) return false;

    uint32_t hash = fnv1a_hash(domain); 
    
    AcquireSRWLockExclusive(&cache->lock);
    for (size_t i = 0; i < cache->capacity; i++) {
        dns_cache_entry_t* entry = &cache->entries[i];
        
        if (entry->valid && entry->hash == hash && 
            strcmp(entry->domain, domain) == 0) { 
            InterlockedDecrement64(&cache->count);
            memset(entry, 0, sizeof(*entry));
            ReleaseSRWLockExclusive(&cache->lock);
            return true;
        }
    }
    
    ReleaseSRWLockExclusive(&cache->lock);
    return false;
}

void dns_cache_clear(dns_cache_t* cache) {
    if (!cache) return;
    
    AcquireSRWLockExclusive(&cache->lock);
    memset(cache->entries, 0, cache->capacity * sizeof(dns_cache_entry_t));
    InterlockedExchange64(&cache->count, 0);
    ReleaseSRWLockExclusive(&cache->lock);
}

size_t dns_cache_prune_expired(dns_cache_t* cache, uint64_t current_time_ns) {
    if (!cache) return 0;
    size_t pruned = 0;
    
    AcquireSRWLockExclusive(&cache->lock);
    for (size_t i = 0; i < cache->capacity; i++) {
        dns_cache_entry_t* entry = &cache->entries[i];
        
        if (entry->valid) {
            uint64_t ts = entry->timestamp_ns;
            uint64_t expiry = ts + (uint64_t)entry->ttl * 1000000000ULL; 
            if (expiry < current_time_ns) { 
                InterlockedDecrement64(&cache->count);
                memset(entry, 0, sizeof(*entry));
                pruned++;
            }
        }
    }
    ReleaseSRWLockExclusive(&cache->lock);
    return pruned;
}

void dns_cache_debug_print(dns_cache_t* cache) {
    if (!cache) return;
    
    AcquireSRWLockShared(&cache->lock); 
    
    printf("Cache: capacity=%zu, count=%llu\n", 
           cache->capacity, (unsigned long long)cache->count); 
    
    for (size_t i = 0; i < cache->capacity; i++) {
        dns_cache_entry_t* entry = &cache->entries[i];
        if (entry->valid) { 
            printf("  [%zu] %s (action=%d, ttl=%u, hash=%u)\n",
                   i, entry->domain, entry->action, entry->ttl, entry->hash); 
        }
    }
    
    ReleaseSRWLockShared(&cache->lock);
}

void dns_cache_get_stats(dns_cache_t* cache, uint64_t* hits, uint64_t* misses, 
                         uint64_t* evictions, uint64_t* inserts, uint64_t* count) {
    if (!cache) return;
    /* Safe, lock-free atomic reads via MSVC volatile semantics */
    if (hits) *hits = cache->hits;
    if (misses) *misses = cache->misses;
    if (evictions) *evictions = cache->evictions;
    if (inserts) *inserts = cache->inserts;
    if (count) *count = cache->count;
}

double dns_cache_utilization(dns_cache_t* cache) {
    if (!cache || cache->capacity == 0) return 0.0;
    uint64_t current_count = cache->count;
    return (double)current_count / (double)cache->capacity;
}