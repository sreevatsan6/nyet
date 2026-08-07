#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DNS_ACTION_NONE = 0,
    DNS_ACTION_BLOCK,
    DNS_ACTION_ALLOW,
    DNS_ACTION_REDIRECT
} dns_cache_action_t;

typedef struct dns_cache dns_cache_t;

dns_cache_t* dns_cache_init(size_t capacity);
void dns_cache_free(dns_cache_t* cache);

bool dns_cache_lookup(dns_cache_t* cache, const char* domain,
                      dns_cache_action_t* action, uint32_t* ttl);

bool dns_cache_insert(dns_cache_t* cache, const char* domain,
                      dns_cache_action_t action, uint32_t ttl);

bool dns_cache_invalidate(dns_cache_t* cache, const char* domain);
void dns_cache_clear(dns_cache_t* cache);
size_t dns_cache_prune_expired(dns_cache_t* cache, uint64_t current_time_ns);

/* Dropped const from these. They require internal locking. */
void dns_cache_debug_print(dns_cache_t* cache);
void dns_cache_get_stats(dns_cache_t* cache, uint64_t* hits, uint64_t* misses, 
                         uint64_t* evictions, uint64_t* inserts, uint64_t* count);
double dns_cache_utilization(dns_cache_t* cache);

#ifdef __cplusplus
}
#endif

#endif