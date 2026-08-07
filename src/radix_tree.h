#ifndef RADIX_TREE_H
#define RADIX_TREE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>

 /*
 The original "lock-free RCU" approach here had a real use-after-free
 window and added real complexity for no measured benefit over a plain
 SRWLock at this project's actual concurrency scale.

 Swapping/publishing uses Exclusive mode, ensuring safe memory reclamation
 without use-after-free conditions.
*/
typedef enum {
    RADIX_STATUS_BLOCKED = 0,
    RADIX_STATUS_ALLOWED = 1,
    RADIX_STATUS_REVIEW  = 2
} radix_status_t;

typedef struct {
    radix_status_t status;
    uint32_t       ttl;
    uint32_t       hit_count;   /* bumped atomically by radix_lookup on every match */
    uint32_t       last_seen;   /* seconds since DNS_EPOCH, set atomically alongside hit_count */
    uint8_t        source;      /* cast to/from your existing EntrySource enum (S/H/M/G) */
    float          ml_score;
    const char     *note;       /* OWNED, heap copy made internally by radix_insert (see
                                    that function) -- deliberately NOT the "caller must
                                    keep this alive" contract this struct started with.
                                    That contract is exactly what breaks under hot-reload:
                                    every reload builds a fresh tree, the old one gets
                                    node_free()'d, and an unowned note pointer would leak
                                    (nothing else in this codebase tracks or frees it) on
                                    every single reload. Freed in node_free() alongside
                                    the rest of the entry. */
} radix_entry_t;


typedef struct radix_node {
    char              *label;
    size_t            label_len;
    radix_entry_t     *entry;
    struct radix_node **children;        // dynamic array of child pointers,
                                          // not a linked list anymore
    size_t            children_count;
    size_t            children_capacity;
    bool              children_sorted;   // true => find_child() can binary-
                                          // search this node's children.
                                          // Set true by the recursive sort
                                          // pass that runs once at
                                          // radix_publish()/radix_tree_swap()
                                          // time (whole builder, one pass,
                                          // not per-insert). Flipped false
                                          // on THIS node specifically the
                                          // moment radix_tree_insert_live()
                                          // appends a new child to it --
                                          // appending to an otherwise-sorted
                                          // array breaks the invariant
                                          // immediately, "mostly sorted" is
                                          // not sorted for bsearch purposes.
                                          // Falls back to linear scan for
                                          // just that one node until the
                                          // next full reload re-sorts it --
                                          // acceptable, since a node that
                                          // was JUST live-inserted into has
                                          // few children by definition.
} radix_node_t;

typedef struct {
    radix_node_t *root;
} radix_tree_builder_t;

typedef struct {
    SRWLOCK lock;
    radix_node_t *root;
} radix_tree_t;

typedef struct {
    bool           matched;
    radix_status_t status;
    uint32_t       ttl;
    uint32_t       hit_count;
    uint32_t       last_seen;
    uint8_t        source;
    float          ml_score;
    const char     *note;       /* Still owned by the tree, NOT the caller -- valid only
                                    until the next radix_tree_swap()/radix_tree_free().
                                    Copy it (e.g. sanitize_log_field) if you need it to
                                    outlive that. */
} radix_lookup_result_t;

int radix_builder_init(radix_tree_builder_t *builder);
// Parameter order matches BlockEntry's own field grouping in nyet.c, not
// alphabetical -- ttl/hit_count/last_seen/source are the "bookkeeping"
// fields that came from an existing TSV row (or default to 0 for a brand
// new entry), ml_score/note are the "content" fields. hit_count/last_seen
// are inputs here (what load_blocklist parsed off disk, or 0 for a fresh
// insert) -- radix_lookup() takes over updating them live afterward.
int radix_insert(radix_tree_builder_t *builder, const char *domain, radix_status_t status,
                 uint32_t ttl, uint32_t hit_count, uint32_t last_seen, uint8_t source,
                 float ml_score, const char *note);
void radix_publish(radix_tree_t *tree, radix_tree_builder_t *builder);
int radix_tree_init(radix_tree_t *tree);

// Incremental insert directly into the ALREADY-PUBLISHED live tree --
// distinct from radix_insert()+radix_publish()/radix_tree_swap(), which
// build a whole separate tree and replace the root wholesale. That
// wholesale-replace model is right for a periodic full blocklist.tsv
// reload; it is NOT right for the frequent, single-domain inserts that
// happen during live traffic (every first-seen domain getting cached by
// flag_for_review, every Pi-gravity confirmation) -- doing a full
// rebuild-and-swap for each of those would either discard the rest of
// the live tree (if built fresh) or require cloning the entire existing
// tree on every single insert (if built from a copy), neither of which
// is acceptable on a per-query path.
//
// This instead takes the tree's own exclusive lock directly and mutates
// its already-published root in place -- same soundness argument as
// radix_tree_swap: AcquireSRWLockExclusive cannot succeed while any
// reader holds the shared lock (radix_lookup holds it for its entire
// walk), so no reader ever observes a partially-constructed insert.
// Returns 0 on success, -1 on OOM (same convention as radix_insert),
// -2 for bad arguments, -3 if the tree has no published root yet (call
// radix_publish first, at startup, before anything can call this).
int radix_tree_insert_live(radix_tree_t *tree, const char *domain, radix_status_t status,
                           uint32_t ttl, uint32_t hit_count, uint32_t last_seen, uint8_t source,
                           float ml_score, const char *note);

radix_lookup_result_t radix_lookup(radix_tree_t *tree, const char *domain);
void radix_tree_swap(radix_tree_t *tree, radix_tree_builder_t *builder);
void radix_tree_free(radix_tree_t *tree);
void radix_builder_free(radix_tree_builder_t *builder);

#endif /* RADIX_TREE_H */
