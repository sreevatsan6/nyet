#include "radix_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Matches nyet.c's own DNS_EPOCH exactly (seconds since 2020-01-01 UTC).
// Duplicated here rather than shared via a common header on purpose --
// this keeps radix_tree.c a self-contained module with no dependency on
// nyet.c's own macros, at the cost of needing to keep these two values
// in sync by hand if either ever changes (extremely unlikely).
#define RADIX_EPOCH 1577836800

static char *dup_label(const char *label, size_t len) {
    char *copy = (char *)malloc(len + 1);
    if (!copy) return NULL;
    memcpy(copy, label, len);
    copy[len] = '\0';
    return copy;
}

static radix_node_t *node_create(const char *label, size_t label_len) {
    radix_node_t *node = (radix_node_t *)calloc(1, sizeof(radix_node_t));
    if (!node) return NULL;

    node->label = dup_label(label, label_len);
    if (!node->label) {
        free(node);
        return NULL;
    }
    node->label_len = label_len;
    node->children_sorted = true; // vacuously true with 0 children
    return node;
}

// Byte-safe, length-aware three-way compare -- like strcmp, but doesn't
// assume NUL-terminated input (labels here are {pointer,length} pairs,
// see split_domain_rtl) and correctly orders same-prefix, different-
// length labels (e.g. "com" vs "comcast") instead of relying on a NUL
// byte to break the tie.
static int label_compare(const char *a, size_t a_len, const char *b, size_t b_len) {
    size_t min_len = a_len < b_len ? a_len : b_len;
    int cmp = memcmp(a, b, min_len);
    if (cmp != 0) return cmp;
    if (a_len < b_len) return -1;
    if (a_len > b_len) return 1;
    return 0;
}

// qsort() comparator for sort_children_recursive() below. Only ever
// invoked single-threaded (builder construction, before publish) --
// never during a live radix_lookup(), so no concurrency concern with
// qsort's own internal state.
static int node_ptr_compare(const void *a, const void *b) {
    const radix_node_t *na = *(const radix_node_t * const *)a;
    const radix_node_t *nb = *(const radix_node_t * const *)b;
    return label_compare(na->label, na->label_len, nb->label, nb->label_len);
}

static radix_node_t *find_child(radix_node_t *parent, const char *label, size_t len) {
    if (parent->children_sorted) {
        // Hand-rolled binary search, NOT libc bsearch(): bsearch's
        // comparator signature has no clean way to pass the search key
        // alongside a real per-call context without smuggling it through
        // a static/global -- a real hazard here, since find_child runs
        // under a SHARED lock with many concurrent reader threads. A
        // plain local-variable binary search has no such state to race on.
        size_t lo = 0, hi = parent->children_count;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            radix_node_t *cand = parent->children[mid];
            int cmp = label_compare(cand->label, cand->label_len, label, len);
            if (cmp == 0) return cand;
            if (cmp < 0) lo = mid + 1;
            else hi = mid;
        }
        return NULL;
    }

    // Unsorted fallback -- only ever hit for a node that's had a live
    // insert appended to it since the last full reload (see
    // children_sorted's own comment). Same linear scan as before this
    // change, just over an array instead of a linked list.
    for (size_t i = 0; i < parent->children_count; i++) {
        radix_node_t *child = parent->children[i];
        if (child->label_len == len && memcmp(child->label, label, len) == 0) {
            return child;
        }
    }
    return NULL;
}

// Recursively sorts every node's children array by label and marks the
// whole subtree children_sorted. Called ONCE per publish/swap (see
// radix_publish()/radix_tree_swap()), on the builder's root, before it
// ever becomes visible to a reader -- not per-insert. A bulk load of N
// domains pays one O(n log n) sort per node, not N re-sorts.
static void sort_children_recursive(radix_node_t *node) {
    if (node->children_count > 1) {
        qsort(node->children, node->children_count, sizeof(radix_node_t *), node_ptr_compare);
    }
    node->children_sorted = true;
    for (size_t i = 0; i < node->children_count; i++) {
        sort_children_recursive(node->children[i]);
    }
}

static void node_free(radix_node_t *node) {
    if (!node) return;

    for (size_t i = 0; i < node->children_count; i++) {
        node_free(node->children[i]);
    }
    free(node->children);

    if (node->entry) {
        // note is now an owned heap copy (see radix_entry_t's comment) --
        // cast away const to free it. Standard, safe idiom: constness is
        // a compile-time contract for callers ("don't mutate this
        // through the pointer you got"), not a property free() cares
        // about at the type level.
        if (node->entry->note) free((void *)node->entry->note);
        free(node->entry);
    }
    if (node->label) free(node->label);
    free(node);
}

// Appends `child` to parent->children, growing the array (doubling) if
// needed. Marks parent as unsorted -- an append always breaks whatever
// sort order existed, "mostly sorted" is not sorted for binary search
// purposes. Returns 0 on success, -1 on OOM (parent/child untouched on
// failure -- caller's existing rollback logic doesn't need to know
// this array grew at all if it didn't).
static int append_child(radix_node_t *parent, radix_node_t *child) {
    if (parent->children_count == parent->children_capacity) {
        size_t new_cap = parent->children_capacity == 0 ? 4 : parent->children_capacity * 2;
        radix_node_t **new_arr = (radix_node_t **)realloc(parent->children, new_cap * sizeof(radix_node_t *));
        if (!new_arr) return -1;
        parent->children = new_arr;
        parent->children_capacity = new_cap;
    }
    parent->children[parent->children_count++] = child;
    parent->children_sorted = false;
    return 0;
}

static int insert_path(radix_tree_builder_t *builder,
                       const char **labels, const size_t *label_lens, int label_count,
                       radix_status_t status, uint32_t ttl, uint32_t hit_count,
                       uint32_t last_seen, uint8_t source, float ml_score, const char *note) {

    radix_node_t *current = builder->root;
    radix_node_t *first_new = NULL;
    radix_node_t *first_new_parent = NULL;

    for (int i = 0; i < label_count; i++) {
        const char *label = labels[i];
        size_t len = label_lens[i];

        radix_node_t *child = find_child(current, label, len);
        if (!child) {
            child = node_create(label, len);
            if (!child) {
                /* OOM Rollback: this specific insert never appended
                   anything (node_create failed before append_child was
                   even called), so there's nothing to unlink here --
                   just free whatever chain existed from an EARLIER
                   iteration of this same loop, if any. */
                if (first_new) {
                    first_new_parent->children_count--; // first_new is
                        // always the last thing appended to this parent
                        // within this single insert_path() call -- see
                        // append_child(); nothing else could have been
                        // appended to first_new_parent after it.
                    node_free(first_new);
                }
                return -1;
            }

            if (append_child(current, child) != 0) {
                // append itself failed (OOM growing the array) -- child
                // was allocated but never attached anywhere, free it
                // directly; it's not reachable from first_new_parent at
                // all, so no array bookkeeping to undo for THIS node.
                node_free(child);
                if (first_new) {
                    first_new_parent->children_count--;
                    node_free(first_new);
                }
                return -1;
            }

            if (!first_new) {
                first_new = child;
                first_new_parent = current;
            }
        }
        current = child;
    }

    // Duplicate note BEFORE touching current->entry at all -- if this
    // fails, current->entry (a possibly pre-existing entry from an
    // earlier insert into this same builder) must be left completely
    // untouched, not half-replaced.
    char *note_copy = NULL;
    if (note) {
        note_copy = _strdup(note);
        if (!note_copy) {
            if (first_new) {
                first_new_parent->children_count--; // see append_child's comment
                node_free(first_new);
            }
            return -1;
        }
    }

    if (current->entry) {
        if (current->entry->note) free((void *)current->entry->note);
        free(current->entry);
    }
    
    current->entry = (radix_entry_t *)malloc(sizeof(radix_entry_t));
    if (!current->entry) {
        if (note_copy) free(note_copy);
        if (first_new) {
            first_new_parent->children_count--; // see append_child's comment
            node_free(first_new);
        }
        return -1;
    }

    current->entry->status     = status;
    current->entry->ttl        = ttl;
    current->entry->hit_count  = hit_count;
    current->entry->last_seen  = last_seen;
    current->entry->source     = source;
    current->entry->ml_score   = ml_score;
    current->entry->note       = note_copy;

    return 0;
}

// max_labels is always passed as 128 by every caller below -- see
// check_domain()/radix_insert() etc. Wire-format ceiling: a DNS name is
// at most 255 bytes, and the shortest possible label is 1 byte + 1
// length-prefix byte, so (255+1)/2 = 128 is the real worst case. (An
// earlier version of this cap was 16, which silently truncated
// tokenization past the 16th label -- letting 17+ label domains bypass
// the blocklist entirely. Don't lower this without re-deriving the math.)
static int split_domain_rtl(const char *domain, char *label_buf, size_t buf_size,
                            const char **labels, size_t *label_lens, int max_labels) {
    if (!domain || !*domain) return -1;

    size_t len = strlen(domain);
    if (len >= buf_size) return -1;

    for (size_t i = 0; i <= len; i++) {
        char c = domain[i];
        label_buf[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }

    int count = 0;
    char *label_end = label_buf + len;

    while (label_end > label_buf && count < max_labels) {
        char *label_start = label_end - 1;
        while (label_start > label_buf && *label_start != '.') {
            label_start--;
        }
        if (*label_start == '.') {
            label_start++;
        }

        size_t label_len = (size_t)(label_end - label_start);
        if (label_len > 0) {
            labels[count] = label_start;
            label_lens[count] = label_len;
            count++;
        }

        if (label_start == label_buf) break;
        label_end = label_start - 1;
    }

    return count;
}

int radix_builder_init(radix_tree_builder_t *builder) {
    if (!builder) return -1;
    builder->root = node_create("", 0);
    if (!builder->root) return -1;
    return 0;
}

void radix_builder_free(radix_tree_builder_t *builder) {
    if (!builder) return;
    node_free(builder->root);
    builder->root = NULL;
}

int radix_insert(radix_tree_builder_t *builder, const char *domain, radix_status_t status,
                 uint32_t ttl, uint32_t hit_count, uint32_t last_seen, uint8_t source,
                 float ml_score, const char *note) {
    if (!builder || !builder->root || !domain) return -2;

    char label_buf[512];
    const char *labels[128];
    size_t label_lens[128];

    int count = split_domain_rtl(domain, label_buf, sizeof(label_buf), labels, label_lens, 128);
    if (count <= 0) return -2;

    return insert_path(builder, labels, label_lens, count, status, ttl, hit_count, last_seen, source, ml_score, note);
}

int radix_tree_init(radix_tree_t *tree) {
    if (!tree) return -1;
    InitializeSRWLock(&tree->lock);
    tree->root = NULL;
    return 0;
}

void radix_publish(radix_tree_t *tree, radix_tree_builder_t *builder) {
    if (!tree || !builder) return;

    // Sort BEFORE the lock, not after -- the builder's tree is still
    // exclusively owned by this thread here, nothing else can see it
    // yet, so there's nothing to protect. Doing it under the lock would
    // just make every reader wait longer for no reason.
    if (builder->root) sort_children_recursive(builder->root);

    AcquireSRWLockExclusive(&tree->lock);
    tree->root = builder->root;
    ReleaseSRWLockExclusive(&tree->lock);

    builder->root = NULL;
}

int radix_tree_insert_live(radix_tree_t *tree, const char *domain, radix_status_t status,
                           uint32_t ttl, uint32_t hit_count, uint32_t last_seen, uint8_t source,
                           float ml_score, const char *note) {
    if (!tree || !domain) return -2;

    char label_buf[512];
    const char *labels[128];
    size_t label_lens[128];
    int count = split_domain_rtl(domain, label_buf, sizeof(label_buf), labels, label_lens, 128);
    if (count <= 0) return -2;

    AcquireSRWLockExclusive(&tree->lock);

    if (!tree->root) {
        ReleaseSRWLockExclusive(&tree->lock);
        return -3; // no published root yet -- radix_publish() must run first
    }

    // insert_path() only ever mutates nodes REACHABLE from the root it's
    // given (via each node's children array, growing it with
    // append_child()); it never reassigns the root pointer itself.
    // Aliasing a throwaway builder's `root` field to the tree's actual
    // live root and calling the exact same insert_path used by the
    // full-rebuild path is therefore safe here: every new node gets
    // attached under the live tree exactly as if this were a fresh
    // builder, and tree->root's own value never changes. Note this also
    // means a live insert never re-sorts anything -- only the ONE node a
    // new child gets appended to loses its children_sorted flag (see
    // that field's own comment); nothing here calls
    // sort_children_recursive() at all, on purpose.
    radix_tree_builder_t live_alias;
    live_alias.root = tree->root;
    int rc = insert_path(&live_alias, labels, label_lens, count, status, ttl, hit_count, last_seen, source, ml_score, note);

    ReleaseSRWLockExclusive(&tree->lock);
    return rc;
}

radix_lookup_result_t radix_lookup(radix_tree_t *tree, const char *domain) {
    radix_lookup_result_t result = {0};
    if (!tree || !domain || !*domain) {
        result.matched = false;
        return result;
    }

    char label_buf[512];
    const char *labels[128];
    size_t label_lens[128];

    int count = split_domain_rtl(domain, label_buf, sizeof(label_buf), labels, label_lens, 128);
    if (count <= 0) {
        result.matched = false;
        return result;
    }

    bool allow_found = false;
    bool block_found = false;
    bool review_found = false;
    radix_entry_t best_entry = {0};
    // The LIVE node whose entry ultimately wins, so hit_count/last_seen
    // can be bumped on the real thing -- best_entry above is a snapshot
    // copy for building the return value, not something you can update
    // in place and have it mean anything.
    radix_node_t *matched_node = NULL;

    AcquireSRWLockShared(&tree->lock);
    radix_node_t *current = tree->root;

    if (current) {
        for (int i = 0; i < count; i++) {
            size_t len = label_lens[i];
            radix_node_t *child = find_child(current, labels[i], len);
            if (!child) break;

            current = child;

            if (current->entry) {
                switch (current->entry->status) {
                    case RADIX_STATUS_ALLOWED:
                        allow_found = true;
                        best_entry = *current->entry;
                        matched_node = current;
                        break;
                    case RADIX_STATUS_BLOCKED:
                        if (!allow_found) {
                            block_found = true;
                            best_entry = *current->entry;
                            matched_node = current;
                        }
                        break;
                    case RADIX_STATUS_REVIEW:
                        if (!allow_found && !block_found) {
                            review_found = true;
                            best_entry = *current->entry;
                            matched_node = current;
                        }
                        break;
                }
            }
        }
    }

    // Bump hit_count/last_seen on the actual winning node, still under
    // the shared lock -- same pattern as nyet.c's own check_domain: an
    // atomic increment/exchange needs no more than a shared lock here,
    // since only tree mutation (insert/publish/swap) needs exclusive.
    // Matches ALL statuses (ALLOWED too), not just BLOCKED/REVIEW --
    // hit_count exists on every entry type, no reason to special-case.
    if (matched_node) {
        InterlockedIncrement((LONG *)&matched_node->entry->hit_count);
        
                             InterlockedExchange((LONG *)&matched_node->entry->last_seen,
                             (LONG)(time(NULL) - RADIX_EPOCH));
        // Reflect the just-applied update in what we hand back, rather
        // than the pre-increment snapshot taken during the walk above.
        best_entry.hit_count = matched_node->entry->hit_count;
        best_entry.last_seen = matched_node->entry->last_seen;
    }

    ReleaseSRWLockShared(&tree->lock);

    if (allow_found || block_found || review_found) {
        result.matched   = true;
        result.status    = best_entry.status;
        result.ttl       = best_entry.ttl;
        result.hit_count = best_entry.hit_count;
        result.last_seen = best_entry.last_seen;
        result.source    = best_entry.source;
        result.ml_score   = best_entry.ml_score;
        result.note      = best_entry.note;
    }

    return result;
}

void radix_tree_swap(radix_tree_t *tree, radix_tree_builder_t *builder) {
    if (!tree || !builder) return;

    // Same reasoning as radix_publish: sort before taking the lock, the
    // incoming builder tree is still unshared at this point.
    if (builder->root) sort_children_recursive(builder->root);

    AcquireSRWLockExclusive(&tree->lock);
    radix_node_t *old_root = tree->root;
    tree->root = builder->root;
    ReleaseSRWLockExclusive(&tree->lock);

    /* Safe to free immediately. Exclusive lock guarantees 0 active readers. */
    if (old_root) {
        node_free(old_root);
    }
    builder->root = NULL;
}

void radix_tree_free(radix_tree_t *tree) {
    if (!tree) return;

    AcquireSRWLockExclusive(&tree->lock);
    radix_node_t *old_root = tree->root;
    tree->root = NULL;
    ReleaseSRWLockExclusive(&tree->lock);

    if (old_root) {
        node_free(old_root);
    }
}