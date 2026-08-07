#include "heuristics.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

// is_suspicious_label() lives in nyet.c itself (the original entropy
// check). Prototype here so this file doesn't depend on include order.
int is_suspicious_label(const char *label);

/* ============================================================
 * Consonant-run check
 * ============================================================ */
static inline bool is_consonant_char(char c) {
    c = (char)tolower((unsigned char)c);
    return (c >= 'a' && c <= 'z') &&
           !(c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u');
}

// Flags if the label has a sequence of consonants > 4.
static bool is_consonant_suspicious(const char* domain) {
    if (!domain) return false;

    char label[256];
    size_t i = 0;
    while (domain[i] != '.' && domain[i] != '\0' && i < 255) {
        label[i] = domain[i];
        i++;
    }
    label[i] = '\0';

    int max_run = 0;
    int current_run = 0;

    for (size_t j = 0; j < i; j++) {
        if (is_consonant_char(label[j])) {
            current_run++;
            if (current_run > max_run) max_run = current_run;
        } else {
            current_run = 0;
        }
    }

    return (max_run > 4);
}

/* ============================================================
 * Vowel-ratio check
 * ============================================================ */
// Flags labels with an unusually low (<15%, len>10) or unusually high
// (>60%, len>=5) vowel ratio.
static bool is_vowel_suspicious(const char* domain) {
    if (!domain) return false;

    char label[256];
    size_t i = 0;
    while (domain[i] != '.' && domain[i] != '\0' && i < 255) {
        label[i] = domain[i];
        i++;
    }
    label[i] = '\0';

    int len = (int)i;
    if (len == 0) return false;

    int vowels = 0;
    for (int j = 0; j < len; j++) {
        char c = (char)tolower((unsigned char)label[j]);
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') vowels++;
    }

    float ratio = (float)vowels / len;

    if (len > 10 && ratio < 0.15f) return true;
    if (len >= 5 && ratio > 0.60f) return true;

    return false;
}

/* ============================================================
 * Digit-ratio check
 * ============================================================ */
// Flags labels with an unusually high proportion of digits.
//
// Calibration note: this needs a MINIMUM LENGTH gate, or it immediately
// re-flags exactly the short CDN/infra labels that already burned every
// other approach in this pipeline -- "t1", "t2", "x1", "x2" (real,
// legitimate node labels seen in production logs) are 50% digits at
// length 2. Requiring len >= 8 before this check even engages excludes
// that whole short-label class; the >0.4 ratio threshold on top of that
// targets genuinely numeric-heavy strings (tracking IDs, session tokens
// embedded in a hostname) rather than a single incidental digit.
static bool is_digit_suspicious(const char* domain) {
    if (!domain) return false;

    char label[256];
    size_t i = 0;
    while (domain[i] != '.' && domain[i] != '\0' && i < 255) {
        label[i] = domain[i];
        i++;
    }
    label[i] = '\0';

    int len = (int)i;
    if (len < 8) return false; // see calibration note above

    int digits = 0;
    for (int j = 0; j < len; j++) {
        if (isdigit((unsigned char)label[j])) digits++;
    }

    float ratio = (float)digits / len;
    return ratio > 0.4f;
}

/* ============================================================
 * frequent_words: hand-built trie matching common legit tech words as
 * substrings (google, user, content, cloud, api, auth, stream, mail,
 * static). The ONE signal here that can REDUCE suspicion -- everything
 * else can only push toward "suspicious".
 * ============================================================ */

#define FW_ALPHABET_SIZE 27 // a-z plus '-'
#define FW_IDX(c) ((c) - 'a')

static inline int fw_char_to_node_idx(char c) {
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c == '-') return 26;
    return -1;
}

typedef struct {
    short next[FW_ALPHABET_SIZE];
    bool is_end;
} FwTrieNode;

static const FwTrieNode FW_TRIE[] = {
    { .next = { [FW_IDX('g')]=1, [FW_IDX('u')]=6, [FW_IDX('c')]=9, [FW_IDX('a')]=14, [FW_IDX('s')]=19, [FW_IDX('m')]=25 }, .is_end = false }, // [0] ROOT

    { .next = { [FW_IDX('o')]=2 }, .is_end = false }, // 1
    { .next = { [FW_IDX('o')]=3 }, .is_end = false }, // 2
    { .next = { [FW_IDX('g')]=4 }, .is_end = false }, // 3
    { .next = { [FW_IDX('l')]=5 }, .is_end = false }, // 4
    { .next = { [FW_IDX('e')]=29 }, .is_end = false }, // 5

    { .next = { [FW_IDX('s')]=7 }, .is_end = false }, // 6
    { .next = { [FW_IDX('e')]=8 }, .is_end = false }, // 7
    { .next = { [FW_IDX('r')]=30 }, .is_end = false }, // 8

    { .next = { [FW_IDX('o')]=10, [FW_IDX('l')]=31 }, .is_end = false }, // 9
    { .next = { [FW_IDX('n')]=11 }, .is_end = false }, // 10
    { .next = { [FW_IDX('t')]=12 }, .is_end = false }, // 11
    { .next = { [FW_IDX('e')]=13 }, .is_end = false }, // 12
    { .next = { [FW_IDX('n')]=33 }, .is_end = false }, // 13

    { .next = { [FW_IDX('p')]=15, [FW_IDX('u')]=16 }, .is_end = false }, // 14
    { .next = { [FW_IDX('i')]=34 }, .is_end = false }, // 15
    { .next = { [FW_IDX('t')]=17 }, .is_end = false }, // 16
    { .next = { [FW_IDX('h')]=35 }, .is_end = false }, // 17

    { .next = { [FW_IDX('t')]=20 }, .is_end = false }, // 19
    { .next = { [FW_IDX('r')]=21, [FW_IDX('a')]=22 }, .is_end = false }, // 20
    { .next = { [FW_IDX('e')]=23 }, .is_end = false }, // 21
    { .next = { [FW_IDX('a')]=24 }, .is_end = false }, // 22
    { .next = { [FW_IDX('m')]=36 }, .is_end = false }, // 23
    { .next = { [FW_IDX('t')]=37 }, .is_end = false }, // 24

    { .next = { [FW_IDX('a')]=26 }, .is_end = false }, // 25
    { .next = { [FW_IDX('i')]=27 }, .is_end = false }, // 26
    { .next = { [FW_IDX('l')]=38 }, .is_end = false }, // 27

    [29] = { .is_end = true, .next = {0} },  // google
    [30] = { .is_end = true, .next = {0} },  // user
    [31] = { .next = { [FW_IDX('o')]=32 }, .is_end = false },
    [32] = { .next = { [FW_IDX('u')]=39 }, .is_end = false },
    [33] = { .next = { [FW_IDX('t')]=40 }, .is_end = false },
    [34] = { .is_end = true, .next = {0} },  // api
    [35] = { .is_end = true, .next = {0} },  // auth
    [36] = { .is_end = true, .next = {0} },  // stream
    [37] = { .next = { [FW_IDX('i')]=41 }, .is_end = false },
    [38] = { .is_end = true, .next = {0} },  // mail
    [39] = { .next = { [FW_IDX('d')]=42 }, .is_end = false },
    [40] = { .is_end = true, .next = {0} },  // content
    [41] = { .next = { [FW_IDX('c')]=43 }, .is_end = false },
    [42] = { .is_end = true, .next = {0} },  // cloud
    [43] = { .is_end = true, .next = {0} }   // static
};

// Returns the number of distinct legitimate keywords matched as
// substrings, e.g. "googleusercontent" -> 3 (google, user, content).
static int count_legit_subsequences(const char* domain) {
    if (!domain) return 0;

    char label[256];
    size_t len = 0;
    while (domain[len] != '.' && domain[len] != '\0' && len < 255) {
        label[len] = (char)tolower((unsigned char)domain[len]);
        len++;
    }
    label[len] = '\0';

    int matches = 0;

    for (size_t start = 0; start < len; start++) {
        int node = 0;
        for (size_t curr = start; curr < len; curr++) {
            int idx = fw_char_to_node_idx(label[curr]);
            if (idx == -1) break;

            node = FW_TRIE[node].next[idx];
            if (node == 0) break;

            if (FW_TRIE[node].is_end) matches++;
        }
    }

    return matches;
}

/* ============================================================
 * Whole-domain shape checks
 * ============================================================
 * Everything above this point (entropy, consonant run, vowel ratio,
 * digit ratio, legit-word substrings) only ever looks at ONE isolated
 * label at a time -- these functions were always label-scoped, and that
 * hasn't changed. What changed is which labels get handed to them, and
 * what else gets checked at the domain level. See heuristics.h for why:
 * some evasion shapes only show up across multiple labels or in the
 * domain's overall structure, not in any single label alone.
 */

#define HEUR_MAX_LABELS 32 // plenty for any real-world domain; a domain
                            // that legitimately needs more than this is
                            // already unusual enough that hitting this
                            // cap and folding it into fired_too_many_labels
                            // is the correct behavior, not a bug.

// Splits `domain` into up to HEUR_MAX_LABELS labels. Returns the count.
// `label_buf` must be at least as large as `domain`'s length + 1; labels
// are NUL-terminated substrings written into it back-to-back, with
// `out_labels[i]` pointing at the start of each one.
static int split_labels(const char *domain, char *label_buf, size_t label_buf_size,
                         char **out_labels, int max_labels) {
    size_t len = 0;
    while (domain[len] != '\0' && len + 1 < label_buf_size) {
        label_buf[len] = (char)tolower((unsigned char)domain[len]);
        len++;
    }
    label_buf[len] = '\0';

    int count = 0;
    char *start = label_buf;
    for (char *p = label_buf; ; p++) {
        if (*p == '.' || *p == '\0') {
            int is_end = (*p == '\0');
            *p = '\0';
            if (count < max_labels) out_labels[count++] = start;
            if (is_end) break;
            start = p + 1;
        }
    }
    return count;
}

// Fires if there are more labels than any normal domain legitimately
// needs. Real infra (even deeply-nested CDN/telemetry hostnames) rarely
// exceeds this; tracking domains stacking labels to fit more encoded
// junk into the query, or hitting HEUR_MAX_LABELS outright, both land
// here.
#define MAX_NORMAL_LABELS 6
static bool is_too_many_labels(int label_count) {
    return label_count > MAX_NORMAL_LABELS;
}

// Fires when label lengths are wildly uneven -- the "(50 random chars).
// domain.com" shape, where one label carries a long encoded token and
// the rest are short and ordinary. Only meaningful with >=2 non-TLD
// labels to compare; a single-label domain has nothing to be uneven
// against.
#define LABEL_LENGTH_SPREAD_THRESHOLD 20
static bool is_label_length_variance_suspicious(char **labels, int non_tld_count) {
    if (non_tld_count < 2) return false;
    int min_len = 256, max_len = 0;
    for (int i = 0; i < non_tld_count; i++) {
        int len = (int)strlen(labels[i]);
        if (len < min_len) min_len = len;
        if (len > max_len) max_len = len;
    }
    return (max_len - min_len) > LABEL_LENGTH_SPREAD_THRESHOLD;
}

// Fires when dots+hyphens (plus any other non a-z0-9 character) make up
// too large a fraction of the whole domain. A normal domain is mostly
// letters/digits with the occasional separator; a domain built to look
// "structured" purely to seem legitimate (or to cram in more encoded
// fields) tends to be separator-heavy instead.
#define SYMBOL_RATIO_THRESHOLD 0.30f
#define SYMBOL_RATIO_MIN_LEN   12 // below this, one or two separators
                                  // alone can already exceed the ratio --
                                  // not a meaningful signal on short
                                  // domains.
static bool is_symbol_ratio_suspicious(const char *domain) {
    size_t total = strlen(domain);
    if (total < SYMBOL_RATIO_MIN_LEN) return false;

    size_t symbols = 0;
    for (size_t i = 0; i < total; i++) {
        char c = domain[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
            symbols++;
        }
    }
    return ((float)symbols / (float)total) > SYMBOL_RATIO_THRESHOLD;
}

// Fires when a domain has almost no real subdomain structure (<=2
// labels total, i.e. just "something.tld") but that "something" is
// itself heavily hyphen-segmented -- looks like several logical
// subdomains got flattened into one hyphen-joined label instead of
// using real dot-separated subdomains. Distinct from the general hyphen
// count below: this specifically requires the flattening pattern (few
// real labels, one of them hyphen-heavy), not just "has some hyphens".
#define HYPHEN_FLATTEN_MIN_HYPHENS 3
static bool is_hyphen_flattened(char **labels, int label_count) {
    if (label_count > 2) return false; // has real subdomain structure, not flattened
    int hyphens = 0;
    for (const char *p = labels[0]; *p; p++) if (*p == '-') hyphens++;
    return hyphens >= HYPHEN_FLATTEN_MIN_HYPHENS;
}

// Fires when the domain uses a LOT of hyphens overall, regardless of
// structure. Deliberately the lowest-weighted signal in the whole
// combiner (see WEIGHT_EXCESSIVE_HYPHENS below) -- plenty of completely
// legitimate infra is hyphen-heavy by convention (apple-native-relay.
// apple.com, amp-api-edge.apps.apple.com, bag-cdn-lb-itunes-apple.com.
// akadns.net are all real, all fine). This check exists to contribute
// to an ensemble decision alongside other signals, never to flag
// anything on its own -- see the combiner's threshold-crossing math.
#define EXCESSIVE_HYPHENS_THRESHOLD 5
static bool is_excessive_hyphens(const char *domain) {
    int hyphens = 0;
    for (const char *p = domain; *p; p++) if (*p == '-') hyphens++;
    return hyphens >= EXCESSIVE_HYPHENS_THRESHOLD;
}

/* ============================================================
 * Combiner
 * ============================================================
 * Plain weighted sum over independent cheap signals -- no max()/trained-
 * model term. Each signal alone stays comfortably below the 0.5
 * threshold on its own, so a single heuristic firing in isolation won't
 * push a domain into review.tsv; it takes roughly two-plus agreeing
 * signals to cross that line. This is deliberate, same reasoning as
 * before the domain-wide checks were added: a single confident (and
 * often wrong) signal flooding review.tsv is exactly the failure mode
 * that got the trained models removed in the first place. More signals
 * now feed the sum than before, so these weights are a starting point,
 * not gospel -- watch review.tsv's actual signal-to-noise after this
 * ships and retune WEIGHT_* / the individual thresholds above against
 * real traffic, the same way the original four were never claimed to be
 * perfectly calibrated either.
 *
 * WEIGHT_EXCESSIVE_HYPHENS is deliberately the lowest weight in the set
 * -- per-request, this needs to stay "one component that contributes,"
 * never enough on its own to flag legitimate hyphen-heavy CDN/infra
 * hostnames for review.
 */

#define WEIGHT_ENTROPY            0.20f
#define WEIGHT_CONSONANT          0.15f
#define WEIGHT_VOWEL              0.15f
#define WEIGHT_DIGIT              0.15f
#define WEIGHT_WORD_STEP          0.15f   // per matched word, up to WORD_MATCH_CAP
#define WORD_MATCH_CAP            2
#define WEIGHT_TOO_MANY_LABELS    0.20f
#define WEIGHT_LABEL_VARIANCE     0.20f
#define WEIGHT_SYMBOL_RATIO       0.20f
#define WEIGHT_HYPHEN_FLATTEN     0.20f
#define WEIGHT_EXCESSIVE_HYPHENS  0.10f   // deliberately low -- see comment above

float compute_heuristic_score(const char *domain, char *reason_out, size_t reason_out_size) {
    char label_buf[256];
    char *labels[HEUR_MAX_LABELS];
    int label_count = split_labels(domain, label_buf, sizeof(label_buf), labels, HEUR_MAX_LABELS);

    if (label_count == 0) {
        if (reason_out && reason_out_size > 0) reason_out[0] = '\0';
        return 0.0f;
    }

    // Per-label checks (entropy/consonant/vowel/digit/word-match) now run
    // over EVERY non-TLD label, not just the leftmost one -- OR'd
    // together, so any single label tripping a check is enough for that
    // check to count. This is the actual fix for misses like
    // "ln-0007.ln-msedge.net": the leftmost label alone ("ln-0007") is
    // too short to trip the digit-ratio gate, but scoring every label
    // means "ln-msedge" (or whichever label is actually suspicious) still
    // gets looked at instead of silently skipped.
    //
    // Excludes only the final label (assumed TLD, e.g. "com"/"net") --
    // a rough approximation (doesn't know about multi-part effective
    // TLDs like "co.uk"), but scoring an actual TLD label serves no
    // purpose and the existing length gates on these checks mean short
    // real TLDs essentially never fire anyway.
    int non_tld_count = (label_count > 1) ? label_count - 1 : label_count;

    int fired_entropy = 0, fired_consonant = 0, fired_vowel = 0, fired_digit = 0;
    int word_matches = 0;
    for (int i = 0; i < non_tld_count; i++) {
        if (is_suspicious_label(labels[i]))      fired_entropy   = 1;
        if (is_consonant_suspicious(labels[i]))  fired_consonant = 1;
        if (is_vowel_suspicious(labels[i]))      fired_vowel     = 1;
        if (is_digit_suspicious(labels[i]))      fired_digit     = 1;
        word_matches += count_legit_subsequences(labels[i]);
    }

    int fired_too_many_labels = is_too_many_labels(label_count);
    int fired_label_variance  = is_label_length_variance_suspicious(labels, non_tld_count);
    int fired_symbol_ratio    = is_symbol_ratio_suspicious(domain);
    int fired_hyphen_flatten  = is_hyphen_flattened(labels, label_count);
    int fired_excessive_hyphens = is_excessive_hyphens(domain);

    float score = 0.0f;
    if (fired_entropy)          score += WEIGHT_ENTROPY;
    if (fired_consonant)        score += WEIGHT_CONSONANT;
    if (fired_vowel)            score += WEIGHT_VOWEL;
    if (fired_digit)            score += WEIGHT_DIGIT;
    if (fired_too_many_labels)  score += WEIGHT_TOO_MANY_LABELS;
    if (fired_label_variance)   score += WEIGHT_LABEL_VARIANCE;
    if (fired_symbol_ratio)     score += WEIGHT_SYMBOL_RATIO;
    if (fired_hyphen_flatten)   score += WEIGHT_HYPHEN_FLATTEN;
    if (fired_excessive_hyphens) score += WEIGHT_EXCESSIVE_HYPHENS;

    if (word_matches > 0) {
        int capped = (word_matches > WORD_MATCH_CAP) ? WORD_MATCH_CAP : word_matches;
        score -= WEIGHT_WORD_STEP * (float)capped;
    }

    if (score < 0.0f) score = 0.0f;
    if (score > 1.0f) score = 1.0f;

    if (reason_out && reason_out_size > 0) {
        snprintf(reason_out, reason_out_size,
                 "entropy=%d consonant=%d vowel=%d digit=%d words=%d "
                 "labels=%d toomany=%d variance=%d symbols=%d flatten=%d hyphens=%d final=%.2f",
                 fired_entropy, fired_consonant, fired_vowel, fired_digit, word_matches,
                 label_count, fired_too_many_labels, fired_label_variance, fired_symbol_ratio,
                 fired_hyphen_flatten, fired_excessive_hyphens, score);
    }

    return score;
}