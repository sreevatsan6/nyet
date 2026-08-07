#ifndef HEURISTICS_H
#define HEURISTICS_H

#include <stddef.h>

// ADVISORY ONLY -- this score never blocks or clears anything by itself.
// It exists purely to flag domains for review.tsv; the deterministic
// blocklist + Pi-hole gravity cross-reference + human curation loop is
// the actual decision-making system.
//
// Both trained models (trigram classifier, bigram+MLP) were removed
// after evaluation showed all three ML approaches we tried (trigram
// bag-of-words, bigram+MLP against synthetic negatives, hand-engineered
// features + XGBoost) hit a similar ceiling: real infrastructure traffic
// (CDN nodes, cert validators, telemetry endpoints) and real tracking
// infrastructure are both auto-generated, non-human-readable strings --
// statistically close to indistinguishable from domain-string features
// alone. Rather than keep maintaining models that actively hurt
// review.tsv's signal-to-noise (an overnight run with the trained models
// enabled flagged the majority of genuinely legitimate traffic), this is
// now just the cheap, free, deterministic checks -- zero training, zero
// retraining, zero staleness risk, and it was never the primary signal
// anyway.
//
// Computes a combined suspicion score in [0.0, 1.0] for a FULL domain
// (not just its leftmost label anymore -- pass the whole thing, e.g.
// "ln-0007.ln-msedge.net", not "ln-0007"). This matters: some evasion
// patterns only show up when you look at more than one label, or at the
// domain's overall shape --
//   - ln-0007.ln-msedge.net: the leftmost label alone ("ln-0007", 7
//     chars) is too short to even trip the digit-ratio check's own
//     length gate, and none of the other single-label checks fire on it
//     either. Scoring every non-TLD label (not just the first) catches
//     this kind of thing that a single truncated label would miss
//     entirely.
//   - Domains that flatten what should be several real subdomains into
//     one hyphen-joined blob, an unusually large spread between label
//     lengths, or an outright excessive number of labels/hyphens/dots
//     relative to domain length are all domain-wide shape signals with
//     no single label to point to.
//
// If reason_out is non-NULL, it's filled with a short breakdown of which
// signals fired, for review.tsv's reason column / for eyeballing why
// something scored the way it did.
float compute_heuristic_score(const char *domain, char *reason_out, size_t reason_out_size);

#endif