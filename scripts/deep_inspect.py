#!/usr/bin/env python3
"""
Deep Inspection Engine for adversarial domain classification.
Implements a 7-stage scoring pipeline:
1. Canonicalization (Leetspeak, deduplication)
2. Exact Knowledge Base Match
3. Fast Automaton Substring (Regex Trie)
4. Trigram Similarity
5. Damerau-Levenshtein Distance
6. Substring Windowing (Word Segmentation lite)
7. Weighted Scoring
"""

import sys
import re
from collections import defaultdict
import time

# ---------- 1. Knowledge Bases & Thresholds ----------

# Known-vendor exact-match list. If it matches, block it -- no fuzzy
# scoring needed for these, they're confirmed ad/tracking infrastructure.
KNOWN_VENDORS = {
    # Ad-Tech & RTB
    'ezojs', 'ezodn', 'btloader', 'confiant-integrations', 'openweb', 
    'sharethis', 'doubleverify', 'flashtalking', 'zephr', 'dianomi', 
    'kameleoon', 'liadm', 'pubmatic', 'rubiconproject', 'criteo', 
    'taboola', 'scorecardresearch', 'demdex', 'rokt', 'liveperson', 
    'ensighten', 'iterable', 'videoamp', 'similarweb', 'serpapi', 
    'dwin1', 'cognitohq', 'primis', 'sharethrough', 'sail-horizon', 
    '4dex', 'contextweb', 'onetag-sys', 'socdm', 'creativecdn', 
    'adsrvr', 'adform', 'gumgum', 'seedtag', 'openx', 'outbrain', 
    'pgammedia', 'qntv', 'r2b2',
    
    # Trackers hiding as utilities/analytics
    'spserv', 'birdeatsbug', 'siftscience', 'smct', 'anthropic', 
    'sardine', 'zeronaught', 'appfoliowebsites', 'braze', 
    'branch', 'adjust', 'appsflyer', 'kochava', 'mparticle',
}

# High-risk stems we want to find anywhere in the string.
SUSPICIOUS_STEMS = {
    'metric', 'metrix', 'telemetry', 'analytics', 'analtyics', 
    'track', 'pixel', 'beacon', 'logger', 'ingest', 'advert', 
    'segment', 'measure', 'consent', 'collect'
}

# Compile Aho-Corasick equivalent for rapid substring matching
STEM_AUTOMATON = re.compile(f"({'|'.join(SUSPICIOUS_STEMS)})", re.IGNORECASE)

# Known big-tech telemetry endpoints that use rotating prefixes
TOXIC_SUFFIXES = [
    '-pa.googleapis.com', '-pa.clients6.google.com',
    '.icloud.com', '.iadsdk.apple.com', 
    '.log-global.aliyuncs.com', '.alicdn.com'
]

SCORE_THRESHOLD = 75 # Out of 100

# ---------- 2. Core Algorithms ----------

def canonicalize(domain: str) -> str:
    """Step 1: Strip separators, resolve leetspeak, collapse dupes."""
    # Strip TLD and delimiters
    s = re.sub(r'\.[a-z]{2,6}$', '', domain.lower())
    s = re.sub(r'[\.\-\_]', '', s)
    
    # Normalize leetspeak
    leetspeak = {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '8': 'b'}
    s = ''.join(leetspeak.get(c, c) for c in s)
    
    # Collapse consecutive identical characters (meeetrics -> metrics)
    if not s: return ""
    collapsed = [s[0]]
    for char in s[1:]:
        if char != collapsed[-1]:
            collapsed.append(char)
            
    return ''.join(collapsed)

def get_trigrams(s: str) -> set:
    """Generate trigrams for string similarity comparison."""
    if len(s) < 3: return set([s])
    return set(s[i:i+3] for i in range(len(s)-2))

def trigram_similarity(s1: str, s2: str) -> float:
    """Step 4: Jaccard similarity of trigrams."""
    tri1, tri2 = get_trigrams(s1), get_trigrams(s2)
    if not tri1 or not tri2: return 0.0
    intersection = len(tri1 & tri2)
    union = len(tri1 | tri2)
    return intersection / union if union > 0 else 0.0

def damerau_levenshtein(s1: str, s2: str) -> int:
    """Step 5: Edit distance with transpositions (metrix -> metrics = 1)."""
    d = {}
    len1, len2 = len(s1), len(s2)
    for i in range(-1, len1 + 1): d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1): d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i-1, j)] + 1,      # deletion
                d[(i, j-1)] + 1,      # insertion
                d[(i-1, j-1)] + cost  # substitution
            )
            # Transposition
            if i > 0 and j > 0 and s1[i] == s2[j-1] and s1[i-1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i-2, j-2)] + cost)
                
    return d[(len1 - 1, len2 - 1)]

def fuzzy_substring_score(canonical_str: str) -> tuple:
    """
    Step 6: Sliding window across the canonical domain to find embedded
    fuzzy matches of suspicious stems (e.g., catching 'metrix' inside 
    'onlinemetrixsecurity').
    """
    highest_score = 0
    best_match = None
    best_stem = None
    
    for stem in SUSPICIOUS_STEMS:
        stem_len = len(stem)
        # Check windows of size: stem_len-1 to stem_len+1
        for window_size in [stem_len - 1, stem_len, stem_len + 1]:
            if window_size < 3 or window_size > len(canonical_str):
                continue
                
            for i in range(len(canonical_str) - window_size + 1):
                window = canonical_str[i:i+window_size]
                
                # Fast trigram check before expensive Levenshtein
                tri_sim = trigram_similarity(window, stem)
                if tri_sim > 0.3: 
                    edit_dist = damerau_levenshtein(window, stem)
                    
                    # Calculate confidence score
                    if edit_dist == 0:
                        score = 100
                    elif edit_dist == 1:
                        score = 85
                    elif edit_dist == 2 and stem_len > 5:
                        score = 65
                    else:
                        score = 0
                        
                    if score > highest_score:
                        highest_score = score
                        best_match = window
                        best_stem = stem
                        
    return highest_score, best_match, best_stem

# ---------- 3. The Assessment Pipeline ----------

def assess_domain(domain: str) -> tuple:
    """Run the 7-stage pipeline and return (score, reason)."""
    score = 0
    reasons = []
    
    # Stage 1: Fast suffix checks (Cloud/OS telemetry routing)
    for suffix in TOXIC_SUFFIXES:
        if domain.endswith(suffix):
            return 100, f"Known toxic suffix ({suffix})"
            
    # Stage 2: Exact Vendor Match
    for label in domain.lower().split('.'):
        if label in KNOWN_VENDORS:
            return 100, f"Known tracker vendor ({label})"
            
    # Stage 3: Canonicalization
    canon = canonicalize(domain)
    if not canon: return 0, "Clean"
    
    # Stage 4: Substring Automaton (Exact stems within canonical string)
    match = STEM_AUTOMATON.search(canon)
    if match:
        score += 90
        reasons.append(f"Contains exact stem '{match.group(1)}'")
        
    # Stages 5-7: Trigram + Levenshtein sliding window
    fuzzy_score, fuzzy_match, stem = fuzzy_substring_score(canon)
    
    if fuzzy_score > 0 and fuzzy_score > score:
        score = fuzzy_score
        reasons.append(f"Fuzzy match '{fuzzy_match}' resembles '{stem}' (Score: {fuzzy_score})")
        
    if score >= SCORE_THRESHOLD:
        return score, " | ".join(reasons)
        
    return score, "Clean"

# ---------- 4. Execution ----------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 deep_inspect.py filtered_input.tsv")
        sys.exit(1)

    input_file = sys.argv[1]
    
    print("\n[*] Initializing Deep Inspection Pipeline...")
    start_time = time.time()
    caught_count = 0
    
    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or 'no_suspicious_pattern_found' not in line:
                continue
                
            domain = line.split('\t')[0]
            score, reason = assess_domain(domain)
            
            if score >= SCORE_THRESHOLD:
                print(f"[\033[91mCAUGHT\033[0m] {domain:<35} -> {reason}")
                caught_count += 1
                
    elapsed = time.time() - start_time
    print(f"\n[*] Deep scan complete in {elapsed:.2f}s.")
    print(f"[*] Caught {caught_count} additional obfuscated trackers.")

if __name__ == '__main__':
    main()