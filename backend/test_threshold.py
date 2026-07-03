"""
Threshold-tuning script for fuzzy keyword matching (Levenshtein-based).
Used to empirically compare false-positive/true-positive rates across
different similarity thresholds before choosing the production value (0.70).
Run manually — not part of the CI test suite.
"""


import Levenshtein
from checkings.keywords_synonyms import normalize

KEYWORDS = ["urgent", "verify your account", "suspended", "confirm your identity",
    "click immediately", "your account has been", "unusual activity",
    "update your information", "limited time", "act now"]

LEGITIMATE = [
    "please verify your email preferences in settings",
    "your subscription has been confirmed",
    "thank you for your continued support",
    "we have updated our terms of service",
    "your order has shipped and is on its way",
]

PHISHING_PARAPHRASES = [
    "authenticate your login details",
    "please confirm who you are",
    "your access has been restricted",
    "immediate response needed to avoid suspension",
]

def sliding_window_ratio(text, keyword):
    text = normalize(text)
    keyword = normalize(keyword)
    words = text.split()
    kw_len = len(keyword.split())
    best_ratio = 0
    best_window = ""
    for i in range(len(words) - kw_len + 1):
        window = " ".join(words[i:i+kw_len])
        ratio = Levenshtein.ratio(window, keyword)
        if ratio > best_ratio:
            best_ratio = ratio
            best_window = window
    return best_ratio, best_window

def test_threshold(threshold):
    print(f"\n=== Threshold: {threshold} ===")
    print("-- Legitimate--")
    false_positives = 0
    for phrase in LEGITIMATE:
        for kw in KEYWORDS:
            ratio, window = sliding_window_ratio(phrase, kw)
            if ratio >= threshold:
                print(f"  ❌ FALSE POSITIVE: '{window}' ~ '{kw}' (ratio={ratio:.2f})")
                false_positives += 1

    print("-- Phishing paraphrases --")
    true_positives = 0
    for phrase in PHISHING_PARAPHRASES:
        matched = False
        for kw in KEYWORDS:
            ratio, window = sliding_window_ratio(phrase, kw)
            if ratio >= threshold:
                print(f"CAUGHT: '{window}' ~ '{kw}' (ratio={ratio:.2f})")
                matched = True
        if not matched:
            print(f"MISSED: '{phrase}'")
        else:
            true_positives += 1

    print(f"\nSummary: {false_positives} false positives, {true_positives}/{len(PHISHING_PARAPHRASES)} caught")

test_threshold(0.70)
test_threshold(0.65)
