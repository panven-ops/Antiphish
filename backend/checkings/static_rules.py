import re
import Levenshtein
import ipaddress
from models import CheckResult
from checkings.keywords_synonyms import normalize


KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "google", "microsoft",
    "netflix", "facebook", "instagram", "twitter", "ebay",
    "bankofamerica", "chase", "wellsfargo", "dhl", "fedex"
]

PHISHING_KEYWORDS = [
    "urgent", "verify your account", "suspended", "confirm your identity",
    "click immediately", "your account has been", "unusual activity",
    "update your information", "limited time", "act now"
]

SCAM_PHONE_PREFIXES = [
    "+92", "+234", "+254", "+233", "+256",  # Pakistan, Nigeria, Kenya, Ghana, Uganda
    "+91", "+855", "+66",                    # India, Cambodia, Thailand (scam hubs)
]

STOPWORDS = {"your", "you", "to", "in", "on", "the", "a", "an", "is", "has", "been", "and", "of", "for"}


FUZZY_RATIO = 0.7

def strip_stopwords(phrase: str) -> str:
    return " ".join(w for w in phrase.split() if w not in STOPWORDS)


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def strip_port(value: str) -> str:
    parts = value.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return value


def normalize_domain(domain: str) -> str:
    replacements = { "0": "o", "1": "l", "3": "e", "5": "s", "@": "a" }
    domain = domain.lower()

    for old, new in replacements.items():
        domain = domain.replace(old, new)

    domain = re.sub(r"[^a-z]", "", domain)

    return domain


URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
DOMAIN_REGEX = re.compile(r'(?:https?://)?(?:www\.)?([^/\s]+)')

def extract_url(url: str) -> list[str]:

    return URL_REGEX.findall(url)

def extract_domain(domain: str) -> str:

    match = DOMAIN_REGEX.match(domain)

    if match:
        return match.group(1).lower()

    return ""

def check_typosquatting(text: str) -> CheckResult:
    urls = extract_url(text)
    found = []

    for url in urls:
        domain = extract_domain(url)
        base = domain.split(".")[0]
        normalized = normalize_domain(base)

        for brand in KNOWN_BRANDS:
            distance = Levenshtein.distance(normalized, brand)

            if brand in normalized or 0 < distance <= 2:
                found.append(f"{domain} which is similar to {brand}")

    if found:
        return CheckResult(name = "typosquatting",
                           passed = False,
                           score = 30,
                           detail = f"Suspicious domains found: {','.join(found)}")

    return CheckResult(name = "typosquatting",
                       passed = True,
                       score = 0,
                       detail = "Nothing that is related to typosquatting found")

def check_brand_impersonation(text: str) -> CheckResult:
    urls = extract_url(text)
    text_lower = text.lower()
    found = []

    mentioned_brands = [b for b in KNOWN_BRANDS if b in text_lower]

    for url in urls:
        domain = extract_domain(url)

        for brand in mentioned_brands:
            if brand not in domain:
                found.append(f"'{brand}' mentioned but link goes to {domain}")

    if found:
        return CheckResult(name = "brand_impersonation",
                    passed = False,
                    score = 40,
                    detail = f"Brand mismatch: {', '.join(found)}")

    return CheckResult(name = "brand_impersonation",
                passed = True,
                score= 0,
                detail = "No brand impersonation detected")

def check_keywords(text: str) -> CheckResult:
    words = re.findall(r"[a-z']+", text.lower())
    found = []

    for phrase in PHISHING_KEYWORDS:
        phrase_words = phrase.split()
        window_size = len(phrase_words)

        if len(phrase) < 5:
            if phrase in text.lower():
                found.append(phrase)
            continue

        phrase_core = normalize(strip_stopwords(phrase))
        if not phrase_core:
            continue

        matched = False
        best_ratio = 0.0
        for i in range(len(words) - window_size + 1):
            window = " ".join(words[i:i + window_size])
            window_core = normalize(strip_stopwords(window))

            if not window_core:
                continue

            ratio = Levenshtein.ratio(window_core, phrase_core)
            if ratio > best_ratio:
                best_ratio = ratio
            if ratio >= FUZZY_RATIO:
                matched = True
                break

        if matched:
            found.append(phrase)

    if found:
        score = min(len(found) * 10, 30)
        return CheckResult(name="suspicious_keywords",
                           passed=False,
                           score=score,
                           detail=f"Found: {', '.join(found)}")

    return CheckResult(name="suspicious_keywords",
                       passed=True,
                       score=0,
                       detail="No suspicious keywords found in the text")

def check_phone_prefix(text: str) -> CheckResult:

    for prefix in SCAM_PHONE_PREFIXES:
        if re.search(re.escape(prefix), text):

            return CheckResult(name = "scam_phonenumber",
                               passed = False,
                               score = 25,
                               detail = f"High-risk country prefix: {prefix}")

    return CheckResult(name = "scam_phonenumber",
                       passed = True,
                       score = 0,
                       detail = "No suspicious prefixes found in the phonenumber")

def run_static_checks(text: str, input_type: str) -> list[CheckResult]:
    if input_type == "phone":
        return [check_phone_prefix(text)]

    return [check_brand_impersonation(text),
            check_keywords(text),
            check_typosquatting(text)]
