SYNONYMS = {
    "authenticate": "verify",
    "validate": "verify",
    "confirm": "verify",
    "login": "account",
    "log-in": "account",
    "signin": "account",
    "sign-in": "account",
    "credentials": "account",
    "profile": "account",
    "identity": "account",
    "details": "information",
    "data": "information",
    "restricted": "suspended",
    "locked": "suspended",
    "disabled": "suspended",
    "blocked": "suspended",
    "deactivated": "suspended",
    "terminated": "suspended",
    "immediate": "urgent",
    "immediately": "urgent",
    "asap": "urgent",
    "unrecognized": "unusual",
    "unfamiliar": "unusual",
    "suspicious": "unusual",
}


def normalize(text: str) -> str:
    words = text.lower().split()
    return " ".join(SYNONYMS.get(w, w) for w in words)
