import re
import math

COMMON_PATTERNS = [
    "1234", "password", "qwerty", "admin", "letmein", "1234567890"
]

def estimate_entropy(password: str) -> float:
    charset_size = 0

    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset_size += 32

    if charset_size == 0:
        return 0

    return len(password) * math.log2(charset_size)


def check_common_patterns(password: str):
    findings = []
    lower = password.lower()

    for pattern in COMMON_PATTERNS:
        if pattern in lower:
            findings.append(pattern)

    return findings


def analyze_password(password: str):
    entropy = estimate_entropy(password)
    issues = check_common_patterns(password)

    score = 0

    
    if len(password) >= 12:
        score += 30
    elif len(password) >= 8:
        score += 20
    else:
        score += 10

   
    if entropy > 60:
        score += 40
    elif entropy > 40:
        score += 25
    else:
        score += 10

  
    score -= len(issues) * 10

    score = max(0, min(score, 100))

    return {
        "score": score,
        "entropy": round(entropy, 2),
        "issues": issues
    }
