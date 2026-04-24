import re
import math

COMMON_PATTERNS = [
    "1234", "123456", "1234567890",
    "password", "qwerty", "admin", "letmein"
]

KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn"
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
            findings.append(f"common pattern: {pattern}")

    return findings


def detect_keyboard_patterns(password: str):
    lower = password.lower()
    return any(pattern in lower for pattern in KEYBOARD_PATTERNS)


def detect_weak_structure(password: str):
    findings = []

    # Only flag simple whole-password structures, not coincidental sub-matches.
    # Pattern: ALL letters then ALL digits, nothing else (e.g. "Meet123", "hello99")
    if re.fullmatch(r"[A-Za-z]+[0-9]+", password):
        findings.append("predictable pattern: letters followed by numbers")

    # Pattern: ALL letters, then ONE symbol block, then ALL digits (e.g. "Meet@123")
    if re.fullmatch(r"[A-Za-z]+[^A-Za-z0-9]+[0-9]+", password):
        findings.append("predictable pattern: word + symbol + numbers")

    # Repeated characters anywhere (aaa, 111) — fine to check globally
    if re.search(r"(.)\1{2,}", password):
        findings.append("repeated characters detected")

    return findings


def classify_strength(score: int) -> str:
    if score <= 30:
        return "Very Weak"
    elif score <= 50:
        return "Weak"
    elif score <= 70:
        return "Moderate"
    elif score <= 85:
        return "Strong"
    else:
        return "Very Strong"


def detect_sequences(password: str):
    findings = []
    lower = password.lower()

    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789"
    ]

    for seq in sequences:
        # Forward: stop at first match to avoid flooding with overlapping windows
        for i in range(len(seq) - 3):
            pattern = seq[i:i+4]
            if pattern in lower:
                findings.append(f"sequential pattern detected: {pattern}")
                break

        # Reverse: same — report once
        rev_seq = seq[::-1]
        for i in range(len(rev_seq) - 3):
            pattern = rev_seq[i:i+4]
            if pattern in lower:
                findings.append(f"reverse sequential pattern detected: {pattern}")
                break

    return findings


def analyze_password(password: str):
    entropy = estimate_entropy(password)

    issues = check_common_patterns(password)

    if detect_keyboard_patterns(password):
        issues.append("keyboard pattern detected")

    structure_issues = detect_weak_structure(password)
    issues.extend(structure_issues)

    sequence_issues = detect_sequences(password)
    issues.extend(sequence_issues)

    score = 0

    if len(password) < 8:
        issues.append("password must contain at least 8 characters")
        score += 5
    elif len(password) >= 12:
        score += 25
    else:
        score += 15

    if entropy > 60:
        score += 30
    elif entropy > 40:
        score += 20
    else:
        score += 10

    # Graduated penalty so one minor issue doesn't tank a strong password
    for issue in issues:
        lower_issue = issue.lower()
        if any(k in lower_issue for k in ("common pattern", "keyboard pattern", "at least 8")):
            score -= 15  # critical
        elif any(k in lower_issue for k in ("sequential", "repeated")):
            score -= 8   # moderate
        else:
            score -= 5   # minor (predictable structure)

    score = max(0, min(score, 100))

    return {
        "score": score,
        "strength": classify_strength(score),
        "entropy": round(entropy, 2),
        "issues": issues
    }


if __name__ == "__main__":
    samples = [
        "abc",
        "password",
        "Meet123",
        "Meet@123",
        "qwerty123",
        "Tr0ub4dor&3",
        "correct-horse-Battery-staple!9",
        "X#9mK!vQ2@pL",
    ]

    for pw in samples:
        r = analyze_password(pw)
        print(f"{pw:<35} score={r['score']:>3}  {r['strength']:<12}  entropy={r['entropy']:.1f}")
        for issue in r["issues"]:
            print(f"  ⚠ {issue}")
        print()