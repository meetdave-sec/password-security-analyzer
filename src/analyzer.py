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

    if re.fullmatch(r"[A-Za-z]+[0-9]+", password):
        findings.append("predictable pattern: letters followed by numbers")

    if re.fullmatch(r"[A-Za-z]+[^A-Za-z0-9]+[0-9]+", password):
        findings.append("predictable pattern: word + symbol + numbers")

    if re.search(r"(.)\1{2,}", password):
        findings.append("repeated characters detected")

    return findings


def detect_sequences(password: str):
    findings = []
    lower = password.lower()

    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789"
    ]

    for seq in sequences:
        for i in range(len(seq) - 3):
            pattern = seq[i:i+4]
            if pattern in lower:
                findings.append(f"sequential pattern detected: {pattern}")
                break

        rev_seq = seq[::-1]
        for i in range(len(rev_seq) - 3):
            pattern = rev_seq[i:i+4]
            if pattern in lower:
                findings.append(f"reverse sequential pattern detected: {pattern}")
                break

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


def analyze_password(password: str):
    entropy = estimate_entropy(password)

    issues = []
    issues.extend(check_common_patterns(password))

    if detect_keyboard_patterns(password):
        issues.append("keyboard pattern detected")

    issues.extend(detect_weak_structure(password))
    issues.extend(detect_sequences(password))

    if entropy >= 80:
        entropy_score = 90
    elif entropy >= 60:
        entropy_score = 75
    elif entropy >= 40:
        entropy_score = 55
    elif entropy >= 20:
        entropy_score = 35
    else:
        entropy_score = 10


    length_bonus = min(len(password) * 2, 20)

 
    penalty = 0

    for issue in issues:
        issue_lower = issue.lower()

        if "common pattern" in issue_lower or "keyboard" in issue_lower:
            penalty += 20
        elif "sequential" in issue_lower or "too short" in issue_lower:
            penalty += 15
        else:
            penalty += 5

    penalty = min(penalty, 40)

  
    score = entropy_score + length_bonus - penalty
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
