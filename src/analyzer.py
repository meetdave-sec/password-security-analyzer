import re
import math

COMMON_PASSWORDS = {
    "password", "qwerty", "letmein", "welcome", "monkey", "dragon",
    "master", "shadow", "sunshine", "princess", "football", "baseball",
    "iloveyou", "trustno1", "superman", "batman",
}

DICTIONARY_WORDS = {
    "admin", "root", "login", "pass", "test", "guest", "user", "default",
    "meet", "john", "jane", "mike", "anna", "alex", "sara", "lisa",
    "james", "mark", "paul", "kate", "emma", "ryan", "luke", "adam",
    "surrey", "london", "oxford", "cambridge", "india", "china",
    "france", "paris", "berlin", "dubai", "texas", "boston", "york",
    "google", "apple", "microsoft", "amazon", "facebook", "twitter",
    "cisco", "oracle", "adobe", "intel", "samsung", "huawei",
    "cyber", "security", "network", "system", "server", "hacker",
    "dragon", "monkey", "tiger", "eagle", "falcon", "phoenix",
    "summer", "winter", "spring", "batman", "superman", "spider",
    "captain", "marvel", "avenger",
    "love", "happy", "lucky", "cool", "best", "super", "ultra",
    "mega", "alpha", "omega", "delta", "sigma",
}

KEYBOARD_WALKS = [
    "qwerty", "qwert", "werty",
    "asdfgh", "asdf", "sdfg", "dfgh",
    "zxcvbn", "zxcv", "xcvb", "cvbn",
    "qazwsx", "wsxedc",
]

YEAR_PATTERN = re.compile(r"(19[0-9]{2}|20[0-2][0-9]|2030)")

LEET_MAP = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a",
     "5": "s", "6": "g", "7": "t", "8": "b",
     "@": "a", "$": "s", "!": "i", "+": "t"}
)


_PENALTY_TABLE = [
    ("exact_common",       "common",       75),
    ("partial_common",     "common",       26),
    ("predictable_struct", "structure",    14),
    ("keyboard_walk",      "keyboard",     14),
    ("year_embedded",      "year",         10),
    ("dictionary_word",    "dictionary",    8),
    ("sequential_pattern", "sequential",    6),
    ("repeated_chars",     "repeated",      6),
    ("low_diversity",      "diversity",     4),
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
    return 0.0 if charset_size == 0 else len(password) * math.log2(charset_size)



def _tag(category: str, message: str) -> str:
    return f"[{category}] {message}"


def check_common_passwords(password: str) -> list:
    findings = []
    lower = password.lower()
    for word in COMMON_PASSWORDS:
        if word == lower:
            findings.append(
                _tag("exact_common", f"exact match to top common password: '{word}'")
            )
            return findings  
        if word in lower and len(word) >= 5:
            findings.append(
                _tag("partial_common", f"contains well-known password word: '{word}'")
            )
    return findings


def check_dictionary_words(password: str) -> list:
    findings = []
    lower = password.lower()
    deleet = lower.translate(LEET_MAP)
    seen: set = set()

    for word in DICTIONARY_WORDS:
        if word in seen:
            continue
        if word in lower or word in deleet:
            findings.append(_tag("dictionary_word", f"dictionary word detected: '{word}'"))
            seen.add(word)

    return findings


def check_keyboard_patterns(password: str) -> list:
    findings = []
    lower = password.lower()
    seen: set = set()

    for walk in KEYBOARD_WALKS:
        canonical = min(walk, walk[::-1])
        if canonical in seen:
            continue
        if walk in lower or walk[::-1] in lower:
            findings.append(_tag("keyboard_walk", f"keyboard walk: '{walk}'"))
            seen.add(canonical)

    return findings


def check_sequential_patterns(password: str) -> list:
    findings = []
    lower = password.lower()

    for label, seq in (("alphabetic", "abcdefghijklmnopqrstuvwxyz"),
                       ("numeric",    "0123456789")):
        for direction, s in (("ascending", seq), ("descending", seq[::-1])):
            for i in range(len(s) - 2):
                run = s[i:i + 3]
                if run in lower:
                    findings.append(
                        _tag("sequential_pattern",
                             f"{direction} {label} sequence: '{run}'")
                    )
                    break 

    return findings


def check_years(password: str) -> list:
    findings = []
    seen: set = set()
    for year in YEAR_PATTERN.findall(password):
        if year not in seen:
            findings.append(_tag("year_embedded", f"year embedded: '{year}'"))
            seen.add(year)
    return findings


def check_repeated_characters(password: str) -> list:
    if re.search(r"(.)\1{2,}", password):
        return [_tag("repeated_chars", "repeated characters (e.g. 'aaa', '111')")]
    return []


def check_structural_predictability(password: str) -> list:
    patterns = [
        (r"[A-Za-z]{2,}[^A-Za-z0-9][A-Za-z]{2,}[0-9]*",
         "word + symbol + word (± digits)  e.g. Meet@Surrey2024"),
        (r"[A-Za-z]{2,}[^A-Za-z0-9][0-9]+",
         "word + symbol + digits  e.g. Admin@2025"),
        (r"[A-Za-z]{2,}[0-9]+",
         "word + digits  e.g. Surrey2024"),
    ]
    for pattern, description in patterns:
        if re.fullmatch(pattern, password):
            return [_tag("predictable_struct", f"predictable template: {description}")]
    return []


def check_character_diversity(password: str) -> list:
    findings = []
    n = len(password)
    if n < 6:
        return findings

    classes = {
        "lowercase letters": sum(c.islower() for c in password),
        "uppercase letters": sum(c.isupper() for c in password),
        "digits":            sum(c.isdigit() for c in password),
    }
    for label, count in classes.items():
        if count / n > 0.82:
            findings.append(
                _tag("low_diversity",
                     f"low diversity: dominated by {label} ({count / n:.0%})")
            )
    return findings


def _calculate_penalty(raw_issues: list) -> int:
    worst: dict = {}
    for issue in raw_issues:
        for tag, category, points in _PENALTY_TABLE:
            if tag in issue:
                worst[category] = max(worst.get(category, 0), points)
                break
    return min(sum(worst.values()), 85)


def _entropy_to_base_score(entropy: float) -> int:
    if entropy >= 100:
        return 76
    elif entropy >= 85:
        return 70
    elif entropy >= 75:
        return 68
    elif entropy >= 65:
        return 62
    elif entropy >= 50:
        return 52
    elif entropy >= 38:
        return 47
    elif entropy >= 25:
        return 30
    elif entropy >= 15:
        return 16
    else:
        return 5


def _length_bonus(length: int) -> int:
    if length >= 20:
        return 22
    elif length >= 16:
        return 16
    elif length >= 12:
        return 10
    elif length >= 8:
        return 4
    return 0


def classify_strength(score: int) -> str:
    if score <= 18:
        return "Very Weak"
    elif score <= 38:
        return "Weak"
    elif score <= 58:
        return "Moderate"
    elif score <= 77:
        return "Strong"
    else:
        return "Very Strong"



def analyze_password(password: str) -> dict:
    if not password:
        return {
            "score": 0,
            "strength": "Very Weak",
            "entropy": 0.0,
            "issues": ["empty password"],
        }

    entropy = estimate_entropy(password)
    raw_issues: list = []
    raw_issues.extend(check_common_passwords(password))
    raw_issues.extend(check_dictionary_words(password))
    raw_issues.extend(check_keyboard_patterns(password))
    raw_issues.extend(check_sequential_patterns(password))
    raw_issues.extend(check_years(password))
    raw_issues.extend(check_repeated_characters(password))
    raw_issues.extend(check_structural_predictability(password))
    raw_issues.extend(check_character_diversity(password))
  
    issues = [re.sub(r"^\[[^\]]+\] ", "", i) for i in raw_issues]
   
    base_score   = _entropy_to_base_score(entropy)
    length_bonus = _length_bonus(len(password))
    penalty      = _calculate_penalty(raw_issues)

    score = max(0, min(base_score + length_bonus - penalty, 100))

    return {
        "score": score,
        "strength": classify_strength(score),
        "entropy": round(entropy, 2),
        "issues": issues,
    }


if __name__ == "__main__":
    samples = [
        # (password,                              expected_band)
        ("123456",                                "Very Weak"),
        ("password",                              "Very Weak"),
        ("qwerty",                                "Very Weak"),
        ("Meet123",                               "Weak"),
        ("Surrey2024",                            "Weak"),
        ("Admin@2025",                            "Weak"),
        ("India@123",                             "Weak"),
        ("Password@123",                          "Weak"),
        ("Meet@Surrey2024",                       "Moderate"),
        ("CyberSecurity#1",                       "Moderate"),
        ("T9$vL2!qPx",                            "Strong"),
        ("X#9mK!vQ2@pL",                          "Very Strong"),
        ("correct-horse-Battery-staple!9",        "Very Strong"),
    ]

    print(
        f"\n{'Password':<35} {'Expected':<13} {'Score':>5}  "
        f"{'Actual':<13}  {'Entropy':>9}  Pass?"
    )
    print("-" * 92)
    for pw, expected in samples:
        r = analyze_password(pw)
        passed = "✓" if r["strength"] == expected else "✗"
        print(
            f"{pw:<35} {expected:<13} {r['score']:>5}  {r['strength']:<13}  "
            f"{r['entropy']:>8.1f}b  {passed}"
        )
        for issue in r["issues"]:
            print(f"    ⚠ {issue}")
    print()
