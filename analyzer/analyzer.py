import math
import re
import json
import hashlib
from typing import Dict, List, Any

# default character set sizes
CHARSET_SIZES = {
    'lower': 26,
    'upper': 26,
    'digits': 10,
    'symbols': 32  
}

# heuristics for scoring
WEIGHTS = {
    'entropy': 0.5,
    'length_bonus': 0.1,
    'dictionary': -0.5,
    'patterns': -0.3,
    'breach': -1.0
}

DEFAULT_GUESSES_PER_SEC = 1e9 


def charset_size(password: str) -> int:
    size = 0
    if re.search(r'[a-z]', password):
        size += CHARSET_SIZES['lower']
    if re.search(r'[A-Z]', password):
        size += CHARSET_SIZES['upper']
    if re.search(r'\d', password):
        size += CHARSET_SIZES['digits']
    # symbols: anything not alnum
    if re.search(r'[^A-Za-z0-9]', password):
        size += CHARSET_SIZES['symbols']
    return size or 1


def entropy_bits(password: str) -> float:
    """Calculate Shannon-like entropy estimate in bits: length * log2(charset_size)"""
    cs = charset_size(password)
    if cs <= 1:
        return 0.0
    return len(password) * math.log2(cs)


def time_to_crack_seconds(entropy_bits: float, guesses_per_second: float = DEFAULT_GUESSES_PER_SEC) -> float:
    """Estimate time to try all combinations (2^entropy / guesses_per_second)."""
    combinations = 2 ** entropy_bits
    return combinations / guesses_per_second


def readable_time(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    units = [
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1)
    ]
    parts = []
    for name, count in units:
        if seconds >= count:
            val = int(seconds // count)
            parts.append(f"{val} {name}")
            seconds -= val * count
    return ", ".join(parts[:2]) if parts else "0 seconds"


def load_wordlist(path: str) -> set:
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()


# pattern checks
def has_repeated_chars(password: str) -> bool:
    return bool(re.search(r'(.)\1\1', password))  # 3 same chars in a row


def has_sequence(password: str, length: int = 4) -> bool:
    pwd = password.lower()
    for i in range(len(pwd) - (length - 1)):
        chunk = pwd[i:i+length]
        if all(ord(chunk[j+1]) - ord(chunk[j]) == 1 for j in range(len(chunk)-1)):
            return True
    return False


def keyboard_pattern(password: str) -> bool:
    patterns = ['qwerty', 'asdf', 'zxcv', '1234', '4321', 'password']
    return any(p in password.lower() for p in patterns)


def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8')).hexdigest()


class PasswordReport:
    def __init__(self, password: str,
                 wordlist_paths: List[str] = None,
                 common_passwords_path: str = None,
                 guesses_per_second: float = DEFAULT_GUESSES_PER_SEC):
        self.password = password
        self.guesses_per_second = guesses_per_second
        self.wordlist_paths = wordlist_paths or []
        self.common_passwords_path = common_passwords_path
        self.result: Dict[str, Any] = {}
        # load lists
        self.common = load_wordlist(common_passwords_path) if common_passwords_path else set()
        self.wordlists = set()
        for p in self.wordlist_paths:
            self.wordlists |= load_wordlist(p)

    def analyze(self) -> Dict[str, Any]:
        p = self.password
        ent = entropy_bits(p)
        cs = charset_size(p)
        ttc = time_to_crack_seconds(ent, self.guesses_per_second)

        # dictionary checks
        lower = p.lower()
        dict_match = any(w in lower for w in self.wordlists) if self.wordlists else False
        common_match = lower in self.common if self.common else False

        # pattern checks
        repeated = has_repeated_chars(p)
        sequence = has_sequence(p)
        keyboard = keyboard_pattern(p)

        # basic length bonus
        length_bonus = 0.0
        if len(p) >= 12:
            length_bonus = 1.0
        elif len(p) >= 8:
            length_bonus = 0.5

        breached = False
        if self.common:
            breached = sha1_hex(p).lower() in (sha1_hex(w) for w in self.common)

        score = 50.0  # baseline
        score += (min(ent, 80) / 80.0) * WEIGHTS['entropy'] * 100
        score += length_bonus * WEIGHTS['length_bonus'] * 100
        if dict_match or common_match:
            score += WEIGHTS['dictionary'] * 100
        if repeated or sequence or keyboard:
            score += WEIGHTS['patterns'] * 100
        if breached:
            score += WEIGHTS['breach'] * 100

        # clamp
        score = max(0.0, min(100.0, score))

        self.result = {
            'password': '<redacted>',
            'length': len(p),
            'charset_size': cs,
            'entropy_bits': round(ent, 2),
            'time_to_crack_seconds': ttc,
            'time_to_crack_readable': readable_time(ttc),
            'guesses_per_second': self.guesses_per_second,
            'dictionary_match': dict_match,
            'common_password_match': common_match,
            'repeated_chars': repeated,
            'sequence_detected': sequence,
            'keyboard_pattern': keyboard,
            'breached': breached,
            'score': round(score, 2),
            'rating': self._rating(score)
        }
        return self.result

    def _rating(self, score: float) -> str:
        if score >= 85:
            return "Excellent"
        if score >= 70:
            return "Strong"
        if score >= 50:
            return "Moderate"
        if score >= 25:
            return "Weak"
        return "Very Weak"

    def to_json(self) -> str:
        return json.dumps(self.result, indent=2)


