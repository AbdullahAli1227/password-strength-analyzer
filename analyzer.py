"""Core logic for the Password Strength Analyzer."""
import hashlib, math, re, secrets, string, urllib.request

COMMON = {"password","123456","12345678","123456789","qwerty","admin","letmein","welcome",
          "iloveyou","abc123","password1","111111","monkey","dragon","football","login"}
WALKS = ("qwerty","asdf","zxcv","1qaz","qaz","123456","abcdef","password","admin","welcome")
WORDS = """apple river cloud tiger ocean maple rocket silver forest planet coffee violin
anchor meadow thunder pixel garden bridge falcon marble island candle jungle lantern orbit
canyon harbor velvet summit breeze copper desert ember galaxy horizon ivory jasmine kernel""".split()
RATES = {"Online attack (100 guesses/hour)": 100/3600,
         "Offline, Argon2/bcrypt (10K/s)": 1e4,
         "Offline, fast hash on GPU rig (100B/s)": 1e11}

def charset(pw):
    return sum(n for n, p in [(26,"[a-z]"),(26,"[A-Z]"),(10,r"\d"),(33,r"[^A-Za-z0-9]")] if re.search(p, pw))

def patterns(pw):
    low, issues = pw.lower(), []
    if low in COMMON: issues.append("Appears in the most common passwords list")
    if any(w in low for w in WALKS): issues.append("Contains a keyboard walk or common sequence")
    if re.search(r"(.)\1{2,}", pw): issues.append("Repeated characters (aaa, 111)")
    if re.search(r"(19|20)\d{2}", pw): issues.append("Contains a year, which is easy to guess")
    if pw.isdigit() or pw.isalpha(): issues.append("Uses a single character type")
    if re.search(r"(?:012|123|234|345|456|567|678|789|abc|bcd|cde|def)", low): issues.append("Contains an ascending sequence")
    if re.fullmatch(r"[A-Za-z]+[\d\W]+", pw) and len(pw) < 14: issues.append("Common 'word + digits/symbol' structure")
    return issues

def entropy(pw):
    base = len(pw) * math.log2(charset(pw)) if pw else 0
    if pw.lower() in COMMON: base = min(base, 10)
    return base * max(0.5, 1 - 0.1 * len(patterns(pw)))

def crack_time(bits, rate):
    seconds = (2 ** bits) / 2 / rate
    for unit, n in [("centuries", 3.15e9), ("years", 3.15e7), ("days", 86400), ("hours", 3600), ("minutes", 60)]:
        if seconds >= n: return "more than 1 million centuries" if seconds / n > 1e6 and unit == "centuries" else f"{seconds / n:,.1f} {unit}"
    return "instantly" if seconds < 1 else f"{seconds:.0f} seconds"

def analyze(pw):
    bits = entropy(pw)
    score = int(min(100, bits / 75 * 100)) if pw else 0
    label = ["Very Weak","Weak","Fair","Good","Strong"][min(4, score // 20)]
    checks = {"12+ characters": len(pw) >= 12, "Lowercase": bool(re.search("[a-z]", pw)),
              "Uppercase": bool(re.search("[A-Z]", pw)), "Numbers": bool(re.search(r"\d", pw)),
              "Symbols": bool(re.search(r"[^A-Za-z0-9]", pw))}
    return {"score": score, "label": label, "bits": bits, "checks": checks, "issues": patterns(pw),
            "times": {k: crack_time(bits, v) for k, v in RATES.items()}}

def breach_count(pw):
    """Have I Been Pwned k-anonymity check: only the first 5 hash characters leave your device."""
    h = hashlib.sha1(pw.encode()).hexdigest().upper()
    req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{h[:5]}", headers={"User-Agent": "pw-analyzer"})
    for line in urllib.request.urlopen(req, timeout=6).read().decode().splitlines():
        suffix, count = line.split(":")
        if suffix == h[5:]: return int(count)
    return 0

def generate_password(n=18, symbols=True):
    pool = string.ascii_letters + string.digits + ("!@#$%^&*-_=+?" if symbols else "")
    while True:
        pw = "".join(secrets.choice(pool) for _ in range(n))
        if re.search("[a-z]", pw) and re.search("[A-Z]", pw) and re.search(r"\d", pw) and (not symbols or re.search(r"\W|_", pw)): return pw

def generate_passphrase(words=5):
    return "-".join(secrets.choice(WORDS) for _ in range(words)) + str(secrets.randbelow(90) + 10)
