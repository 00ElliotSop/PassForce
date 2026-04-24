#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          ElliotSop Security — PassForge v1.0                 ║
║   Personalized wordlist generator with mutation engine       ║
║   OSCP / Red Team Ops toolkit — github.com/00ElliotSop       ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python3 elliotsop_passgen.py
    python3 elliotsop_passgen.py --file targets.txt
    python3 elliotsop_passgen.py --hibp-key <API_KEY>

Requires:
    pip install requests colorama tqdm
"""

import argparse
import hashlib
import itertools
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    import requests
    from colorama import Fore, Style, init
    from tqdm import tqdm
    init(autoreset=True)
except ImportError:
    print("[!] Missing dependencies. Run: pip install requests colorama tqdm")
    sys.exit(1)


# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

BANNER = f"""
{Fore.RED}
  ██████╗  █████╗ ███████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ██████╔╝███████║███████╗███████╗█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
  ██║     ██║  ██║███████║███████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{Style.RESET_ALL}
{Fore.WHITE}  PassForge v1.0 — ElliotSop Security LLC{Style.RESET_ALL}
{Fore.YELLOW}  Personalized Wordlist Generator + Breach Intelligence Engine{Style.RESET_ALL}
  {Fore.RED}github.com/00ElliotSop  |  elliotsop.com{Style.RESET_ALL}
  ─────────────────────────────────────────────────────────────
"""


# ─────────────────────────────────────────────
#  LEET / MUTATION CONFIG
# ─────────────────────────────────────────────

LEET_MAP = {
    'a': ['4', '@'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7'],
    'l': ['1'],
    'b': ['8'],
    'g': ['9'],
    'z': ['2'],
}

# Common suffix sets appended to passwords
SUFFIXES = [
    '!', '!!', '!!!',
    '1', '12', '123', '1234',
    '#', '##', '###',
    '$', '$$', '$$$',
    '*', '**', '***',
    '@', '@@',
    '!@#', '#!', '$!', '!#',
    '69', '77', '88', '99', '00',
    '2024', '2025', '2026',
    '!1', '1!', '!2', '!123',
]

# Common prefix additions
PREFIXES = ['', '!', '#', '1', '123', 'The', 'the']

# Year variants
YEARS = ['2020', '2021', '2022', '2023', '2024', '2025', '2026',
         '20', '21', '22', '23', '24', '25', '26',
         '1990', '1991', '1992', '1993', '1994', '1995',
         '1996', '1997', '1998', '1999', '2000', '2001']


# ─────────────────────────────────────────────
#  MUTATION ENGINE
# ─────────────────────────────────────────────

def capitalize_variants(word: str) -> list[str]:
    """Generate capitalisation variants of a word."""
    variants = set()
    variants.add(word.lower())
    variants.add(word.upper())
    variants.add(word.capitalize())
    variants.add(word.title())
    # Toggle case: first char lower, rest upper
    if len(word) > 1:
        variants.add(word[0].lower() + word[1:].upper())
        variants.add(word[0].upper() + word[1:].lower())
    # camelCase style (useful for compound words)
    parts = re.split(r'[\s_\-]', word)
    if len(parts) > 1:
        variants.add(''.join(p.capitalize() for p in parts))
        variants.add(parts[0].lower() + ''.join(p.capitalize() for p in parts[1:]))
    return list(variants)


def leet_mutate(word: str) -> list[str]:
    """Apply leet substitutions — generates ALL combos up to depth 3."""
    word = word.lower()
    results = {word}

    # Single substitutions
    for i, ch in enumerate(word):
        if ch in LEET_MAP:
            for sub in LEET_MAP[ch]:
                results.add(word[:i] + sub + word[i + 1:])

    # Double substitutions (pairs)
    positions = [(i, ch) for i, ch in enumerate(word) if ch in LEET_MAP]
    for (i, ci), (j, cj) in itertools.combinations(positions, 2):
        for si in LEET_MAP[ci]:
            for sj in LEET_MAP[cj]:
                tmp = list(word)
                tmp[i] = si
                tmp[j] = sj
                results.add(''.join(tmp))

    # Full leet (replace every applicable char)
    full = list(word)
    for i, ch in enumerate(full):
        if ch in LEET_MAP:
            full[i] = LEET_MAP[ch][0]
    results.add(''.join(full))

    return list(results)


def apply_suffixes(base: str) -> list[str]:
    """Attach common password suffixes to a base string."""
    return [base + sfx for sfx in SUFFIXES] + [base]


def apply_prefixes(base: str) -> list[str]:
    """Attach common password prefixes to a base string."""
    return [pfx + base for pfx in PREFIXES if pfx] + [base]


def year_append(base: str) -> list[str]:
    """Append year variants."""
    return [base + y for y in YEARS]


def number_pad(base: str) -> list[str]:
    """Append common number pads."""
    pads = ['1', '12', '123', '1234', '12345', '0', '01', '007',
            '111', '000', '99', '77', '88', '21', '10']
    return [base + p for p in pads]


def combine_words(tokens: list[str]) -> list[str]:
    """Generate compound combinations from 2 tokens."""
    combined = []
    for a, b in itertools.permutations(tokens, 2):
        combined.append(a + b)
        combined.append(a + '_' + b)
        combined.append(a + '.' + b)
        combined.append(a + '-' + b)
        combined.append(a.capitalize() + b.capitalize())
    return combined


def mutate_token(token: str) -> list[str]:
    """Full mutation pipeline for a single token."""
    all_mutations = set()

    cap_variants = capitalize_variants(token)
    for cv in cap_variants:
        all_mutations.add(cv)
        for leet in leet_mutate(cv):
            all_mutations.add(leet)
            for s in apply_suffixes(leet):
                all_mutations.add(s)
            for y in year_append(leet):
                all_mutations.add(y)
            for n in number_pad(leet):
                all_mutations.add(n)

    # Base + suffix combos on original caps
    for cv in cap_variants:
        for s in apply_suffixes(cv):
            all_mutations.add(s)
        for y in year_append(cv):
            all_mutations.add(y)
        for n in number_pad(cv):
            all_mutations.add(n)

    return list(all_mutations)


# ─────────────────────────────────────────────
#  BREACH INTELLIGENCE — HIBP (k-Anonymity)
# ─────────────────────────────────────────────

def check_hibp_password(password: str, api_key: str = None) -> tuple[bool, int]:
    """
    Query HaveIBeenPwned Pwned Passwords API using k-Anonymity.
    No full password is transmitted — only the first 5 chars of SHA-1 hash.
    Returns (is_pwned: bool, count: int)

    Free tier: No key needed (rate-limited).
    HIBP subscription key: https://haveibeenpwned.com/API/Key
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    headers = {'Add-Padding': 'true'}
    if api_key:
        headers['hibp-api-key'] = api_key

    try:
        r = requests.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers=headers,
            timeout=8
        )
        r.raise_for_status()
        for line in r.text.splitlines():
            h, count = line.split(':')
            if h == suffix:
                return True, int(count)
        return False, 0
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}  [HIBP] Request error: {e}{Style.RESET_ALL}")
        return False, -1


def fetch_hibp_breaches_for_email(email: str, api_key: str) -> list[dict]:
    """
    Query HIBP Breached Accounts API for an email address.
    Requires a paid HIBP API key (~$3.50/month): https://haveibeenpwned.com/API/Key
    Returns list of breach objects.
    """
    if not api_key:
        print(f"{Fore.YELLOW}  [HIBP] Email breach lookup requires an API key. Skipping.{Style.RESET_ALL}")
        return []

    headers = {'hibp-api-key': api_key, 'User-Agent': 'ElliotSop-PassForge'}
    try:
        r = requests.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
            headers=headers,
            params={'truncateResponse': 'false'},
            timeout=10
        )
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}  [HIBP] Breach lookup error: {e}{Style.RESET_ALL}")
        return []


def enrich_from_breach_names(breaches: list[dict]) -> list[str]:
    """
    Extract passwords/usernames from breach metadata to seed extra mutations.
    Breach data itself is not provided by HIBP — this pulls service names,
    usernames, and domains to further seed wordlist generation.
    """
    tokens = []
    for b in breaches:
        # Service name (e.g. "LinkedIn", "Adobe")
        name = b.get('Name', '')
        domain = b.get('Domain', '').split('.')[0]
        if name:
            tokens.append(name)
        if domain:
            tokens.append(domain)
    return tokens


# ─────────────────────────────────────────────
#  INPUT COLLECTION
# ─────────────────────────────────────────────

def prompt_input() -> dict:
    """Interactive collection of personal details for wordlist generation."""
    print(f"\n{Fore.CYAN}  ┌─ TARGET PROFILE BUILDER ────────────────────────────────┐{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  │  Enter details below. Leave blank to skip.               │{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  └──────────────────────────────────────────────────────────┘{Style.RESET_ALL}\n")

    profile = {}

    def ask(label, key):
        val = input(f"  {Fore.WHITE}{label}{Style.RESET_ALL}: ").strip()
        if val:
            profile[key] = val

    ask("First name", "first_name")
    ask("Last name", "last_name")
    ask("Nickname / handle", "nickname")
    ask("Username(s) [comma-separated]", "usernames")
    ask("Email address(es) [comma-separated]", "emails")
    ask("Date of birth [DD/MM/YYYY or YYYY]", "dob")
    ask("Partner / pet / child name", "related_name")
    ask("Favourite word / phrase", "phrase")
    ask("Numbers you use (lucky, PIN, phone tail) [comma-separated]", "numbers")
    ask("Company / organisation name", "company")
    ask("City / country", "location")
    ask("Hobby / interest", "hobby")

    return profile


def parse_profile(profile: dict) -> list[str]:
    """Flatten profile into raw token list."""
    tokens = []

    def add(val):
        if val:
            for part in re.split(r'[,;\s]+', val):
                part = part.strip()
                if part:
                    tokens.append(part)

    add(profile.get('first_name'))
    add(profile.get('last_name'))
    add(profile.get('nickname'))
    add(profile.get('usernames'))
    add(profile.get('related_name'))
    add(profile.get('phrase'))
    add(profile.get('numbers'))
    add(profile.get('company'))
    add(profile.get('location'))
    add(profile.get('hobby'))

    # DOB parsing
    dob = profile.get('dob', '')
    if dob:
        # Extract numeric components
        parts = re.findall(r'\d+', dob)
        tokens.extend(parts)
        if len(parts) == 3:
            day, month, year = parts[0], parts[1], parts[2]
            tokens += [day + month, month + year, day + month + year, year]

    # Email local part
    for email in re.split(r'[,;\s]+', profile.get('emails', '')):
        local = email.split('@')[0]
        if local:
            tokens.append(local)

    return list(set(t for t in tokens if len(t) >= 2))


def load_from_file(filepath: str) -> list[str]:
    """Load tokens from a plaintext file (one per line)."""
    path = Path(filepath)
    if not path.exists():
        print(f"{Fore.RED}  [!] File not found: {filepath}{Style.RESET_ALL}")
        sys.exit(1)
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


# ─────────────────────────────────────────────
#  CORE WORDLIST BUILDER
# ─────────────────────────────────────────────

def build_wordlist(tokens: list[str], extra_tokens: list[str] = None) -> list[str]:
    """Generate full mutated wordlist from token list."""
    all_tokens = list(set(tokens + (extra_tokens or [])))
    print(f"\n{Fore.GREEN}  [*] Generating mutations for {len(all_tokens)} base tokens...{Style.RESET_ALL}")

    wordlist = set()

    # Single-token mutations
    for token in tqdm(all_tokens, desc="  Mutating tokens", ncols=70):
        for w in mutate_token(token):
            wordlist.add(w)

    # Compound tokens (pairs)
    if len(all_tokens) > 1:
        print(f"\n{Fore.GREEN}  [*] Building compound combinations...{Style.RESET_ALL}")
        for combo in tqdm(combine_words(all_tokens), desc="  Compounds", ncols=70):
            wordlist.add(combo)
            for w in apply_suffixes(combo):
                wordlist.add(w)
            for y in year_append(combo):
                wordlist.add(y)

    # Filter: min 6 chars, max 64 chars
    wordlist = {w for w in wordlist if 6 <= len(w) <= 64}

    return sorted(wordlist)


# ─────────────────────────────────────────────
#  HIBP BREACH CHECK ON WORDLIST
# ─────────────────────────────────────────────

def hibp_filter_wordlist(wordlist: list[str], api_key: str = None,
                          mark_only: bool = True) -> tuple[list[str], list[str]]:
    """
    Check each password against HIBP k-Anonymity API.
    mark_only=True  → returns (all_passwords, pwned_passwords)
    mark_only=False → removes pwned passwords from list
    Rate limit: ~1 req/1.5s recommended for free tier.
    """
    pwned = []
    clean = []

    print(f"\n{Fore.YELLOW}  [*] Checking {len(wordlist)} passwords against HIBP breach database...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  [!] This may take several minutes depending on list size.{Style.RESET_ALL}\n")

    for pw in tqdm(wordlist, desc="  HIBP Check", ncols=70):
        is_pwned, count = check_hibp_password(pw, api_key)
        if is_pwned:
            pwned.append(f"{pw}  # PWNED:{count}")
        else:
            clean.append(pw)
        time.sleep(1.5)  # Respectful rate limiting

    return clean, pwned


# ─────────────────────────────────────────────
#  OUTPUT
# ─────────────────────────────────────────────

def write_output(wordlist: list[str], pwned: list[str], output_path: str):
    """
    Write final merged wordlist to single output file.
    Format: one password per line.
    Pwned passwords annotated with # PWNED:<count> comment.
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# ════════════════════════════════════════════════════════════\n")
        f.write("# ElliotSop Security — PassForge v1.0\n")
        f.write("# Personalized Wordlist + Breach Intelligence Output\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total entries: {len(wordlist) + len(pwned)}\n")
        f.write("# ════════════════════════════════════════════════════════════\n\n")

        if clean_list := wordlist:
            f.write("# ── CLEAN (not found in breach databases) ──────────────────\n")
            for pw in clean_list:
                f.write(pw + '\n')

        if pwned:
            f.write("\n# ── BREACH-CONFIRMED (found in HIBP, high-priority targets) ─\n")
            for pw in pwned:
                f.write(pw + '\n')

    total = len(wordlist) + len(pwned)
    print(f"\n{Fore.GREEN}  [✔] Wordlist written: {output_path}{Style.RESET_ALL}")
    print(f"  Total entries : {Fore.CYAN}{total}{Style.RESET_ALL}")
    print(f"  Clean         : {Fore.GREEN}{len(wordlist)}{Style.RESET_ALL}")
    print(f"  Breach hits   : {Fore.RED}{len(pwned)}{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description='ElliotSop PassForge — Personalized Wordlist Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--file', '-f', help='Path to file with one token per line (skips interactive prompt)')
    parser.add_argument('--output', '-o', default='passforge_output.txt', help='Output file path (default: passforge_output.txt)')
    parser.add_argument('--hibp-key', help='HaveIBeenPwned API key for email breach lookup')
    parser.add_argument('--no-hibp', action='store_true', help='Skip HIBP breach database checks entirely')
    parser.add_argument('--hibp-filter', action='store_true', help='Remove HIBP-confirmed passwords from output (default: annotate only)')
    parser.add_argument('--email', help='Email address to check for breaches via HIBP (requires --hibp-key)')
    args = parser.parse_args()

    # ── Step 1: Collect tokens ──────────────────────────────────
    extra_breach_tokens = []

    if args.file:
        print(f"{Fore.CYAN}  [*] Loading tokens from file: {args.file}{Style.RESET_ALL}")
        tokens = load_from_file(args.file)
        print(f"  Loaded {len(tokens)} tokens.")
    else:
        profile = prompt_input()
        tokens = parse_profile(profile)

        # Email breach lookup for extra seed tokens
        emails_raw = profile.get('emails', '')
        if emails_raw and args.hibp_key:
            for email in re.split(r'[,;\s]+', emails_raw):
                email = email.strip()
                if not email:
                    continue
                print(f"\n{Fore.YELLOW}  [*] Checking breach history for: {email}{Style.RESET_ALL}")
                breaches = fetch_hibp_breaches_for_email(email, args.hibp_key)
                if breaches:
                    print(f"{Fore.RED}  [!] Found in {len(breaches)} breach(es):{Style.RESET_ALL}")
                    for b in breaches:
                        print(f"      • {b.get('Name')} ({b.get('BreachDate', 'unknown date')}) — {b.get('PwnCount', 0):,} records")
                    extra_breach_tokens += enrich_from_breach_names(breaches)
                else:
                    print(f"{Fore.GREEN}  [✔] No breaches found for {email}{Style.RESET_ALL}")

    if not tokens:
        print(f"{Fore.RED}  [!] No tokens collected. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

    print(f"\n  {Fore.CYAN}Base tokens:{Style.RESET_ALL} {tokens}")

    # ── Step 2: Build wordlist ──────────────────────────────────
    wordlist = build_wordlist(tokens, extra_breach_tokens)
    print(f"\n  {Fore.GREEN}Raw mutations generated: {len(wordlist):,}{Style.RESET_ALL}")

    # ── Step 3: HIBP password breach check ─────────────────────
    clean_list = wordlist
    pwned_list = []

    if not args.no_hibp:
        do_check = input(f"\n  {Fore.YELLOW}Run HIBP breach check on generated passwords? (y/N): {Style.RESET_ALL}").strip().lower()
        if do_check == 'y':
            # Limit to 500 for free tier sanity; remove limit with --hibp-key
            check_limit = len(wordlist) if args.hibp_key else min(len(wordlist), 500)
            if check_limit < len(wordlist):
                print(f"{Fore.YELLOW}  [!] Free tier: checking first {check_limit} passwords. Use --hibp-key for full list.{Style.RESET_ALL}")
            clean_list, pwned_list = hibp_filter_wordlist(
                wordlist[:check_limit], args.hibp_key
            )
            if args.hibp_filter:
                print(f"{Fore.YELLOW}  [*] --hibp-filter active: removing {len(pwned_list)} breach-confirmed passwords.{Style.RESET_ALL}")
                pwned_list = []  # Don't include them in output

    # ── Step 4: Write output ────────────────────────────────────
    write_output(clean_list, pwned_list, args.output)

    print(f"  {Fore.RED}★ ElliotSop Security | elliotsop.com | github.com/00ElliotSop{Style.RESET_ALL}\n")


if __name__ == '__main__':
    main()
