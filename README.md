<div align="center">

```
 ██████╗  █████╗ ███████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 ██████╔╝███████║███████╗███████╗█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
 ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
 ██║     ██║  ██║███████║███████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
 ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

**PassForge v1.0** — Personalized Wordlist Generator + Breach Intelligence Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-ElliotSop-black?style=flat-square)](https://elliotsop.com)
[![OSCP](https://img.shields.io/badge/OSCP-Certified-orange?style=flat-square)](https://elliotsop.com)

*Built for red teamers and pentesters who need targeted, intelligent wordlists — not generic rockyou rehashes.*

[elliotsop.com](https://elliotsop.com) · [GitHub](https://github.com/00ElliotSop) · [LinkedIn](https://linkedin.com/in/padeshina)

</div>

---

## Overview

PassForge generates **highly targeted, mutation-rich wordlists** from personal profiling data. Unlike generic wordlist tools, PassForge models how real users construct passwords — combining personal details, leet substitutions, common suffixes, year variants, and compound phrases — then cross-references every candidate against the **HaveIBeenPwned breach database** using k-Anonymity (no plaintext passwords are transmitted).

Designed for authorised penetration testing engagements where wordlist quality directly determines attack success.

---

## Features

- **Interactive profile collection** — first/last name, usernames, emails, DOB, related names, phrases, numbers, company, location, hobby
- **File input mode** — skip the prompt entirely, feed a flat token file
- **Full mutation engine**:
  - Capitalisation variants (lower, upper, title, camelCase, toggle)
  - Leet substitution — single, double, and full-replacement combos
  - Suffix appending — `!`, `!!`, `##`, `$$`, `***`, `123`, `2024`, `69`, `@` and more
  - Year variants — `1990–2026`, two-digit short forms
  - Number pads — `01`, `007`, `99`, `111`, etc.
  - Compound permutations — cross-joins all token pairs with `.`, `_`, `-`, CamelCase
- **HIBP k-Anonymity breach check** — SHA-1 prefix method, zero full-password exposure
- **Email breach lookup** — with a paid HIBP API key, surfaces every known breach for a target email and seeds additional tokens from breach service names
- **Single output file** — one password per line, clean vs. breach-confirmed sections annotated

---

## Installation

```bash
git clone https://github.com/00ElliotSop/PassForge
cd PassForge
pip install -r requirements.txt
```

**requirements.txt**
```
requests
colorama
tqdm
```

---

## Usage

### Interactive mode (recommended for targeted engagements)
```bash
python3 elliotsop_passgen.py
```

### File input — one token per line
```bash
python3 elliotsop_passgen.py --file targets.txt
```

### With HIBP API key (unlocks email breach lookup + full list breach check)
```bash
python3 elliotsop_passgen.py --hibp-key YOUR_KEY_HERE
```

### Full example with all options
```bash
python3 elliotsop_passgen.py \
  --file tokens.txt \
  --hibp-key YOUR_KEY_HERE \
  --output /tmp/wordlist.txt \
  --hibp-filter
```

### Skip breach check entirely
```bash
python3 elliotsop_passgen.py --no-hibp --output wordlist.txt
```

---

## Options

| Flag | Description |
|------|-------------|
| `--file`, `-f` | Path to token file (one per line). Skips interactive prompt. |
| `--output`, `-o` | Output file path (default: `passforge_output.txt`) |
| `--hibp-key` | HaveIBeenPwned API key. Required for email breach lookup. |
| `--no-hibp` | Skip all HIBP queries. |
| `--hibp-filter` | Remove breach-confirmed passwords from output instead of annotating. |
| `--email` | Email address to check for breaches (requires `--hibp-key`). |

---

## Output Format

```
# ════════════════════════════════════════════════════════════
# ElliotSop Security — PassForge v1.0
# Personalized Wordlist + Breach Intelligence Output
# Generated: 2026-04-24 14:32:01
# Total entries: 18,432
# ════════════════════════════════════════════════════════════

# ── CLEAN (not found in breach databases) ──────────────────
JohnSmith2024!
J0hnSm1th##
johnsmith.work$$$
...

# ── BREACH-CONFIRMED (found in HIBP, high-priority targets) ─
Password123!  # PWNED:24013
Qwerty2020##  # PWNED:7841
...
```

---

## HIBP Integration

PassForge uses the [HaveIBeenPwned Pwned Passwords API](https://haveibeenpwned.com/API/v3) with **k-Anonymity**:

1. SHA-1 hash of the candidate password is computed locally
2. Only the **first 5 characters** of the hash are transmitted
3. The API returns all hash suffixes matching that prefix
4. PassForge checks for a local match — **the full password never leaves your machine**

A free HIBP subscription key (~$3.50/month) is required for the email breach lookup endpoint. Password range queries are free with rate limiting.

---

## Mutation Examples

Given the input token `GoTo`:

| Mutation Type | Example Output |
|---------------|---------------|
| Capitalisation | `goto`, `GOTO`, `Goto`, `goTo` |
| Leet | `G0T0`, `G0to`, `Go7o` |
| Suffix | `GoTo!`, `GoTo##`, `GoTo$$`, `GoTo2024` |
| Year append | `GoTo2025`, `GoTo99`, `GoTo21` |
| Number pad | `GoTo123`, `GoTo007`, `GoTo01` |
| Compound | `GoToWork`, `goto_corp`, `GoTo.Home` |

---

## Legal

> **For authorised penetration testing engagements only.**  
> Using this tool against systems you do not have explicit written permission to test is illegal.  
> ElliotSop Security LLC accepts no liability for misuse.

---

## Author

**Prince Adeshina** — OSCP · CRTP  
[elliotsop.com](https://elliotsop.com) · [contact@elliotsop.com](mailto:contact@elliotsop.com)  
ElliotSop Security LLC
