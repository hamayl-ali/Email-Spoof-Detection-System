"""
Email Spoof Detection System
==============================
Parses raw email files (.eml) and checks for indicators of spoofing /
phishing: failed SPF/DKIM/DMARC authentication, display-name vs. actual
address mismatches, lookalike ("typosquatted") domains, Reply-To
mismatches, and suspicious links.

MITRE ATT&CK mapping: T1566.001/T1566.002 (Phishing: Spearphishing
Attachment/Link), T1656 (Impersonation).

Usage:
    python3 detector.py --input sample_emails/                # scan a folder
    python3 detector.py --input sample_emails/spoof_01.eml     # scan one file
    python3 detector.py --input sample_emails/ --csv-out report.csv
    python3 detector.py --input sample_emails/ --trusted-domain corp-example.com
"""

import argparse
import csv
import email
import re
import sys
from dataclasses import dataclass, field
from email.utils import parseaddr
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Edit distance between two strings - used to catch lookalike domains
    like 'corp-exarnple.com' vs 'corp-example.com' (rn -> m swap)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur_row = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur_row.append(min(
                prev_row[j] + 1,        # deletion
                cur_row[j - 1] + 1,     # insertion
                prev_row[j - 1] + cost  # substitution
            ))
        prev_row = cur_row
    return prev_row[-1]


def extract_domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].lower().strip()


def parse_auth_results(header_value: str) -> dict:
    """Extract spf/dkim/dmarc verdicts from an Authentication-Results header."""
    results = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", header_value, re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()
    return results


URL_PATTERN = re.compile(r"https?://[^\s)>\]\"']+", re.IGNORECASE)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".live", ".click",
}

URGENCY_PHRASES = [
    r"\burgent(ly)?\b", r"\bimmediately\b", r"\bact now\b",
    r"\bverify (your|now)\b", r"\bsuspended?\b", r"\bwithin 24 hours\b",
    r"\bclick here\b", r"\bconfirm your\b", r"\baccount.{0,15}(locked|disabled)\b",
    r"\bfailure to act\b", r"\bkeep this (between us|confidential)\b",
    r"\bgift cards?\b", r"\bwire transfer\b",
]


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    filename: str
    from_display: str
    from_address: str
    reply_to: str
    subject: str
    spf: str
    dkim: str
    dmarc: str
    score: int = 0
    severity: str = "LOW"
    reasons: list = field(default_factory=list)


SEVERITY_THRESHOLDS = [
    (70, "CRITICAL"),
    (45, "HIGH"),
    (20, "MEDIUM"),
    (0, "LOW"),
]


def severity_for_score(score: int) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyze_eml(path: Path, trusted_domain: str = None) -> Finding:
    with open(path, "r", errors="ignore") as f:
        msg = email.message_from_file(f)

    from_header = msg.get("From", "")
    from_display, from_address = parseaddr(from_header)
    reply_to_header = msg.get("Reply-To", "")
    _, reply_to_address = parseaddr(reply_to_header) if reply_to_header else ("", "")
    subject = msg.get("Subject", "")

    auth_header = msg.get("Authentication-Results", "")
    auth = parse_auth_results(auth_header)
    spf = auth.get("spf", "none")
    dkim = auth.get("dkim", "none")
    dmarc = auth.get("dmarc", "none")

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        body = payload.decode(errors="ignore") if payload else str(msg.get_payload())

    score = 0
    reasons = []

    # --- 1. Authentication results ---
    if spf == "fail":
        score += 30
        reasons.append(("SPF Fail (T1656)", "Sending server is not authorized to send mail for this domain."))
    elif spf == "softfail":
        score += 15
        reasons.append(("SPF Softfail", "Sending server is questionable but not outright rejected by domain policy."))

    if dkim == "fail":
        score += 25
        reasons.append(("DKIM Fail", "Message signature is invalid or missing - content/headers may have been tampered with, or sender isn't who they claim."))
    elif dkim == "none":
        score += 5
        reasons.append(("DKIM Missing", "No DKIM signature present - lower confidence the sender is legitimate."))

    if dmarc == "fail":
        score += 30
        reasons.append(("DMARC Fail", "Message fails domain's published DMARC policy - strong spoofing indicator."))

    # --- 2. Display name vs actual address mismatch ---
    from_domain = extract_domain(from_address)
    if trusted_domain and from_domain and from_domain != trusted_domain.lower():
        # check if display name claims to be from the trusted org
        if trusted_domain.split(".")[0].lower() in from_display.lower():
            score += 25
            reasons.append((
                "Display Name Impersonation",
                f"Display name references '{trusted_domain}' but the actual sending "
                f"address domain is '{from_domain}'.",
            ))

    # --- 3. Lookalike / typosquatted domain ---
    if trusted_domain and from_domain and from_domain != trusted_domain.lower():
        distance = levenshtein(from_domain, trusted_domain.lower())
        if 0 < distance <= 2:
            score += 35
            reasons.append((
                "Lookalike Domain",
                f"Sending domain '{from_domain}' is suspiciously similar "
                f"(edit distance {distance}) to trusted domain '{trusted_domain}' "
                f"- likely typosquatting.",
            ))

    # --- 4. Reply-To mismatch ---
    reply_to_domain = extract_domain(reply_to_address)
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        score += 20
        reasons.append((
            "Reply-To Domain Mismatch",
            f"Reply-To address ('{reply_to_domain}') differs from the From "
            f"address domain ('{from_domain}') - replies would be redirected "
            f"to a different domain than the apparent sender.",
        ))

    # --- 5. Suspicious URLs in body ---
    urls = URL_PATTERN.findall(body)
    flagged_urls = []
    for url in urls:
        url_lower = url.lower()
        for shortener in URL_SHORTENERS:
            if shortener in url_lower:
                flagged_urls.append((url, "URL shortener (hides true destination)"))
        for tld in SUSPICIOUS_TLDS:
            if re.search(re.escape(tld) + r"(/|$)", url_lower.split("?")[0]):
                flagged_urls.append((url, f"Suspicious/free TLD ({tld})"))
        # link domain doesn't match claimed sender domain but body implies it should
        if trusted_domain and trusted_domain.lower() in url_lower:
            link_domain_match = re.search(r"https?://([^/]+)", url_lower)
            if link_domain_match:
                link_domain = link_domain_match.group(1)
                if trusted_domain.lower() not in link_domain.split(".")[-2:]:
                    flagged_urls.append((url, f"Mimics trusted domain name but resolves elsewhere ({link_domain})"))

    if flagged_urls:
        score += 20
        unique_reasons = {reason for _, reason in flagged_urls}
        reasons.append((
            "Suspicious Link(s)",
            "; ".join(unique_reasons) + f" -- {len(flagged_urls)} link(s) flagged.",
        ))

    # --- 6. Urgency / social engineering language ---
    matched_phrases = []
    combined_text = (subject + " " + body).lower()
    for pattern in URGENCY_PHRASES:
        if re.search(pattern, combined_text):
            matched_phrases.append(pattern.strip(r"\b").replace("\\", ""))
    if matched_phrases:
        weight = min(20, 5 * len(matched_phrases))
        score += weight
        reasons.append((
            "Urgency / Social Engineering Language",
            f"Found {len(matched_phrases)} urgency/pressure phrase(s) commonly "
            f"used in phishing to rush victims into acting without verifying.",
        ))

    severity = severity_for_score(score)

    return Finding(
        filename=path.name,
        from_display=from_display,
        from_address=from_address,
        reply_to=reply_to_address,
        subject=subject,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        score=score,
        severity=severity,
        reasons=reasons,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def print_report(findings, min_severity="LOW"):
    min_rank = SEVERITY_ORDER[min_severity]
    relevant = [f for f in findings if SEVERITY_ORDER[f.severity] <= min_rank]
    relevant.sort(key=lambda f: -f.score)

    by_sev = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    print("=" * 78)
    print("EMAIL SPOOF DETECTION REPORT")
    print("=" * 78)
    print(f"Total emails analyzed: {len(findings)}")
    print(
        "Severity breakdown: "
        + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items(), key=lambda kv: SEVERITY_ORDER[kv[0]]))
    )
    print(f"Showing severity >= {min_severity}")
    print("-" * 78)

    for f in relevant:
        print(f"\n[{f.severity}] score={f.score}  {f.filename}")
        print(f"  From: \"{f.from_display}\" <{f.from_address}>")
        if f.reply_to and f.reply_to != f.from_address:
            print(f"  Reply-To: {f.reply_to}")
        print(f"  Subject: {f.subject}")
        print(f"  Auth: SPF={f.spf}  DKIM={f.dkim}  DMARC={f.dmarc}")
        if f.reasons:
            print("  Reasons flagged:")
            for name, desc in f.reasons:
                print(f"    - {name}: {desc}")
        else:
            print("  No issues detected.")
    print("\n" + "=" * 78)


def write_csv_report(findings, out_path):
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Filename", "FromDisplay", "FromAddress", "ReplyTo", "Subject",
            "SPF", "DKIM", "DMARC", "Severity", "Score", "Reasons",
        ])
        for finding in sorted(findings, key=lambda x: -x.score):
            reason_text = "; ".join(f"{name}: {desc}" for name, desc in finding.reasons)
            writer.writerow([
                finding.filename, finding.from_display, finding.from_address,
                finding.reply_to, finding.subject, finding.spf, finding.dkim,
                finding.dmarc, finding.severity, finding.score, reason_text,
            ])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def collect_eml_files(input_path: Path):
    if input_path.is_file():
        return [input_path]
    return sorted(input_path.glob("*.eml"))


def main():
    parser = argparse.ArgumentParser(
        description="Detect spoofed/phishing emails from .eml files."
    )
    parser.add_argument("--input", required=True, help="Path to a .eml file or a folder of .eml files")
    parser.add_argument(
        "--trusted-domain", default=None,
        help="Your organization's legitimate domain (e.g. corp-example.com) "
             "- enables lookalike-domain and impersonation checks",
    )
    parser.add_argument(
        "--min-severity", default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    )
    parser.add_argument("--csv-out", default=None)
    args = parser.parse_args()

    input_path = Path(args.input)
    files = collect_eml_files(input_path)
    if not files:
        print(f"No .eml files found at {args.input}", file=sys.stderr)
        sys.exit(1)

    findings = [analyze_eml(f, trusted_domain=args.trusted_domain) for f in files]
    print_report(findings, min_severity=args.min_severity)

    if args.csv_out:
        write_csv_report(findings, args.csv_out)
        print(f"\nCSV report written to: {args.csv_out}")


if __name__ == "__main__":
    main()
