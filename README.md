# 🛡️ Email Spoof Detection System

A Python-based cybersecurity tool that analyzes **.eml email files** and detects common email spoofing and phishing indicators. The project assigns a risk score, classifies severity levels, and generates detailed reports to help identify potentially malicious emails.

---

## ✨ Features

- ✅ Detects SPF authentication failures
- ✅ Detects DKIM authentication failures
- ✅ Detects DMARC policy failures
- ✅ Identifies display-name impersonation
- ✅ Detects lookalike (typosquatted) domains
- ✅ Checks Reply-To domain mismatches
- ✅ Detects suspicious URLs
- ✅ Detects URL shorteners
- ✅ Flags suspicious top-level domains (TLDs)
- ✅ Detects urgency and social engineering language
- ✅ Assigns risk scores
- ✅ Classifies severity:
  - Low
  - Medium
  - High
  - Critical
- ✅ Generates CSV reports
- ✅ Supports scanning a single email or an entire directory

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/hamayl-ali/Email-Spoof-Detection-System.git

cd Email-Spoof-Detection-System
```

No external libraries are required.

The project only uses Python's standard library.

---

## ▶️ Usage

### Scan a folder

```bash
python detector.py --input sample_emails/
```

### Scan a single email

```bash
python detector.py --input sample_emails/spoof_01_failed_auth_payroll.eml
```

### Generate a CSV report

```bash
python detector.py --input sample_emails/ --csv-out report.csv
```

### Enable trusted domain checks

```bash
python detector.py --input sample_emails/ --trusted-domain corp-example.com
```

### Show only High or Critical alerts

```bash
python detector.py --input sample_emails/ --min-severity HIGH
```

---

## 🧪 Generate Sample Emails

Generate legitimate and phishing test emails:

```bash
python generate_samples.py
```

This creates a `sample_emails/` directory containing both benign and malicious `.eml` files for testing.

---

## 🔍 Detection Techniques

The tool analyzes emails using multiple detection methods:

- SPF validation
- DKIM validation
- DMARC validation
- Display Name vs Email Address comparison
- Lookalike domain detection (Levenshtein Distance)
- Reply-To mismatch detection
- Suspicious URL detection
- URL Shortener detection
- Suspicious Top-Level Domains
- Social engineering keyword detection

---

## 📊 Severity Levels

| Score | Severity |
|--------|----------|
| 0–19 | Low |
| 20–44 | Medium |
| 45–69 | High |
| 70+ | Critical |

---

## 📈 Example Output

```
==========================================================================
EMAIL SPOOF DETECTION REPORT
==========================================================================

[CRITICAL] score=95 spoof_02_lookalike_domain_ceo.eml

From:
Michael Tran (CEO)

Authentication:
SPF = FAIL
DKIM = NONE
DMARC = FAIL

Reasons:
• Lookalike domain
• Reply-To mismatch
• Gift card scam language
• Social engineering
```

---

## 🎯 MITRE ATT&CK Mapping

This project maps several phishing techniques to the MITRE ATT&CK framework.

| Technique | ID |
|-----------|----|
| Spearphishing Attachment | T1566.001 |
| Spearphishing Link | T1566.002 |
| Impersonation | T1656 |

---

## 💻 Technologies Used

- Python 3
- argparse
- csv
- email
- pathlib
- regex (re)
- dataclasses

---

## 📌 Future Improvements

- GUI version using Tkinter or PyQt
- Machine Learning-based phishing detection
- VirusTotal API integration
- Email attachment analysis
- PDF report generation
- Web dashboard
- Real-time email monitoring

---

## 🤝 Contributing

Contributions, feature requests, and bug reports are welcome.

Feel free to fork the repository and submit a pull request.

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Hamayl Ali**

Cybersecurity Enthusiast | Python Developer | SOC Analyst Aspirant

If you found this project useful, don't forget to ⭐ the repository!
