"""
Generates synthetic sample .eml files for testing the email spoof detector.
Includes a mix of legitimate emails (passing SPF/DKIM/DMARC) and spoofed /
phishing-style emails (failing auth checks, lookalike domains, display
name spoofing, etc).
"""
import os

SAMPLES_DIR = "sample_emails"

EMAILS = {
    # ---------------- LEGITIMATE EMAILS ----------------
    "legit_01_internal_it.eml": """Delivered-To: jsmith@corp-example.com
Received: from mail.corp-example.com (mail.corp-example.com [203.0.113.10])
    by mx.corp-example.com with ESMTPS id abc123
    for <jsmith@corp-example.com>; Mon, 22 Jun 2026 09:12:03 -0700
Authentication-Results: mx.corp-example.com;
    spf=pass smtp.mailfrom=it-notifications@corp-example.com;
    dkim=pass header.d=corp-example.com;
    dmarc=pass header.from=corp-example.com
From: IT Notifications <it-notifications@corp-example.com>
Reply-To: it-notifications@corp-example.com
To: jsmith@corp-example.com
Subject: Scheduled Maintenance Window - This Weekend
Date: Mon, 22 Jun 2026 09:12:00 -0700
Message-ID: <a1b2c3d4@corp-example.com>

Hi team,

This is a reminder that we'll be performing scheduled maintenance on the
file server this Saturday from 2 AM to 5 AM EST. No action is needed.

Thanks,
IT Operations
""",
    "legit_02_external_vendor.eml": """Delivered-To: jsmith@corp-example.com
Received: from mail.vendorcorp.com (mail.vendorcorp.com [198.51.100.20])
    by mx.corp-example.com with ESMTPS id def456
    for <jsmith@corp-example.com>; Tue, 23 Jun 2026 14:30:00 -0700
Authentication-Results: mx.corp-example.com;
    spf=pass smtp.mailfrom=billing@vendorcorp.com;
    dkim=pass header.d=vendorcorp.com;
    dmarc=pass header.from=vendorcorp.com
From: VendorCorp Billing <billing@vendorcorp.com>
Reply-To: billing@vendorcorp.com
To: jsmith@corp-example.com
Subject: Your Invoice #4471 is Ready
Date: Tue, 23 Jun 2026 14:30:00 -0700
Message-ID: <e5f6g7h8@vendorcorp.com>

Hello,

Your monthly invoice is now available in your account portal. Please
log in at https://portal.vendorcorp.com to view and download it.

Best regards,
VendorCorp Billing Team
""",
    # ---------------- SPOOFED / PHISHING EMAILS ----------------
    "spoof_01_failed_auth_payroll.eml": """Delivered-To: jsmith@corp-example.com
Received: from unknown (185.220.101.45)
    by mx.corp-example.com with SMTP id xyz789
    for <jsmith@corp-example.com>; Wed, 24 Jun 2026 03:15:00 -0700
Authentication-Results: mx.corp-example.com;
    spf=fail smtp.mailfrom=payroll@corp-example.com;
    dkim=fail header.d=corp-example.com;
    dmarc=fail header.from=corp-example.com
From: "Payroll Department" <payroll@corp-example.com>
Reply-To: payroll-update@corp-mail-secure.com
To: jsmith@corp-example.com
Subject: URGENT: Payroll System Update Required
Date: Wed, 24 Jun 2026 03:15:00 -0700
Message-ID: <fake001@corp-mail-secure.com>

Dear Employee,

Due to a recent system update, you must verify your direct deposit
information immediately or your next paycheck will be delayed.

Click here to verify: http://corp-example-payroll.secure-verify.net/login

Failure to act within 24 hours will result in payment suspension.

Payroll Department
""",
    "spoof_02_lookalike_domain_ceo.eml": """Delivered-To: jsmith@corp-example.com
Received: from unknown (45.142.214.19)
    by mx.corp-example.com with SMTP id qrs321
    for <jsmith@corp-example.com>; Thu, 25 Jun 2026 08:02:00 -0700
Authentication-Results: mx.corp-example.com;
    spf=fail smtp.mailfrom=ceo@corp-exarnple.com;
    dkim=none;
    dmarc=fail header.from=corp-exarnple.com
From: "Michael Tran (CEO)" <ceo@corp-exarnple.com>
Reply-To: m.tran.ceo@gmail.com
To: jsmith@corp-example.com
Subject: Quick favor - need this done today
Date: Thu, 25 Jun 2026 08:02:00 -0700
Message-ID: <fake002@corp-exarnple.com>

Hi,

I'm in back-to-back meetings and need you to purchase $500 in gift
cards for a client appreciation event. Send me the codes once
purchased, I'll reimburse you. Keep this between us for now, it's
a surprise.

Thanks,
Michael
""",
    "spoof_03_display_name_mismatch.eml": """Delivered-To: jsmith@corp-example.com
Received: from unknown (91.234.55.12)
    by mx.corp-example.com with SMTP id tuv654
    for <jsmith@corp-example.com>; Fri, 26 Jun 2026 11:47:00 -0700
Authentication-Results: mx.corp-example.com;
    spf=softfail smtp.mailfrom=security-noreply@accountverify-srv.com;
    dkim=fail header.d=accountverify-srv.com;
    dmarc=fail header.from=accountverify-srv.com
From: "Microsoft Security Team" <security-noreply@accountverify-srv.com>
Reply-To: no-reply@accountverify-srv.com
To: jsmith@corp-example.com
Subject: Unusual sign-in activity detected on your account
Date: Fri, 26 Jun 2026 11:47:00 -0700
Message-ID: <fake003@accountverify-srv.com>

We detected an unusual sign-in attempt on your Microsoft account from
a new device in Lagos, Nigeria.

If this wasn't you, secure your account immediately:
http://account-verify-microsoft.live-secure-login.com

Microsoft Account Team
""",
    "spoof_04_spf_pass_but_domain_mismatch.eml": """Delivered-To: jsmith@corp-example.com
Received: from mail.freemailhost.com (mail.freemailhost.com [203.0.113.99])
    by mx.corp-example.com with ESMTPS id wxy987
    for <jsmith@corp-example.com>; Sat, 27 Jun 2026 16:20:00 -0700
Authentication-Results: mx.corp-example.com;
    spf=pass smtp.mailfrom=alerts@freemailhost.com;
    dkim=pass header.d=freemailhost.com;
    dmarc=pass header.from=freemailhost.com
From: "IT Support - corp-example.com" <alerts@freemailhost.com>
Reply-To: alerts@freemailhost.com
To: jsmith@corp-example.com
Subject: Your mailbox is almost full
Date: Sat, 27 Jun 2026 16:20:00 -0700
Message-ID: <fake004@freemailhost.com>

Your corp-example.com mailbox has reached 95% capacity. Click below to
increase your storage limit immediately or you will stop receiving
emails:

http://mailbox-storage-upgrade.freemailhost.com/expand

IT Support
""",
}


def main():
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    for filename, content in EMAILS.items():
        path = os.path.join(SAMPLES_DIR, filename)
        with open(path, "w") as f:
            f.write(content)
    print(f"Generated {len(EMAILS)} sample .eml files in '{SAMPLES_DIR}/'")
    n_spoof = sum(1 for k in EMAILS if k.startswith("spoof"))
    print(f"  {n_spoof} spoofed/phishing, {len(EMAILS) - n_spoof} legitimate")


if __name__ == "__main__":
    main()
