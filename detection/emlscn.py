import re
import dns.resolver

def check_dkim_dmarc(domain):
    try:
        dkim = dns.resolver.resolve(f'_domainkey.{domain}', 'TXT')
        dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        return {"DKIM": str(dkim[0]), "DMARC": str(dmarc[0])}
    except:
        return {"DKIM": "Not found", "DMARC": "Not found"}

def extract_email_headers(email_text):
    headers = {}
    for line in email_text.split("\n"):
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value
    return headers

email_sample = """
Received: from attacker.com (malicious.com [192.168.1.1])
From: "Fake Bank" <support@fakebank.com>
To: victim@example.com
Subject: Urgent! Verify your account
"""

headers = extract_email_headers(email_sample)
email_domain = headers.get("From", "").split("@")[-1]
dns_results = check_dkim_dmarc(email_domain)

print("Extracted Headers:", headers)
print("DKIM/DMARC Check:", dns_results)
