import re

def analyze_email(email_text):
    risk_score = 0
    findings = []

    # Suspicious urgent words
    urgent_keywords = [
        "urgent", "immediately", "asap", "act now",
        "limited time", "verify now", "suspend",
        "account locked", "click now"
    ]

    # Sensitive data requests
    sensitive_keywords = [
        "password", "otp", "bank account",
        "credit card", "cvv", "pin", "social security",
        "login details"
    ]

    # Check for urgent language
    for word in urgent_keywords:
        if word.lower() in email_text.lower():
            risk_score += 2
            findings.append(f"⚠️ Urgent phrase detected: '{word}'")

    # Check for sensitive information requests
    for word in sensitive_keywords:
        if word.lower() in email_text.lower():
            risk_score += 3
            findings.append(f"🔒 Sensitive data request detected: '{word}'")

    # Detect URLs
    urls = re.findall(r'https?://\S+|www\.\S+', email_text)

    if urls:
        risk_score += len(urls)
        findings.append(f"🌐 Found {len(urls)} link(s):")
        for url in urls:
            findings.append(f"   - {url}")

    # Determine risk level
    if risk_score >= 8:
        risk_level = "HIGH RISK"
    elif risk_score >= 4:
        risk_level = "MEDIUM RISK"
    else:
        risk_level = "LOW RISK"

    # Display results
    print("\n===== Email Risk Analysis Report =====")
    print(f"Risk Level: {risk_level}")
    print(f"Risk Score: {risk_score}")

    if findings:
        print("\nDetected Issues:")
        for item in findings:
            print(item)
    else:
        print("\n✅ No suspicious patterns detected.")

# Main Program
print("=== Email Risk Analyzer ===")
email_content = input("\nPaste the email content:\n")

analyze_email(email_content)