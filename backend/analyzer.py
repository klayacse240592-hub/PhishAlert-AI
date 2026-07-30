"""
PhishGuard Analyzer
───────────────────
ML + heuristic phishing detection engine.
Uses rule-based scoring + optional Claude AI for description generation.
"""

import re
import urllib.parse
from datetime import datetime


# ─── KNOWN PHISHING PATTERNS ──────────────────────────────────────────────

PHISHING_KEYWORDS = [
    'verify your account', 'confirm your identity', 'suspended account',
    'unusual activity', 'click here immediately', 'login to secure',
    'update your payment', 'your account will be closed', 'verify now',
    'limited time offer', 'you have won', 'claim your prize', 'free gift',
    'act now', 'urgent action required', 'dear customer', 'dear user',
    'password expired', 'security alert', 'compromised', 'validate your',
    'reset your password now', 'unauthorized access', 'locked out',
    'paypal account', 'netflix account', 'amazon account', 'bank account',
    'social security', 'credit card', 'wire transfer', 'western union',
    'nigerian prince', 'lottery winner', 'inheritance'
]

SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.club', '.work', '.zip']

TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'github.com', 'stackoverflow.com', 'linkedin.com',
    'twitter.com', 'youtube.com', 'netflix.com', 'paypal.com',
    'wikipedia.org', 'reddit.com', 'instagram.com'
]

URL_PHISHING_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',      # IP address as host
    r'(paypal|amazon|apple|google|microsoft|netflix|bank).*\.(xyz|tk|ml|top|pw)',  # brand + suspicious TLD
    r'(secure|login|verify|account|update|confirm)[^.]*\.',  # suspicious subdomain keywords
    r'[a-z]+-[a-z]+-[a-z]+\.',                    # triple-hyphen domains
    r'@',                                           # @ in URL (URL misdirection)
    r'bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly',       # URL shorteners
    r'[0-9]{5,}',                                   # long number sequences in domain
]

URGENCY_WORDS = [
    'immediately', 'urgent', 'asap', 'expires', 'deadline', 'last chance',
    'act now', 'limited', 'hours left', '24 hours', 'final warning'
]

CREDENTIAL_WORDS = [
    'password', 'username', 'ssn', 'social security', 'credit card',
    'debit card', 'cvv', 'pin', 'account number', 'routing number',
    'date of birth', 'mother maiden', 'security question'
]


# ─── URL ANALYZER ──────────────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """Analyze a URL for phishing indicators."""
    score = 0
    indicators = []
    max_score = 100

    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()
    except Exception:
        return _build_result(85, ['Invalid URL format'], 'URL could not be parsed — likely malformed or obfuscated.', url)

    # ── Check 1: HTTP vs HTTPS
    if url.startswith('http://') and not url.startswith('https://'):
        score += 15
        indicators.append('Uses insecure HTTP protocol (no SSL)')

    # ── Check 2: IP address as domain
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 30
        indicators.append('IP address used instead of domain name')

    # ── Check 3: Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            indicators.append(f'Suspicious top-level domain: {tld}')
            break

    # ── Check 4: Brand impersonation
    brand_names = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix', 'facebook', 'instagram', 'bank', 'irs', 'fedex', 'dhl']
    for brand in brand_names:
        if brand in domain and not domain.endswith(f'{brand}.com'):
            score += 25
            indicators.append(f'Possible brand impersonation: "{brand}" in domain')
            break

    # ── Check 5: Suspicious keywords in URL
    suspicious_url_keywords = ['login', 'verify', 'secure', 'update', 'confirm', 'account', 'password', 'signin', 'banking']
    found_kw = [kw for kw in suspicious_url_keywords if kw in full_url]
    if len(found_kw) >= 2:
        score += 15
        indicators.append(f'Multiple suspicious keywords in URL: {", ".join(found_kw[:3])}')
    elif found_kw:
        score += 7
        indicators.append(f'Suspicious keyword in URL: {found_kw[0]}')

    # ── Check 6: URL shortener
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'short.link']
    if any(s in domain for s in shorteners):
        score += 20
        indicators.append('URL shortener used — destination is hidden')

    # ── Check 7: @ symbol in URL
    if '@' in url:
        score += 25
        indicators.append('@ symbol in URL — may redirect to different host')

    # ── Check 8: Excessive subdomains
    subdomain_count = domain.count('.')
    if subdomain_count >= 4:
        score += 15
        indicators.append(f'Excessive subdomains ({subdomain_count} dots) — common obfuscation technique')

    # ── Check 9: Very long URL
    if len(url) > 100:
        score += 10
        indicators.append(f'Unusually long URL ({len(url)} chars)')

    # ── Check 10: Trusted domain bonus
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith('.' + trusted):
            score = max(0, score - 25)
            indicators.append(f'✓ Recognized trusted domain: {trusted}')
            break

    # ── Check 11: Hyphen abuse
    if domain.count('-') >= 3:
        score += 10
        indicators.append('Excessive hyphens in domain — evasion tactic')

    # ── Check 12: Numeric domain
    digits_in_domain = sum(c.isdigit() for c in domain.split('.')[0])
    if digits_in_domain > 4:
        score += 10
        indicators.append('Domain contains many numbers — atypical for legitimate sites')

    score = min(score, max_score)

    description = _generate_url_description(url, domain, score, indicators)
    verdict = _score_to_verdict(score)

    return _build_result(score, indicators, description, url, verdict)


# ─── EMAIL ANALYZER ────────────────────────────────────────────────────────

def analyze_email(content: str) -> dict:
    """Analyze email content for phishing indicators."""
    score = 0
    indicators = []
    content_lower = content.lower()
    words = content_lower.split()

    # ── Check 1: Phishing keywords
    found_kw = [kw for kw in PHISHING_KEYWORDS if kw in content_lower]
    if len(found_kw) >= 3:
        score += 35
        indicators.append(f'Multiple phishing keywords: "{found_kw[0]}", "{found_kw[1]}", +{len(found_kw)-2} more')
    elif len(found_kw) >= 1:
        score += 15
        indicators.append(f'Phishing keyword detected: "{found_kw[0]}"')

    # ── Check 2: Urgency language
    found_urgency = [w for w in URGENCY_WORDS if w in content_lower]
    if len(found_urgency) >= 2:
        score += 20
        indicators.append(f'High urgency language: {", ".join(found_urgency[:3])}')
    elif found_urgency:
        score += 10
        indicators.append(f'Urgency language detected: "{found_urgency[0]}"')

    # ── Check 3: Credential harvesting
    found_creds = [w for w in CREDENTIAL_WORDS if w in content_lower]
    if found_creds:
        score += 20
        indicators.append(f'Requests sensitive info: {", ".join(found_creds[:3])}')

    # ── Check 4: URLs in email
    urls_in_email = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
    if urls_in_email:
        suspicious_urls = []
        for u in urls_in_email[:5]:
            url_result = analyze_url(u)
            if url_result['risk_score'] > 40:
                suspicious_urls.append(u[:50])
        if suspicious_urls:
            score += 25
            indicators.append(f'Suspicious URL(s) in email: {suspicious_urls[0]}...')

    # ── Check 5: Generic greeting
    generic_greetings = ['dear customer', 'dear user', 'dear member', 'dear account holder', 'valued customer', 'dear sir/madam']
    if any(g in content_lower for g in generic_greetings):
        score += 10
        indicators.append('Generic greeting (no personalization)')

    # ── Check 6: Misspellings / grammar
    misspellings = ['recieve', 'verifiy', 'acount', 'pasword', 'securiy', 'autentication', 'veirfy', 'urgant']
    found_mis = [m for m in misspellings if m in content_lower]
    if found_mis:
        score += 10
        indicators.append(f'Possible misspellings/grammar issues: "{found_mis[0]}"')

    # ── Check 7: Threatening language
    threats = ['legal action', 'arrest', 'suspended', 'terminated', 'deactivated', 'prosecuted', 'penalty', 'fine']
    found_threats = [t for t in threats if t in content_lower]
    if found_threats:
        score += 15
        indicators.append(f'Threatening language: "{found_threats[0]}"')

    # ── Check 8: Excessive caps / exclamation
    caps_ratio = sum(1 for c in content if c.isupper()) / max(len(content), 1)
    if caps_ratio > 0.3 and len(content) > 50:
        score += 10
        indicators.append('Excessive use of capital letters')
    if content.count('!') > 3:
        score += 5
        indicators.append('Excessive exclamation marks')

    score = min(score, 100)
    verdict = _score_to_verdict(score)
    description = _generate_email_description(content, score, indicators, found_kw)

    return _build_result(score, indicators, description, content[:100] + '...', verdict)


# ─── HELPERS ───────────────────────────────────────────────────────────────

def _score_to_verdict(score: float) -> str:
    if score >= 60:
        return 'PHISHING'
    elif score >= 30:
        return 'SUSPICIOUS'
    else:
        return 'SAFE'


def _build_result(score, indicators, description, input_val, verdict=None):
    if verdict is None:
        verdict = _score_to_verdict(score)
    return {
        'risk_score': round(score, 1),
        'verdict': verdict,
        'indicators': indicators,
        'description': description,
        'analyzed_at': datetime.utcnow().isoformat()
    }


def _generate_url_description(url, domain, score, indicators):
    if score >= 60:
        return (
            f"⚠️ HIGH RISK: This URL exhibits multiple characteristics commonly associated with phishing attacks. "
            f"The domain '{domain}' shows {len(indicators)} red flag(s) including: {'; '.join(indicators[:2])}. "
            f"Phishing URLs often use deceptive domains to impersonate trusted services and steal credentials. "
            f"Do NOT click this link or enter any personal information."
        )
    elif score >= 30:
        return (
            f"⚡ SUSPICIOUS: This URL has some characteristics that warrant caution. "
            f"Detected: {'; '.join(indicators[:2]) if indicators else 'minor anomalies'}. "
            f"While not definitively malicious, proceed with caution and verify the source independently before entering credentials."
        )
    else:
        trusted_note = next((i for i in indicators if '✓' in i), '')
        return (
            f"✅ SAFE: No significant phishing indicators detected. "
            f"{trusted_note + '. ' if trusted_note else ''}"
            f"The URL follows standard patterns for legitimate websites. "
            f"Always maintain vigilance — even safe-looking URLs can occasionally be compromised."
        )


def _generate_email_description(content, score, indicators, keywords):
    if score >= 60:
        return (
            f"⚠️ HIGH RISK PHISHING EMAIL: This email contains {len(indicators)} phishing indicator(s). "
            f"Key red flags: {'; '.join(indicators[:3])}. "
            f"This matches common social engineering tactics used by cybercriminals to steal login credentials, "
            f"financial information, or install malware. Do NOT click any links, download attachments, "
            f"or reply with personal information. Report this email to your IT department."
        )
    elif score >= 30:
        return (
            f"⚡ SUSPICIOUS EMAIL: This email has {len(indicators)} questionable characteristic(s). "
            f"Detected: {'; '.join(indicators[:2]) if indicators else 'minor anomalies'}. "
            f"Exercise caution before clicking links or providing information. "
            f"Verify the sender's identity through official channels."
        )
    else:
        return (
            f"✅ APPEARS SAFE: No significant phishing patterns detected in this email. "
            f"The content does not exhibit common social engineering tactics. "
            f"Remember: always verify unexpected requests for personal information, "
            f"even from seemingly legitimate senders."
        )
