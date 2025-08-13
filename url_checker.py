# url_checker.py
import re
from urllib.parse import urlparse
import tldextract

# Common URL shorteners
SHORTENERS = {"bitly", "t.co", "tinyurl", "ow.ly", "goo.gl", "buff.ly", "is.gd"}

def analyze_url(url):
    out = {"url": url, "score": 0, "reasons": [], "suspicious": False}
    
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        out["score"] += 5
        out["reasons"].append("Malformed URL format")
        out["suspicious"] = True
        return out

    host = parsed.netloc.split(':')[0]
    path = parsed.path or ""
    full_url_str = (host + path).lower()

    # 1) HTTPS check
    if parsed.scheme.lower() != "https":
        out["score"] += 2
        out["reasons"].append("Uses HTTP instead of HTTPS (less secure)")

    # 2) IP address instead of domain
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        out["score"] += 3
        out["reasons"].append("Uses raw IP address instead of domain")

    # 3) '@' in URL (redirection trick)
    if "@" in url:
        out["score"] += 3
        out["reasons"].append("Contains '@' symbol (possible redirection trick)")

    # 4) Long URL
    if len(url) > 75:
        out["score"] += 1
        out["reasons"].append("Unusually long URL (>75 characters)")

    # 5) Many subdomains or suspicious hyphen
    ext = tldextract.extract(host)
    subdomains = ext.subdomain.split('.') if ext.subdomain else []
    if len(subdomains) >= 2:
        out["score"] += 1
        out["reasons"].append("Multiple subdomains detected")
    if '-' in ext.domain:
        out["score"] += 1
        out["reasons"].append("Hyphen in domain name (often used in phishing)")

    # 6) Shortener
    if ext.domain in SHORTENERS:
        out["score"] += 2
        out["reasons"].append("URL shortener service detected")

    # 7) Suspicious keywords
    suspicious_words = [
        "login", "secure", "confirm", "account", "update", "verify", "bank", "paypal", "signin"
    ]
    if any(w in full_url_str for w in suspicious_words):
        out["score"] += 2
        out["reasons"].append("Suspicious keyword found in URL")

    # 8) Punycode (IDN homograph attack)
    if "xn--" in host:
        out["score"] += 2
        out["reasons"].append("Punycode/IDN detected (possible homograph attack)")

    # Final suspicion decision (same threshold as others)
    out["suspicious"] = out["score"] >= 4

    return out


if __name__ == "__main__":
    test_urls = [
        "https://paypal.com",
        "http://paypa1.com/login",
        "http://192.168.1.1/verify",
        "https://bit.ly/3xyz",
        "http://example.com/@evil"
    ]
    for u in test_urls:
        result = analyze_url(u)
        print(f"URL: {u}\nScore: {result['score']}\nReasons: {result['reasons']}\nSuspicious? {result['suspicious']}\n")
