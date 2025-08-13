# api_checker.py
import requests
import os
from dotenv import load_dotenv

load_dotenv()  # loads variables from .env into environment


GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def google_safebrowsing_check(url):
    if not GOOGLE_API_KEY:
        return {"error": "Google API key not set."}

    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(api_url, json=payload)
        r.raise_for_status()
        data = r.json()

        if "matches" in data and data["matches"]:
            reasons = [f"Google Safe Browsing: {match['threatType']}" for match in data["matches"]]
            return {"malicious": True, "details": data, "reasons": reasons}
        return {"malicious": False, "reasons": []}

    except Exception as e:
        return {"error": str(e)}


def virustotal_check(url):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not set."}

    try:
        headers = {"x-apikey": VT_API_KEY}
        api_url = f"https://www.virustotal.com/api/v3/urls"
        # VirusTotal needs the URL in encoded form
        url_id = requests.utils.quote(url, safe='')
        scan_url = f"{api_url}/{url_id}"

        r = requests.get(scan_url, headers=headers)
        if r.status_code == 404:  # URL not analyzed yet, submit for analysis
            scan_req = requests.post(api_url, headers=headers, data={"url": url})
            scan_req.raise_for_status()
            return {"malicious": False, "reasons": ["VirusTotal: No prior data, submitted for analysis."]}

        r.raise_for_status()
        data = r.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)

        if malicious_count > 0 or suspicious_count > 0:
            reasons = []
            if malicious_count > 0:
                reasons.append(f"VirusTotal: {malicious_count} engines flagged as malicious")
            if suspicious_count > 0:
                reasons.append(f"VirusTotal: {suspicious_count} engines flagged as suspicious")
            return {"malicious": True, "stats": stats, "malicious_count": malicious_count,
                    "suspicious_count": suspicious_count, "reasons": reasons}

        return {"malicious": False, "reasons": []}

    except Exception as e:
        return {"error": str(e)}


def final_verdict(rule_res, gsb_res, vt_res):
    all_reasons = []

    # Rule-based
    if rule_res.get("suspicious"):
        all_reasons.extend(rule_res.get("reasons", []))

    # Google Safe Browsing
    if gsb_res.get("malicious"):
        all_reasons.extend(gsb_res.get("reasons", []))

    # VirusTotal
    if vt_res.get("malicious"):
        all_reasons.extend(vt_res.get("reasons", []))

    verdict = "SUSPICIOUS" if all_reasons else "SAFE"

    return {"verdict": verdict, "reasons": all_reasons}
