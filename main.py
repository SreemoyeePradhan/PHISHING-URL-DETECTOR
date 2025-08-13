# main.py
import argparse
from url_checker import analyze_url
from api_checker import google_safebrowsing_check, virustotal_check
from colorama import init, Fore

init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(description="Phishing URL Detector CLI")
    parser.add_argument("url", help="URL to analyze")
    args = parser.parse_args()

    url = args.url.strip()

    # --- Run checks ---
    rule_res = analyze_url(url)
    gsb_res = google_safebrowsing_check(url)
    vt_res = virustotal_check(url)

    # --- Collect all reasons ---
    combined_reasons = list(rule_res.get("reasons", []))

    if gsb_res.get("malicious"):
        combined_reasons.append("Flagged by Google Safe Browsing")
    elif "error" in gsb_res:
        combined_reasons.append(f"Google Safe Browsing error: {gsb_res['error']}")

    if vt_res.get("malicious"):
        combined_reasons.append(
            f"Flagged by VirusTotal - Malicious detections: {vt_res.get('malicious_count', 0)}"
        )
    elif "error" in vt_res:
        combined_reasons.append(f"VirusTotal error: {vt_res['error']}")

    # --- Determine final verdict ---
    suspicious = (
        rule_res.get("suspicious", False)
        or gsb_res.get("malicious", False)
        or vt_res.get("malicious", False)
    )

    # --- Output ---
    print(Fore.CYAN + "Final URL Analysis")
    print(f"URL: {url}")
    print(f"Score (Rule-based): {rule_res['score']}")
    print(f"Verdict: {Fore.RED + 'SUSPICIOUS' if suspicious else Fore.GREEN + 'SAFE'}")

    if combined_reasons:
        print("Reasons:")
        for r in combined_reasons:
            print(f"- {r}")

if __name__ == "__main__":
    main()
