# app.py
import streamlit as st
from url_checker import analyze_url
from api_checker import google_safebrowsing_check, virustotal_check

st.set_page_config(page_title="Phishing URL Detector", page_icon="🔍", layout="wide")
st.title("🔍 Phishing URL Detector")

st.markdown(
    "Enter a URL to check if it is safe or potentially malicious using "
    "**Rule-based Analysis**, **Google Safe Browsing**, and **VirusTotal**."
)

url = st.text_input("Enter URL to analyze", "", key="url_input")

# Single button (unique key) to avoid DuplicateElementId
clicked = st.button("Check URL", type="primary", key="check_btn")

if clicked:
    url = url.strip()
    if not url:
        st.warning("⚠️ Please enter a valid URL.")
    else:
        # --- Run all checks ---
        rule_res = analyze_url(url)
        gsb_res = google_safebrowsing_check(url)
        vt_res = virustotal_check(url)

        # Status booleans
        rule_bad = rule_res.get("suspicious", False)
        gsb_bad = gsb_res.get("malicious", False)
        vt_bad  = vt_res.get("malicious", False)

        # Icons for expanders
        rule_icon = "🚨" if rule_bad else "✅"
        gsb_icon  = "🚨" if gsb_bad else ("⚠️" if "error" in gsb_res else "✅")
        vt_icon   = "🚨" if vt_bad  else ("⚠️" if "error" in vt_res else "✅")

        # --- Rule-based section ---
        with st.expander(f"{rule_icon} Rule-based Analysis", expanded=True):
            if rule_bad:
                st.error(f"Suspicious — Score: {rule_res['score']}")
            else:
                st.success(f"Safe — Score: {rule_res['score']}")
            if rule_res.get("reasons"):
                st.markdown("**Reasons:**")
                for r in rule_res["reasons"]:
                    st.markdown(f"- {r}")

        # --- Google Safe Browsing section ---
        with st.expander(f"{gsb_icon} Google Safe Browsing", expanded=True):
            if "error" in gsb_res:
                st.warning(f"Error: {gsb_res['error']}")
            elif gsb_bad:
                st.error("Flagged as malicious by Google Safe Browsing")
                if gsb_res.get("details"):
                    st.json(gsb_res["details"])
            else:
                st.success("No threats found by Google Safe Browsing")

        # --- VirusTotal section ---
        with st.expander(f"{vt_icon} VirusTotal", expanded=True):
            if "error" in vt_res:
                st.warning(f"Error: {vt_res['error']}")
            elif vt_bad:
                st.error(
                    f"Flagged as malicious by VirusTotal — Malicious detections: {vt_res.get('malicious_count', 0)}"
                )
                if "suspicious_count" in vt_res:
                    st.info(f"Suspicious detections: {vt_res['suspicious_count']}")
                if "stats" in vt_res:
                    st.json(vt_res["stats"])
            else:
                st.success("No threats found by VirusTotal")

        # --- Merge reasons for final verdict ---
        combined_reasons = list(rule_res.get("reasons", []))
        if "error" in gsb_res:
            combined_reasons.append(f"Google Safe Browsing error: {gsb_res['error']}")
        elif gsb_bad:
            combined_reasons.append("Flagged by Google Safe Browsing")

        if "error" in vt_res:
            combined_reasons.append(f"VirusTotal error: {vt_res['error']}")
        elif vt_bad:
            combined_reasons.append(
                f"Flagged by VirusTotal — Malicious detections: {vt_res.get('malicious_count', 0)}"
            )

        # --- Final verdict ---
        suspicious = rule_bad or gsb_bad or vt_bad

        st.subheader("Final Verdict")
        if suspicious:
            st.error("🚨 SUSPICIOUS URL DETECTED 🚨")
        else:
            st.success("✅ SAFE URL")

        st.markdown(f"**Rule-based Score:** {rule_res['score']}")
        if combined_reasons:
            st.markdown("### Combined Reasons")
            for r in combined_reasons:
                st.markdown(f"- {r}")
