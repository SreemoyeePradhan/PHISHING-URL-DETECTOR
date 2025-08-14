import streamlit as st
from dotenv import load_dotenv
import os
from url_checker import check_google_safebrowsing, check_virustotal, check_rule_based

# Load environment variables
load_dotenv()

st.set_page_config(page_title="URL Safety Checker", layout="wide")

st.title("🔍 URL Safety Checker")

# Input URL
url = st.text_input("Enter the URL to check:")

if st.button("Check URL"):
    if url:
        st.write("### Checking URL...")
        
        # Google Safe Browsing
        gs_result = check_google_safebrowsing(url)
        st.subheader("Google Safe Browsing Result")
        st.write(gs_result)
        
        # VirusTotal
        vt_result = check_virustotal(url)
        st.subheader("VirusTotal Result")
        st.write(vt_result)
        
        # Rule-based analysis
        rule_score, rule_findings = check_rule_based(url)
        st.subheader("Rule-based Analysis")
        for finding in rule_findings:
            st.markdown(f"- {finding}")
        
        # Determine Final Verdict
        final_verdict = ""
        verdict_color = "green"
        
        # STRICTER VERDICT LOGIC
        # Check if VirusTotal or Google Safe Browsing reported threats
        vt_threat = any(v in vt_result.lower() for v in ["malware", "phishing", "suspicious", "unsafe"])
        gs_threat = any(v in gs_result.lower() for v in ["malware", "phishing", "suspicious", "unsafe"])
        
        if vt_threat or gs_threat or rule_score >= 5:
            final_verdict = "❌ Unsafe URL"
            verdict_color = "red"
        elif rule_score > 0:  # Even 1 small risk triggers yellow
            final_verdict = "⚠ Potential Risk"
            verdict_color = "orange"
        else:
            final_verdict = "✅ Safe URL"
            verdict_color = "green"
        
        # Display final verdict with color
        st.markdown(
            f"<h3 style='color:{verdict_color}'>{final_verdict}</h3>",
            unsafe_allow_html=True
        )

    else:
        st.warning("Please enter a URL to check.")
