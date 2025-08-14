## 🔍 Phishing URL Detector

The Phishing URL Detector is a Streamlit-based web application designed to help users check whether a given URL is safe or potentially malicious. It leverages three layers of protection — rule-based analysis, Google Safe Browsing API, and VirusTotal API — to provide a comprehensive risk assessment. The system is built for security researchers, developers, and everyday users who want a quick and interactive way to verify suspicious links before clicking on them.
The application’s rule-based engine inspects URLs for phishing indicators such as the use of HTTP instead of HTTPS, excessive subdomains, URL shorteners, punycode, suspicious keywords, IP-based domains, and unusual formatting. This logic provides an immediate offline analysis even without API keys.
For enhanced accuracy, the app integrates with the Google Safe Browsing API to detect known malware, phishing pages, and harmful content, and the VirusTotal API to cross-check URLs against dozens of antivirus engines and blacklists. Even if one service fails or is unreachable, the rule-based component ensures that basic checks are still performed.
The project is implemented in Python using Streamlit for the user interface, enabling a clean, interactive, and browser-based experience. dotenv is used to manage sensitive API keys through a .env file, which should be excluded from version control for security. Requests to APIs are handled via the requests library, while tldextract and urllib assist in parsing and analyzing URLs.

# Main Features:
Real-time rule-based phishing detection.
Google Safe Browsing API integration.
VirusTotal API integration.
Combined final verdict with detailed reasoning.
Interactive Streamlit-based interface with collapsible sections for detailed reports.

# Tech Stack:
Python (Core language)
Streamlit (UI framework)
Google Safe Browsing API (Cloud-based threat intelligence)
VirusTotal API (Multi-engine URL scanning)
dotenv (Environment variable management)

# Python Libraries Used:
streamlit
requests
python-dotenv
tldextract
urllib
re (built-in)
