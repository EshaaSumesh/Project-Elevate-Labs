import streamlit as st
from scanner_core import WebVulnerabilityScanner
import time

st.set_page_config(
    page_title="Cyber Web Vulnerability Scanner",
    layout="wide",
    initial_sidebar_state="expanded"
)
# --- Custom CSS for dark mode & cyber-tech look ---
dark_css = """
<style>
    /* Background and text colors */
    .reportview-container, .main, header, footer {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    /* Sidebar */
    .css-1d391kg {
        background-color: #161b22;
    }
    /* Headers */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Courier New', Courier, monospace;
        color: #58a6ff;
    }
    /* Buttons */
    .stButton>button {
        background-color: #238636;
        color: white;
        font-weight: bold;
        border-radius: 6px;
        border: none;
        padding: 10px 20px;
    }
    .stButton>button:hover {
        background-color: #2ea043;
        color: #e6f1ff;
    }
    /* Text input */
    input, textarea {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
        border: 1px solid #30363d !important;
    }
    /* Scrollbars */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #0d1117;
    }
    ::-webkit-scrollbar-thumb {
        background-color: #30363d;
        border-radius: 10px;
    }
    /* Text area */
    textarea {
        font-family: 'Courier New', Courier, monospace !important;
    }
</style>
"""

st.markdown(dark_css, unsafe_allow_html=True)

# Page config
st.set_page_config(
    page_title="Cyber Web Vulnerability Scanner",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("Cyber Web Vulnerability Scanner")

target_url = st.text_input(
    "Enter Target URL", 
    "https://testphp.vulnweb.com/"
)

# Progress placeholders
progress_bar = st.progress(0)
status_text = st.empty()

if st.button("Start Scan"):

    if not target_url.strip():
        st.error("Please enter a valid URL")
    else:
        scanner = WebVulnerabilityScanner(target_url)

        progress_bar.progress(0)
        status_text.text("Initializing scan...")

        results = {
            "headers": [],
            "sqli": [],
            "xss": [],
            "forms": [],
            "logs": []
        }

        def update_progress(pct, msg):
            progress_bar.progress(pct)
            status_text.text(msg)

        update_progress(5, "Checking security headers...")
        scanner.check_security_headers()
        results["headers"] = scanner.results["headers"]
        results["logs"].extend(scanner.results["logs"])

        update_progress(25, "Crawling website to find links and forms...")
        scanner.crawl()
        results["logs"].extend(scanner.results["logs"])

        update_progress(50, "Testing for SQL Injection vulnerabilities...")
        scanner.test_sql_injection(target_url)
        results["sqli"] = scanner.results["sqli"]
        results["logs"].extend(scanner.results["logs"])

        update_progress(70, "Testing for Cross-Site Scripting (XSS)...")
        scanner.test_xss(target_url)
        results["xss"] = scanner.results["xss"]
        results["logs"].extend(scanner.results["logs"])

        update_progress(90, "Testing forms for vulnerabilities...")
        scanner.test_forms()
        results["forms"] = scanner.results["forms"]
        results["logs"].extend(scanner.results["logs"])

        update_progress(100, "Scan complete!")
        status_text.text("")

        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "Security Headers", 
            "SQL Injection", 
            "XSS", 
            "Forms", 
            "Logs"
        ])

        with tab1:
            if results["headers"]:
                for header in results["headers"]:
                    st.warning(header)
            else:
                st.success("All recommended security headers are present.")

        with tab2:
            if results["sqli"]:
                for vuln in results["sqli"]:
                    st.error(vuln)
            else:
                st.success("No SQL Injection vulnerabilities found.")

        with tab3:
            if results["xss"]:
                for vuln in results["xss"]:
                    st.error(vuln)
            else:
                st.success("No Cross-Site Scripting (XSS) vulnerabilities found.")

        with tab4:
            if results["forms"]:
                for vuln in results["forms"]:
                    st.warning(vuln)
            else:
                st.success("No vulnerable forms detected.")

        with tab5:
            st.text_area("Scan Logs", value="\n".join(results.get("logs", [])), height=350, max_chars=None)

        report_text = f"""
Cyber Web Vulnerability Scanner Report

Target URL: {target_url}

Security Headers:
{chr(10).join(results['headers']) if results['headers'] else 'All headers present'}

SQL Injection Findings:
{chr(10).join(results['sqli']) if results['sqli'] else 'No issues found.'}

XSS Findings:
{chr(10).join(results['xss']) if results['xss'] else 'No issues found.'}

Form Vulnerabilities:
{chr(10).join(results['forms']) if results['forms'] else 'No issues found.'}

Logs:
{chr(10).join(results['logs'])}
"""

        st.download_button(
            label="Download Full Scan Report",
            data=report_text,
            file_name="cyber_vuln_scan_report.txt",
            mime="text/plain"
        )
