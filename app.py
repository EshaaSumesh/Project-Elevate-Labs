import streamlit as st
from scanner_core import WebVulnerabilityScanner
import time
import json # For saving structured report later, if desired

st.set_page_config(
    page_title="CYBERNETIC SCANNER",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for dark mode & cyber-tech look ---
# Enhanced CSS for more pronounced cyberpunk aesthetic
st.markdown("""
<style>
    /* Overall Background and Text */
    .stApp {
        background-color: #0A0A0A; /* Deep Space Black */
        color: #00FFCC; /* Neon Green for general text */
        font-family: 'Share Tech Mono', monospace; /* Techy Monospace Font */
    }

    /* Headers - Orbitron for Titles, Share Tech Mono for sub-headers */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Orbitron', sans-serif; /* Futuristic Header Font */
        color: #00FFFF; /* Neon Blue for main titles */
        text-shadow: 0 0 5px #00FFFF, 0 0 10px #00FFFF; /* Subtle neon glow */
    }
    h1 {
        color: #FF00FF; /* Neon Pink for the main app title */
        text-align: center;
        font-size: 3em;
        padding-bottom: 0.5em;
    }

    /* Buttons */
    .stButton>button {
        background-color: #238636; /* Dark Green */
        color: #00FFCC; /* Neon Green Text */
        font-weight: bold;
        border-radius: 6px;
        border: 2px solid #00FFFF; /* Neon Blue border */
        padding: 10px 20px;
        box-shadow: 0 0 8px #00FFFF, 0 0 12px #00FFFF; /* Blue glow */
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #2ea043; /* Lighter Green on hover */
        color: #00FFFF; /* Text turns blue on hover */
        box-shadow: 0 0 10px #FF00FF, 0 0 15px #FF00FF; /* Pink glow on hover */
        border-color: #FF00FF;
    }

    /* Text Input */
    .stTextInput>div>div>input {
        background-color: #161B22 !important; /* Dark Grey */
        color: #00FFCC !important; /* Neon Green Text */
        border: 2px solid #00FFFF !important; /* Neon Blue Border */
        border-radius: 5px;
        padding: 10px;
        box-shadow: 0 0 5px #00FFFF;
    }
    .stTextInput>div>div>input:focus {
        border-color: #FF00FF !important; /* Neon Pink on focus */
        box-shadow: 0 0 8px #FF00FF !important;
    }

    /* Text Area */
    .stTextArea>div>div>textarea {
        background-color: #161B22 !important;
        color: #00FFCC !important;
        border: 2px solid #00FFFF !important;
        border-radius: 5px;
        padding: 10px;
        font-family: 'Share Tech Mono', monospace !important;
        box-shadow: 0 0 5px #00FFFF;
    }

    /* Progress Bar */
    .stProgress>div>div>div>div {
        background-color: #00FFCC !important; /* Neon Green Progress */
    }
    .stProgress>div>div {
        background-color: #30363d !important; /* Darker track */
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] button [data-testid="stMarkdownContainer"] p {
        font-size: 1.2rem;
        color: #00FFFF; /* Neon Blue for tab titles */
        font-weight: bold;
        font-family: 'Orbitron', sans-serif;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 20px;
        justify-content: center;
        background-color: #161B22; /* Darker tab background */
        border-radius: 8px;
        padding: 10px;
        box-shadow: 0 0 10px #00FFFF;
    }
    .stTabs [data-baseweb="tab-list"] button {
        background-color: transparent;
        border: none;
        transition: all 0.3s ease;
    }
    .stTabs [data-baseweb="tab-list"] button:hover {
        color: #FF00FF; /* Neon Pink on hover */
        text-shadow: 0 0 5px #FF00FF;
    }
    .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {
        border-bottom: 3px solid #FF00FF; /* Neon Pink active tab indicator */
        color: #FF00FF;
        text-shadow: 0 0 5px #FF00FF;
    }

    /* Expander (for detailed findings) */
    .stExpander {
        background-color: #161B22; /* Darker background for expander */
        border: 1px solid #00FFFF; /* Neon Blue border */
        border-radius: 8px;
        padding: 10px;
        margin-bottom: 10px;
        box-shadow: 0 0 5px #00FFFF;
    }
    .stExpander > div > div > p {
        color: #00FFCC; /* Neon Green text inside expander */
        font-family: 'Share Tech Mono', monospace;
    }
    /* Expander header */
    .stExpander > div:first-child > div:first-child {
        color: #00FFFF;
        font-weight: bold;
        font-family: 'Orbitron', sans-serif;
    }

    /* Streamlit Messages (info, warning, error, success) */
    .stAlert {
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 10px;
        font-family: 'Share Tech Mono', monospace;
        font-weight: bold;
    }
    .stAlert.st-success {
        background-color: #1a3a2a; /* Darker green background */
        color: #00FFCC; /* Neon Green */
        border: 1px solid #00FFCC;
    }
    .stAlert.st-warning {
        background-color: #4a3a1a; /* Darker orange background */
        color: #FFD700; /* Gold */
        border: 1px solid #FFD700;
    }
    .stAlert.st-error {
        background-color: #5a1a1a; /* Darker red background */
        color: #FF6347; /* Tomato */
        border: 1px solid #FF6347;
    }
    .stAlert.st-info {
        background-color: #1a2a4a; /* Darker blue background */
        color: #00FFFF; /* Neon Blue */
        border: 1px solid #00FFFF;
    }

    /* Code Blocks (for evidence) */
    code {
        background-color: #30363d; /* Darker background for code */
        color: #00FFCC; /* Neon Green code text */
        border-radius: 4px;
        padding: 2px 4px;
        font-family: 'Fira Code', monospace; /* Monospace font for code */
        font-size: 0.9em;
    }
    pre {
        background-color: #161B22; /* Darker background for preformatted text */
        color: #00FFCC;
        border: 1px solid #00FFFF;
        border-radius: 5px;
        padding: 10px;
        overflow-x: auto;
    }

    /* Sidebar Customization */
    [data-testid="stSidebar"] {
        background-color: #161B22;
        color: #00FFCC;
        border-right: 2px solid #00FFFF;
        box-shadow: 2px 0 10px #00FFFF;
    }
    [data-testid="stSidebar"] h2 {
        color: #FF00FF;
        font-family: 'Orbitron', sans-serif;
        text-align: center;
        padding-bottom: 1em;
    }

    /* Divider */
    hr {
        border-top: 1px dashed #00FFFF; /* Neon blue dashed line */
    }

</style>
""", unsafe_allow_html=True)


# Google Fonts for the cyberpunk aesthetic
st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Fira+Code&display=swap" rel="stylesheet">
""", unsafe_allow_html=True)


st.title("CYBERNETIC SCANNER")
st.markdown("---")

# Input for Target URL
target_url = st.text_input(
    "Enter Target URL",
    "https://testphp.vulnweb.com/", # Default value
    help="The URL of the web application you want to scan."
)

# Input for Scan Depth
max_depth = st.slider(
    "Scan Depth (0 for current URL only, 1 for immediate links, etc.)",
    min_value=0,
    max_value=3,
    value=1, # Default scan depth
    help="Higher depth means more thorough but longer scans."
)

# Placeholders for dynamic content
log_placeholder = st.empty()
progress_bar = st.progress(0)
status_text = st.empty()

# Function to display findings
def display_findings(findings, title):
    st.subheader(f"🌐 {title} ({len(findings)})")
    if findings:
        for i, finding in enumerate(findings):
            severity = finding.get("severity", "Info")
            # Use Streamlit's colored expanders based on severity
            if severity == "High":
                color_func = st.error
            elif severity == "Medium":
                color_func = st.warning
            elif severity == "Low":
                color_func = st.info
            else:
                color_func = st.success # For 'Info' or 'N/A' severity

            with color_func(f"**[{severity.upper()}]** {finding['type']}").expander(f"Details for Finding #{i+1}"):
                st.markdown(f"**URL:** `{finding['url']}`")
                if finding['payload'] and finding['payload'] != "N/A":
                    st.markdown(f"**Payload:** `{finding['payload']}`")
                st.markdown(f"**Evidence:** \n```\n{finding['evidence']}\n```")
                st.markdown("---")
    else:
        st.success(f"No {title.lower()} vulnerabilities found.")

# The main scan trigger button
if st.button("INITIATE SCAN"):

    if not target_url.strip():
        st.error(" **ERROR:** Please enter a valid URL to initiate the scan.")
    else:
        # Initialize the scanner with the selected depth
        scanner = WebVulnerabilityScanner(target_url, depth=max_depth)

        # Use st.session_state to hold logs and update dynamically
        if 'scan_logs' not in st.session_state:
            st.session_state.scan_logs = []

        def update_log_and_progress(pct, msg, log_msg=None, log_level="INFO"):
            progress_bar.progress(pct)
            status_text.text(f"Status: {msg}")
            if log_msg:
                st.session_state.scan_logs.append(f"[{log_level}] {log_msg}")
                # Use a placeholder to update the text_area without re-running the whole app
                log_placeholder.text_area("Scan Logs", value="\n".join(st.session_state.scan_logs), height=350, max_chars=None, key="scan_logs_display")
            time.sleep(0.1) # Small delay for UI update visibility

        st.session_state.scan_logs = [] # Clear logs for new scan
        log_placeholder = st.empty() # Re-initialize placeholder

        update_log_and_progress(0, "Preparing scanner...", log_msg="Scan initiated.", log_level="INFO")

        # --- Scan Execution Steps ---
        update_log_and_progress(5, "Checking security headers...",
                                log_msg="Starting security header analysis.")
        scanner.check_security_headers()
        # The add_finding method in scanner_core now handles logging
        # The logs are collected in scanner.results["logs"]


        update_log_and_progress(25, "Crawling website...",
                                log_msg=f"Starting website crawling up to depth {max_depth}.")
        scanner.crawl()


        update_log_and_progress(50, "Testing for SQL Injection (GET)...",
                                log_msg="Initiating GET parameter SQL Injection tests.")
        # Ensure we test all visited URLs for GET-based SQLi/XSS
        for url_to_test in scanner.visited_urls:
             scanner.test_sql_injection(url_to_test)


        update_log_and_progress(70, "Testing for Cross-Site Scripting (GET)...",
                                log_msg="Initiating GET parameter XSS tests.")
        for url_to_test in scanner.visited_urls:
            scanner.test_xss(url_to_test)


        update_log_and_progress(80, "Testing forms for vulnerabilities...",
                                log_msg="Analyzing forms for SQLi, XSS, and CSRF.")
        scanner.test_forms()

        update_log_and_progress(90, "Checking for sensitive files and directory listings...",
                                log_msg="Scanning for common sensitive files and directory exposure.")
        scanner.check_sensitive_files()

        # update_log_and_progress(95, "Performing basic IDOR checks...",
        #                         log_msg="Conducting basic Insecure Direct Object Reference checks.")
        # scanner.test_idor_basic() # Uncomment if IDOR is matured for basic heuristic checks

        final_results = scanner.results
        final_logs = st.session_state.scan_logs + final_results["logs"] # Combine internal logs with scanner logs

        update_log_and_progress(100, "Scan complete! Generating report...",
                                log_msg="Scan finished. Results ready.", log_level="INFO")
        status_text.empty() # Clear final status message

        st.markdown("## Scan Summary")
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric(label="SQLi Findings", value=len(final_results['sqli']))
        with col2:
            st.metric(label="XSS Findings", value=len(final_results['xss']))
        with col3:
            st.metric(label="Form Vulns", value=len(final_results['forms']))
        with col4:
            st.metric(label="CSRF Findings", value=len(final_results['csrf']))
        with col5:
            st.metric(label="Sensitive Files", value=len(final_results['sensitive_files']))


        st.markdown("---") # Visual separator

        # --- Display Results in Tabs ---
        tab_titles = ["Security Headers", "SQL Injection", "XSS", "Form Vulnerabilities",
                      "CSRF", "Sensitive Files/Directory Listing", "Full Scan Logs"]
        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(tab_titles)

        with tab1:
            display_findings(final_results["headers"], "Security Header Issues")

        with tab2:
            display_findings(final_results["sqli"], "SQL Injection Vulnerabilities")

        with tab3:
            display_findings(final_results["xss"], "Cross-Site Scripting Vulnerabilities")

        with tab4:
            display_findings(final_results["forms"], "Form-Based Vulnerabilities (SQLi/XSS)")

        with tab5:
            display_findings(final_results["csrf"], "CSRF Vulnerabilities")

        with tab6:
            display_findings(final_results["sensitive_files"], "Sensitive Files & Directory Listings")

        with tab7:
            # Display combined logs
            st.subheader("📡 Full Scan Logs")
            st.text_area("All Scan Activity", value="\n".join(final_logs), height=500, max_chars=None)

        # --- Download Report Button ---
        # Generate a more structured report text, possibly JSON for later parsing
        report_data = {
            "target_url": target_url,
            "scan_depth": max_depth,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "summary": {
                "sqli_findings": len(final_results['sqli']),
                "xss_findings": len(final_results['xss']),
                "form_vulnerabilities": len(final_results['forms']),
                "csrf_findings": len(final_results['csrf']),
                "sensitive_files_findings": len(final_results['sensitive_files']),
                "header_issues": len(final_results['headers'])
            },
            "findings": final_results,
            "logs": final_logs
        }
        report_json = json.dumps(report_data, indent=4)

        st.markdown("---")
        st.download_button(
            label="DOWNLOAD FULL SCAN REPORT (JSON)",
            data=report_json,
            file_name=f"cyber_vuln_scan_report_{int(time.time())}.json",
            mime="application/json",
            help="Download a detailed JSON report of the scan results."
        )