from urllib.parse import urlparse
import streamlit as st
from scanner_core import WebVulnerabilityScanner
import time
import json

st.set_page_config(
    page_title="CYBERNETIC SCANNER",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Updated Custom CSS for Blue/Cyan Cyber-Tech Look (less glow, visible labels) ---
st.markdown("""
<style>
    /* Overall Background and Text */
    .stApp {
        background-color: #0F1C2D; /* Darker Blue-Black */
        color: #00E5FF; /* Bright Cyan for general text */
        font-family: 'Fira Code', monospace; /* Consistent Monospaced Font */
    }

    /* Headers - Orbitron for Titles, Fira Code for sub-headers */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Orbitron', sans-serif; /* Futuristic Header Font */
        color: #66FFFF; /* Lighter Cyan for main titles */
    }
    h1 {
        color: #FF66FF; /* Neon Magenta for the main app title */
        text-align: center;
        font-size: 3.5em; /* Slightly larger */
        padding-bottom: 0.7em;
        /* Removed text-shadow for clean/minimalistic look */
    }

    /* General Labels for Inputs/Sliders */
    .stTextInput label, .stSlider label {
        color: #FFFFFF !important; /* Make labels explicitly white */
        font-family: 'Fira Code', monospace;
        font-size: 1.1em;
        font-weight: bold;
    }
    
    /* Buttons */
    .stButton>button {
        background-color: #0077B6; /* Deep Blue */
        color: #E0FFFF; /* Light Cyan Text */
        font-weight: bold;
        border-radius: 8px; /* Slightly more rounded */
        border: 2px solid #00E5FF; /* Bright Cyan border */
        padding: 12px 25px; /* Larger padding */
        box-shadow: 0 0 10px #00E5FF, 0 0 20px #00E5FF; /* Blue glow */
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #0096C7; /* Lighter Blue on hover */
        color: #FFFFFF; /* White text on hover */
        box-shadow: 0 0 15px #FF66FF, 0 0 25px #FF66FF; /* Magenta glow on hover */
        border-color: #FF66FF;
        transform: translateY(-2px); /* Slight lift effect */
    }

    /* Text Input */
    .stTextInput>div>div>input {
        background-color: #1A2E44 !important; /* Darker Blue-Grey */
        color: #00E5FF !important; /* Bright Cyan Text */
        border: 2px solid #00E5FF !important; /* Bright Cyan Border */
        border-radius: 6px;
        padding: 12px;
        box-shadow: 0 0 6px #00E5FF;
        font-family: 'Fira Code', monospace; /* Monospaced font */
    }
    .stTextInput>div>div>input:focus {
        border-color: #FF66FF !important; /* Neon Magenta on focus */
        box-shadow: 0 0 10px #FF66FF !important;
    }

    /* Text Area */
    .stTextArea>div>div>textarea {
        background-color: #1A2E44 !important;
        color: #00E5FF !important;
        border: 2px solid #00E5FF !important;
        border-radius: 6px;
        padding: 12px;
        font-family: 'Fira Code', monospace !important; /* Monospaced font */
        box-shadow: 0 0 6px #00E5FF;
    }

    /* Progress Bar */
    .stProgress>div>div>div>div {
        background-color: #00E5FF !important; /* Bright Cyan Progress */
    }
    .stProgress>div>div {
        background-color: #304E6C !important; /* Darker track */
        border-radius: 5px;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] button [data-testid="stMarkdownContainer"] p {
        font-size: 1.3rem; /* Slightly larger */
        color: #66FFFF; /* Lighter Cyan for tab titles */
        font-weight: bold;
        font-family: 'Orbitron', sans-serif;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 25px; /* More space between tabs */
        justify-content: center;
        background-color: #1A2E44; /* Darker tab background */
        border-radius: 10px;
        padding: 12px;
        box-shadow: 0 0 12px #00E5FF;
    }
    .stTabs [data-baseweb="tab-list"] button {
        background-color: transparent;
        border: none;
        transition: all 0.3s ease;
    }
    .stTabs [data-baseweb="tab-list"] button:hover {
        color: #FF66FF; /* Neon Magenta on hover */
        text-shadow: 0 0 8px #FF66FF;
    }
    .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {
        border-bottom: 4px solid #FF66FF; /* Neon Magenta active tab indicator */
        color: #FF66FF;
        text-shadow: 0 0 8px #FF66FF;
    }

    /* Expander (for detailed findings) */
    .stExpander {
        background-color: #1A2E44; /* Darker background for expander */
        border: 2px solid #00E5FF; /* Bright Cyan border */
        border-radius: 10px;
        padding: 15px; /* More padding */
        margin-bottom: 15px;
        box-shadow: 0 0 8px #00E5FF;
    }
    .stExpander > div > div > p {
        color: #00E5FF; /* Bright Cyan text inside expander */
        font-family: 'Fira Code', monospace;
    }
    /* Expander header */
    .stExpander > div:first-child > div:first-child {
        color: #66FFFF; /* Lighter Cyan for expander headers */
        font-weight: bold;
        font-family: 'Orbitron', sans-serif;
    }

    /* Streamlit Messages (info, warning, error, success) */
    .stAlert {
        border-radius: 10px;
        padding: 20px; /* More padding */
        margin-bottom: 15px;
        font-family: 'Fira Code', monospace;
        font-weight: bold;
        box-shadow: 0 0 10px rgba(0,229,255,0.3); /* Subtle blue glow for alerts */
    }
    .stAlert.st-success {
        background-color: #0F3D3D; /* Darker teal background */
        color: #00E5FF; /* Bright Cyan */
        border: 1px solid #00E5FF;
    }
    .stAlert.st-warning {
        background-color: #4D4A1A; /* Darker yellow-orange background */
        color: #FFD700; /* Gold */
        border: 1px solid #FFD700;
    }
    .stAlert.st-error {
        background-color: #5C1A1A; /* Darker red background */
        color: #FF6666; /* Soft Red */
        border: 1px solid #FF6666;
    }
    .stAlert.st-info {
        background-color: #1A2A4D; /* Darker blue background */
        color: #66FFFF; /* Lighter Cyan */
        border: 1px solid #66FFFF;
    }

    /* Code Blocks (for evidence) */
    code {
        background-color: #304E6C; /* Darker blue-grey for code */
        color: #00E5FF; /* Bright Cyan code text */
        border-radius: 5px;
        padding: 3px 6px;
        font-family: 'Fira Code', monospace;
        font-size: 0.95em;
    }
    pre {
        background-color: #1A2E44; /* Darker background for preformatted text */
        color: #00E5FF;
        border: 1px solid #00E5FF;
        border-radius: 8px;
        padding: 15px;
        overflow-x: auto;
    }

    /* Sidebar Customization */
    [data-testid="stSidebar"] {
        background-color: #1A2E44;
        color: #00E5FF;
        border-right: 3px solid #00E5FF;
        box-shadow: 3px 0 15px #00E5FF;
    }
    [data-testid="stSidebar"] h2 {
        color: #FF66FF;
        font-family: 'Orbitron', sans-serif;
        text-align: center;
        padding-bottom: 1.5em;
        /* Removed text-shadow here too for consistency if applied */
    }
    /* Streamlit internal text, e.g., for sliders */
    div.st-emotion-cache-1jmvejs p {
        font-family: 'Fira Code', monospace;
        color: #00E5FF;
    }
    div.st-emotion-cache-nahz7x p { /* Another p tag class for text */
        font-family: 'Fira Code', monospace;
        color: #00E5FF;
    }
    
    /* Divider */
    hr {
        border-top: 2px dashed #66FFFF; /* Lighter Cyan dashed line */
        margin-top: 1.5em;
        margin-bottom: 1.5em;
    }

</style>
""", unsafe_allow_html=True)


# Google Fonts for the cyberpunk aesthetic (ensuring Fira Code is loaded for monospaced)
st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Share+Tech+Mono&family=Fira+Code:wght@300;400;500;600;700&display=swap" rel="stylesheet">
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
                    st.markdown(f"**Payload:** \n```\n{finding['payload']}\n```") # Use code block for payload
                st.markdown(f"**Evidence:** \n```\n{finding['evidence']}\n```")
                st.markdown("---")
    else:
        st.success(f"No {title.lower()} vulnerabilities found.")

# The main scan trigger button
if st.button("INITIATE SCAN"):

    if not target_url.strip():
        st.error("🚨 **ERROR:** Please enter a valid URL to initiate the scan.")
    else:
        # Initialize the scanner with the selected depth
        scanner = WebVulnerabilityScanner(target_url, depth=max_depth)

        # Use st.session_state to hold logs and update dynamically
        st.session_state.scan_logs = [] # Clear logs for new scan at the start

        # Function to update progress bar, status text, and collect logs
        def update_progress_and_status(pct, msg, log_msg=None, log_level="INFO"):
            progress_bar.progress(pct)
            status_text.text(f"Status: {msg}")
            if log_msg:
                st.session_state.scan_logs.append(f"[{log_level}] {log_msg}")
            time.sleep(0.05) # Small delay for UI update visibility

        update_progress_and_status(0, "Preparing scanner...", log_msg="Scan initiated.", log_level="INFO")

        # --- Scan Execution Steps ---
        update_progress_and_status(5, "Checking security headers...",
                                log_msg="Starting security header analysis.")
        scanner.check_security_headers()

        update_progress_and_status(25, "Crawling website...",
                                log_msg=f"Starting website crawling up to depth {max_depth}.")
        scanner.crawl()


        update_progress_and_status(50, "Testing for SQL Injection on all visited URLs...",
                                log_msg="Initiating SQL Injection tests on GET parameters.")
        # Pass a copy of visited_urls to avoid RuntimeError if set changes during iteration
        for url_to_test in list(scanner.visited_urls):
            parsed = urlparse(url_to_test)
            # Only test URLs with query parameters for GET-based SQLi
            if parsed.query:
                scanner.test_sql_injection(url_to_test)


        update_progress_and_status(70, "Testing for Cross-Site Scripting on all visited URLs...",
                                log_msg="Initiating XSS tests on GET parameters.")
        for url_to_test in list(scanner.visited_urls):
            parsed = urlparse(url_to_test)
            if parsed.query:
                scanner.test_xss(url_to_test)


        update_progress_and_status(80, "Testing forms for vulnerabilities...",
                                log_msg="Analyzing forms for SQLi, XSS, and CSRF.")
        scanner.test_forms()

        update_progress_and_status(90, "Checking for sensitive files and directory listings...",
                                log_msg="Scanning for common sensitive files and directory exposure.")
        scanner.check_sensitive_files()

        update_progress_and_status(95, "Performing basic IDOR checks...",
                                log_msg="Conducting basic Insecure Direct Object Reference checks.")
        scanner.test_idor_basic() # This will now run

        final_results = scanner.results
        # Combine the logs collected by update_progress_and_status with logs from scanner_core
        final_logs = st.session_state.scan_logs + final_results["logs"]

        update_progress_and_status(100, "Scan complete! Generating report...",
                                log_msg="Scan finished. Results ready.", log_level="INFO")
        status_text.empty() # Clear final status message

        st.markdown("## Scan Summary")
        col1, col2, col3, col4, col5, col6 = st.columns(6) # Added column for IDOR
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
        with col6:
            st.metric(label="IDOR Findings", value=len(final_results['idor']))


        st.markdown("---") # Visual separator

        # --- Display Results in Tabs ---
        tab_titles = ["Security Headers", "SQL Injection", "XSS", "Form Vulnerabilities",
                      "CSRF", "Sensitive Files/Directory Listing", "IDOR", "Full Scan Logs"] # Added IDOR tab
        tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs(tab_titles) # Adjusted tab count

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

        with tab7: # This is the new IDOR tab
            display_findings(final_results["idor"], "Insecure Direct Object Reference (IDOR)")

        with tab8: # This is the new Full Scan Logs tab
            # Display combined logs in a dedicated text_area at the end
            st.subheader("📡 Full Scan Logs")
            st.text_area("All Scan Activity", value="\n".join(final_logs), height=500, max_chars=None, key="final_scan_logs_display")

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
                "header_issues": len(final_results['headers']),
                "idor_findings": len(final_results['idor']) # Added to summary
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