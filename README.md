# Web Application Vulnerability Scanner

## **Overview**
The **Web Application Vulnerability Scanner** is a Python-based tool designed to identify common security vulnerabilities in web applications. It detects issues such as **Cross-Site Scripting (XSS)**, **SQL Injection (SQLi)**, and **Cross-Site Request Forgery (CSRF)** by crawling web pages, injecting test payloads, and analyzing server responses.

This project is aimed at developers, cybersecurity students, and ethical hackers to help secure web applications during the development phase.

---

## **Features**
- **Automated Scanning:** Detects common vulnerabilities (XSS, SQLi, CSRF).
- **Crawling & Form Detection:** Extracts links and form fields for testing.
- **Payload Injection:** Tests endpoints with malicious payloads.
- **OWASP Top 10 Coverage:** Focuses on widely known web vulnerabilities.
- **Lightweight:** Easy to set up and use.

---

## **Tools and Technologies**
- **Programming Language:** Python 3.x  
- **Libraries:**
  - `requests` – HTTP requests.
  - `BeautifulSoup` – HTML parsing and form extraction.
  - `urllib` – URL handling.
  - `re` – Regular expressions.

---

## **Installation**
1. Clone this repository:
   ```bash
   git clone https://github.com/yEshaaSumesh/Project-Elevate-Labs.git
   cd Project-Elevate-Labs
   
2.Install dependencies:

```bash
pip install -r requirements.txt
```
3.Ensure Python 3.x is installed and git is installed in your system.

