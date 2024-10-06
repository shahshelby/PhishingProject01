# Phishing Link Scanner

A Python tool to detect phishing URLs by analyzing domain similarity, suspicious patterns, and other indicators.

## Features
- **Domain Similarity**: Detects typosquatting using Levenshtein distance.
- **Suspicious URL Check**: Flags URLs with unusual length or characters.
- **Domain Age Check**: Optionally flags newly registered domains (via `whois`).
- **Known Phishing Sites**: Compares URLs against a list of known phishing domains.
- **User Input**: Accepts URLs from the user or predefined lists.
- **Summary Report**: Displays results after scanning URLs.

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/shahshelby/PhishingProject01.git
    cd PhishingProject01
    ```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage
Run the scanner using predefined or manually inputted URLs:
```bash
python phishing_link_scanner.py
```
## Example Output
```bash
Potential Phishing Detected: http://examp1e.com
Scan completed. Total URLs scanned: 5
Phishing URLs detected: 2
```
## Notes
- **Domain Age Check:** Requires an active internet connection for WHOIS lookup.
- **Contributions:** Feedback and contributions are welcome! Please submit pull requests or report issues.
