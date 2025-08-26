# Phishing Link Scanner (Python)
A lightweight, explainable phishing URL scanner you can run from the command line. It performs **static analysis** (no internet required) and optional **live checks** (WHOIS, DNS, SSL, HTTP) when enabled.

## Features
- URL normalization + punycode decoding
- Heuristic checks (length, `@`, IP-in-host, suspicious TLDs, hyphens, excessive dots, sensitive keywords, unicode confusables, misleading subdomains, known shorteners)
- Local allow/deny lists
- Optional live checks (WHOIS age, DNS resolve, SSL certificate basics, HTTP HEAD)
- Clear **reasoning** for each score contribution
- Outputs human-friendly text or JSON; can save reports per URL

## Quick start
```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py https://example.com
python main.py --json --save-report reports https://paypal.com-login.example.ru
```

## Optional live checks
Enable with flags (each independent):
```bash
python main.py --whois --dns --cert --http https://suspicious.example
```
> Live checks require internet and may take a few seconds.

## Batch scan
```bash
python main.py --file sample_urls.txt --json --save-report reports
```

## Project structure
```
phishing-link-scanner/
├─ main.py             # CLI entry
├─ scanner.py          # Core analysis library
├─ requirements.txt
├─ sample_urls.txt
└─ README.md
```

## GitHub + LinkedIn (as requested by Brainwave Matrix Solutions)
1. Create a public repo named **Brainwave_Matrix_Intern**. Put this project inside it (either as the whole repo or under `/phishing-link-scanner`).
2. Commit and push your code.
3. Record a short screen capture (30–60s) showing:
   - running `python main.py https://paypal.com-login.example.ru`
   - running `python main.py --json https://bit.ly/3abcxyz`
   - showing the JSON/report output
4. Post on LinkedIn with your video or screenshots. Suggested caption:
   > I built a Python **Phishing Link Scanner** for the Brainwave Matrix Solutions internship task.  
   > It scores risk, explains why, and supports optional WHOIS/DNS/SSL checks.  
   > #cybersecurity #python #infosec #phishing #BrainwaveMatrixSolutions @Brainwave Matrix Solutions
5. Tag **Brainwave Matrix Solutions** and add your repo link.

## License
MIT
