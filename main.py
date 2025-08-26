"""
main.py - CLI for phishing link scanner
"""
import argparse, json, sys, os, pathlib
from scanner import analyze_url

def parse_args():
    ap = argparse.ArgumentParser(description="Phishing Link Scanner")
    ap.add_argument("url", nargs="?", help="URL to analyze")
    ap.add_argument("--file", "-f", help="File with one URL per line")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    ap.add_argument("--whois", action="store_true", help="Enable WHOIS domain age check (live)")
    ap.add_argument("--dns", action="store_true", help="Enable DNS A lookup (live)")
    ap.add_argument("--cert", action="store_true", help="Enable SSL certificate expiry check (live)")
    ap.add_argument("--http", action="store_true", help="Send HTTP HEAD (live)")
    ap.add_argument("--save-report", metavar="DIR", help="Save per-URL JSON reports to DIR")
    return ap.parse_args()

def load_urls(args):
    items = []
    if args.url:
        items.append(args.url.strip())
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                items.append(s)
    if not items:
        print("Provide a URL or --file FILE", file=sys.stderr)
        sys.exit(2)
    return items

def main():
    args = parse_args()
    urls = load_urls(args)
    all_results = []
    for u in urls:
        result = analyze_url(u, whois=args.whois, dns=args.dns, cert=args.cert, http=args.http)
        all_results.append(result)
        if args.save_report:
            os.makedirs(args.save_report, exist_ok=True)
            base = u.replace("://","_").replace("/","_")
            path = pathlib.Path(args.save_report) / f"{base}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

        if not args.json:
            print("="*72)
            print("URL: ", result["url"])
            print("Host:", result["host"], "   Base:", result["base_domain"])
            print("Risk Score:", result["risk_score"])
            if result["findings"]:
                print("Findings:")
                for f in result["findings"]:
                    print(f" - {f['name']}: +{f['score']}  ({f['details']})")
            if result["live"]:
                print("Live:", result["live"])
        else:
            print(json.dumps(result, ensure_ascii=False))

    if args.json and len(all_results) > 1:
        # print final newline for nicer CLI
        print()

if __name__ == "__main__":
    main()
