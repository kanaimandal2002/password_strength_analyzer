import argparse
from analyzer.analyzer import PasswordReport

def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer")
    parser.add_argument("password", help="Password to analyze")
    parser.add_argument("--wordlist", action='append', help="Path to extra wordlist (can be repeated)")
    parser.add_argument("--common", help="Path to common_passwords.txt")
    parser.add_argument("--gps", type=float, default=1e9, help="Guesses per second for brute-force estimate")
    parser.add_argument("--json", action='store_true', help="Output JSON")
    args = parser.parse_args()

    rep = PasswordReport(
        args.password,
        wordlist_paths=args.wordlist or [],
        common_passwords_path=args.common,
        guesses_per_second=args.gps
    )
    rep.analyze()
    if args.json:
        print(rep.to_json())
    else:
        r = rep.result
        print(f"Rating: {r['rating']} ({r['score']} / 100)")
        print(f"Entropy: {r['entropy_bits']} bits | Charset size: {r['charset_size']} | Length: {r['length']}")
        print(f"Estimated time to crack (all combos @ {r['guesses_per_second']}/s): {r['time_to_crack_readable']}")
        if r['dictionary_match'] or r['common_password_match']:
            print("WARNING: dictionary/common password detected.")
        if r['repeated_chars'] or r['sequence_detected'] or r['keyboard_pattern']:
            print("Pattern detected: repeated/sequence/keyboard pattern.")
        if r['breached']:
            print("BREACHED: Exact match in provided breached list.")

if __name__ == "__main__":
    main()
