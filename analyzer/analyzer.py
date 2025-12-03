import argparse
from getpass import getpass
from analyzer.analyzer import PasswordReport

def run_single(password: str, wordlists, common, gps: float, as_json: bool):
    rep = PasswordReport(
        password,
        wordlist_paths=wordlists or [],
        common_passwords_path=common,
        guesses_per_second=gps
    )
    rep.analyze()
    if as_json:
        print(rep.to_json())
    else:
        r = rep.result
        print("-" * 60)
        print(f"Rating: {r['rating']} ({r['score']} / 100)")
        print(f"Entropy: {r['entropy_bits']} bits | Charset size: {r['charset_size']} | Length: {r['length']}")
        print(f"Estimated time to crack (all combos @ {r['guesses_per_second']}/s): {r['time_to_crack_readable']}")
        if r['dictionary_match'] or r['common_password_match']:
            print("WARNING: dictionary/common password detected.")
        if r['repeated_chars'] or r['sequence_detected'] or r['keyboard_pattern']:
            print("Pattern detected: repeated/sequence/keyboard pattern.")
        if r['breached']:
            print("BREACHED: Exact match in provided breached list.")

def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer")
    parser.add_argument("password", nargs="?", help="Password to analyze (optional, will prompt if omitted)")
    parser.add_argument("--wordlist", action='append', help="Path to extra wordlist (can be repeated)")
    parser.add_argument("--common", help="Path to common_passwords.txt")
    parser.add_argument("--gps", type=float, default=1e9, help="Guesses per second for brute-force estimate")
    parser.add_argument("--json", action='store_true', help="Output JSON")
    args = parser.parse_args()

    if args.password:
        # single run, password as argument
        run_single(args.password, args.wordlist, args.common, args.gps, args.json)
    else:
        print("Password Strength Analyzer (interactive mode)")
        print("Press Enter on empty line to exit.\n")
        while True:
            pwd = getpass("Enter a password to analyze (leave blank to quit): ")
            if not pwd:
                print("Bye!")
                break
            run_single(pwd, args.wordlist, args.common, args.gps, args.json)

if __name__ == "__main__":
    main()
