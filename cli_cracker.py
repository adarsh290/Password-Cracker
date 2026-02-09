# cli_cracker.py

import argparse
import string
import os

from hashing_utils import hash_md5, hash_sha256, hash_bcrypt
from cracker import crack_password_hybrid

def run_bcrypt_test_scenario(target_hash_val, wordlist_path_val):
    """
    Runs a specific bcrypt cracking test scenario, bypassing command-line parsing of the hash.
    """
    print("\n--- Running Bcrypt Test Scenario ---")
    print(f"Attempting to crack hash: {target_hash_val} (Type: bcrypt)")
    print(f"Using wordlist: {wordlist_path_val if wordlist_path_val else 'None'}")
    print(f"Using brute-force charset: 'lower' (Length: 1-4)") # Hardcoding for this test

    cracked_password = crack_password_hybrid(
        target_hash_val,
        'bcrypt',
        wordlist_path=wordlist_path_val,
        charset=string.ascii_lowercase,
        min_length=1,
        max_length=4 # Keep max_length small for faster test
    )

    if cracked_password:
        print(f"\nPassword cracked! Found: '{cracked_password}'")
    else:
        print("\nCould not crack the password.")
    print("--- Bcrypt Test Scenario Completed ---\n")

def main():
    parser = argparse.ArgumentParser(description="Password Cracking Tool for Educational Purposes")

    # Arguments for target hash
    parser.add_argument("target_hash", nargs='?', default=None, help="The hash to crack.")
    parser.add_argument("hash_type", nargs='?', default=None, choices=['md5', 'sha256', 'bcrypt'], 
                        help="Type of hash to crack (md5, sha256, bcrypt).")

    # Arguments for dictionary attack
    parser.add_argument("-w", "--wordlist", help="Path to a wordlist file for dictionary attack.")

    # Arguments for brute-force attack
    parser.add_argument("-c", "--charset", default="lower", 
                        choices=['lower', 'upper', 'digits', 'special', 'all'],
                        help="Character set for brute-force attack (lower, upper, digits, special, all).")
    parser.add_argument("-min", "--min_length", type=int, default=1,
                        help="Minimum length for brute-force attack.")
    parser.add_argument("-max", "--max_length", type=int, default=4,
                        help="Maximum length for brute-force attack.")
    
    # Argument for generating a hash
    parser.add_argument("-g", "--generate_hash", help="Generate hash for a given plaintext password (e.g., -g mypassword md5).")

    # Argument to run the bcrypt test scenario
    parser.add_argument("--test_bcrypt_scenario", action="store_true", help="Run a hardcoded bcrypt test scenario.")

    args = parser.parse_args()

    # Handle hash generation request
    if args.generate_hash:
        if not args.hash_type:
            print("Error: --hash_type must be specified when using --generate_hash.")
            return
        plaintext = args.generate_hash
        if args.hash_type == 'md5':
            print(f"MD5 hash of '{plaintext}': {hash_md5(plaintext)}")
        elif args.hash_type == 'sha256':
            print(f"SHA-256 hash of '{plaintext}': {hash_sha256(plaintext)}")
        elif args.hash_type == 'bcrypt':
            print(f"Bcrypt hash of '{plaintext}': {hash_bcrypt(plaintext)}")
        return

    # Handle bcrypt test scenario request
    if args.test_bcrypt_scenario:
        # Recreate test_wordlist_hybrid.txt if it was removed
        dummy_wordlist_content = """apple
banana
password
123456
qwerty
gemini
"""
        wordlist_path = "test_wordlist_hybrid.txt"
        with open(wordlist_path, "w") as f:
            f.write(dummy_wordlist_content)

        bcrypt_hash_for_apple = "$2b$12$zlMhDLjnfXx/BH08Y1ID3OKARcw0qsT58IodKIwNLmOSz2U60mWdy"
        run_bcrypt_test_scenario(bcrypt_hash_for_apple, wordlist_path)
        os.remove(wordlist_path) # Clean up
        return

    # If no generate_hash or test_bcrypt_scenario, then cracking
    if not args.target_hash or not args.hash_type:
        parser.error("target_hash and hash_type are required for cracking operations.")

    # Determine character set for brute-force
    chosen_charset = ""
    if args.charset == 'lower':
        chosen_charset = string.ascii_lowercase
    elif args.charset == 'upper':
        chosen_charset = string.ascii_uppercase
    elif args.charset == 'digits':
        chosen_charset = string.digits
    elif args.charset == 'special':
        chosen_charset = string.punctuation
    elif args.charset == 'all':
        chosen_charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    
    # Perform cracking
    print(f"Attempting to crack hash: {args.target_hash} (Type: {args.hash_type})")
    print(f"Using wordlist: {args.wordlist if args.wordlist else 'None'}")
    print(f"Using brute-force charset: '{args.charset}' (Length: {args.min_length}-{args.max_length})")

    cracked_password = crack_password_hybrid(
        args.target_hash,
        args.hash_type,
        wordlist_path=args.wordlist,
        charset=chosen_charset,
        min_length=args.min_length,
        max_length=args.max_length
    )

    if cracked_password:
        print(f"\nPassword cracked! Found: '{cracked_password}'")
    else:
        print("\nCould not crack the password.")

if __name__ == "__main__":
    main()