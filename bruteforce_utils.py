# bruteforce_utils.py

import itertools
import string
import hashlib # Import hashlib for hashing algorithms if needed directly
from hashing_utils import hash_md5, hash_sha256, hash_bcrypt, verify_bcrypt # Import bcrypt functions

def generate_candidates(charset, min_length, max_length):
    """
    Generates candidate passwords based on a given character set and length range.
    """
    for length in range(min_length, max_length + 1):
        for candidate_tuple in itertools.product(charset, repeat=length):
            yield "".join(candidate_tuple)

def bruteforce_crack(target_hash, hash_type, charset, min_length, max_length):
    """
    Attempts to crack a hash using a brute-force approach.
    :param target_hash: The hash to crack.
    :param hash_type: 'md5', 'sha256', or 'bcrypt'.
    :param charset: The character set to use for generating candidates.
    :param min_length: Minimum length of passwords to try.
    :param max_length: Maximum length of passwords to try.
    :return: The cracked password if found, otherwise None.
    """
    print(f"Starting brute-force attack for hash: {target_hash} ({hash_type})")
    print(f"Character set: {charset}, Length: {min_length}-{max_length}")

    if hash_type not in ['md5', 'sha256', 'bcrypt']:
        print(f"Error: Unsupported hash type '{hash_type}'.")
        return None

    for candidate in generate_candidates(charset, min_length, max_length):
        if hash_type == 'bcrypt':
            if verify_bcrypt(candidate, target_hash):
                print(f"Crack successful! Password found: '{candidate}'")
                return candidate
        else: # For md5 and sha256
            if hash_type == 'md5':
                current_hash = hash_md5(candidate)
            elif hash_type == 'sha256':
                current_hash = hash_sha256(candidate)
            
            if current_hash == target_hash:
                print(f"Crack successful! Password found: '{candidate}'")
                return candidate
                
    print("Brute-force attack completed. Password not found.")
    return None

if __name__ == "__main__":
    charset_lower = string.ascii_lowercase
    charset_digits = string.digits

    print("\n--- Brute-Force Crack Test ---")
    
    # Test 1: MD5 hash of 'ab'
    target_password_md5 = "ab"
    target_hash_md5 = hash_md5(target_password_md5)
    print(f"Target password: '{target_password_md5}', MD5 Hash: '{target_hash_md5}'")
    cracked_password_md5 = bruteforce_crack(target_hash_md5, 'md5', charset_lower, 1, 2)
    print(f"Result for MD5 'ab': {cracked_password_md5}\n")

    # Test 2: SHA256 hash of 'xyz'
    target_password_sha256 = "xyz"
    target_hash_sha256 = hash_sha256(target_password_sha256)
    print(f"Target password: '{target_password_sha256}', SHA-256 Hash: '{target_hash_sha256}'")
    cracked_password_sha256 = bruteforce_crack(target_hash_sha256, 'sha256', charset_lower, 1, 3)
    print(f"Result for SHA256 'xyz': {cracked_password_sha256}\n")

    # Test 3: Password not found (e.g., hash of 'abc' with max_length 2)
    target_password_not_found = "abc"
    target_hash_not_found = hash_md5(target_password_not_found)
    print(f"Target password: '{target_password_not_found}', MD5 Hash: '{target_hash_not_found}'")
    cracked_password_not_found = bruteforce_crack(target_hash_not_found, 'md5', charset_lower, 1, 2)
    print(f"Result for MD5 'abc' (expected not found): {cracked_password_not_found}\n")

    # Test 4: Bcrypt hash of 'a'
    target_password_bcrypt = "a" # Use a very short password for brute-force test
    target_hash_bcrypt = hash_bcrypt(target_password_bcrypt)
    print(f"Target password: '{target_password_bcrypt}', Bcrypt Hash: '{target_hash_bcrypt}'")
    cracked_password_bcrypt = bruteforce_crack(target_hash_bcrypt, 'bcrypt', charset_lower, 1, 1) # Max length 1
    print(f"Result for Bcrypt 'a': {cracked_password_bcrypt}\n")

    # Test 5: Bcrypt hash not found (e.g., too long)
    target_password_bcrypt_not_found = "ab" # A two-character password
    target_hash_bcrypt_not_found = hash_bcrypt(target_password_bcrypt_not_found)
    print(f"Target password: '{target_password_bcrypt_not_found}', Bcrypt Hash: '{target_hash_bcrypt_not_found}'")
    cracked_password_bcrypt_not_found = bruteforce_crack(target_hash_bcrypt_not_found, 'bcrypt', charset_lower, 1, 1) # Max length 1, so 'ab' won't be found
    print(f"Result for Bcrypt 'ab' (expected not found): {cracked_password_bcrypt_not_found}\n")
