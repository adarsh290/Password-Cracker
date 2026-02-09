# cracker.py

from hashing_utils import hash_md5, hash_sha256, hash_bcrypt
from bruteforce_utils import bruteforce_crack, generate_candidates
from dictionary_utils import dictionary_crack
import string
import os

def crack_password_hybrid(target_hash, hash_type, wordlist_path=None, 
                          charset=None, min_length=1, max_length=4):
    """
    Attempts to crack a password using a hybrid approach (dictionary + brute-force).
    :param target_hash: The hash to crack.
    :param hash_type: 'md5', 'sha256', or 'bcrypt'.
    :param wordlist_path: Optional path to a wordlist file for dictionary attack.
    :param charset: Optional character set for brute-force attack (e.g., string.ascii_lowercase).
    :param min_length: Minimum length for brute-force.
    :param max_length: Maximum length for brute-force.
    :return: The cracked password if found, otherwise None.
    """
    cracked_password = None

    # 1. Attempt Dictionary Attack (if wordlist is provided)
    if wordlist_path and os.path.exists(wordlist_path):
        print(f"Attempting dictionary attack...")
        cracked_password = dictionary_crack(target_hash, hash_type, wordlist_path)
        if cracked_password:
            return cracked_password
    elif wordlist_path and not os.path.exists(wordlist_path):
        print(f"Warning: Wordlist not found at '{wordlist_path}'. Skipping dictionary attack.")

    # 2. Attempt Brute-Force Attack (if charset is provided)
    if charset:
        print(f"Attempting brute-force attack...")
        cracked_password = bruteforce_crack(target_hash, hash_type, charset, min_length, max_length)
        if cracked_password:
            return cracked_password

    print("Hybrid attack completed. Password not found.")
    return None

if __name__ == "__main__":
    # Ensure hashing_utils.py, bruteforce_utils.py, and dictionary_utils.py are in the same directory
    # Also ensure a wordlist.txt exists for testing purposes

    # Create a dummy wordlist for testing
    dummy_wordlist_content = """apple
test
password
123456
qwerty
gemini
"""
    with open("test_wordlist_hybrid.txt", "w") as f:
        f.write(dummy_wordlist_content)

    print("\n--- Hybrid Crack Test ---")

    # Test 1: Dictionary crack (password: 'password', MD5)
    target_password_dict = "password"
    target_hash_dict = hash_md5(target_password_dict)
    print(f"\nTarget: '{target_password_dict}', MD5 Hash: '{target_hash_dict}'")
    cracked = crack_password_hybrid(target_hash_dict, 'md5', 
                                    wordlist_path="test_wordlist_hybrid.txt",
                                    charset=string.ascii_lowercase, min_length=1, max_length=3)
    print(f"Result for '{target_password_dict}' (MD5, dictionary): {cracked}")

    # Test 2: Brute-force crack (password: 'abc', MD5) - not in dictionary
    target_password_brute = "abc"
    target_hash_brute = hash_md5(target_password_brute)
    print(f"\nTarget: '{target_password_brute}', MD5 Hash: '{target_hash_brute}'")
    cracked = crack_password_hybrid(target_hash_brute, 'md5', 
                                    wordlist_path="test_wordlist_hybrid.txt", # Will fail
                                    charset=string.ascii_lowercase, min_length=1, max_length=3)
    print(f"Result for '{target_password_brute}' (MD5, brute-force): {cracked}")

    # Test 3: Password not found (too long for brute-force, not in dictionary)
    target_password_not_found = "abcd"
    target_hash_not_found = hash_md5(target_password_not_found)
    print(f"\nTarget: '{target_password_not_found}', MD5 Hash: '{target_hash_not_found}'")
    cracked = crack_password_hybrid(target_hash_not_found, 'md5', 
                                    wordlist_path="test_wordlist_hybrid.txt", 
                                    charset=string.ascii_lowercase, min_length=1, max_length=3) # Max length 3
    print(f"Result for '{target_password_not_found}' (MD5, not found): {cracked}")
    
    # Test 4: Bcrypt hash crack by dictionary (password: 'apple')
    target_password_bcrypt_dict = "apple"
    target_hash_bcrypt_dict = hash_bcrypt(target_password_bcrypt_dict)
    print(f"\nTarget: '{target_password_bcrypt_dict}', Bcrypt Hash: '{target_hash_bcrypt_dict}'")
    cracked_bcrypt_dict = crack_password_hybrid(target_hash_bcrypt_dict, 'bcrypt',
                                                wordlist_path="test_wordlist_hybrid.txt",
                                                charset=string.ascii_lowercase, min_length=1, max_length=3)
    print(f"Result for '{target_password_bcrypt_dict}' (Bcrypt, dictionary): {cracked_bcrypt_dict}")

    # Test 5: Bcrypt hash crack by brute-force (password: 'a')
    target_password_bcrypt_brute = "a"
    target_hash_bcrypt_brute = hash_bcrypt(target_password_bcrypt_brute)
    print(f"\nTarget: '{target_password_bcrypt_brute}', Bcrypt Hash: '{target_hash_bcrypt_brute}'")
    cracked_bcrypt_brute = crack_password_hybrid(target_hash_bcrypt_brute, 'bcrypt',
                                                  wordlist_path="non_existent_wordlist.txt", # Ensure dictionary fails
                                                  charset=string.ascii_lowercase, min_length=1, max_length=1)
    print(f"Result for '{target_password_bcrypt_brute}' (Bcrypt, brute-force): {cracked_bcrypt_brute}")


    # Clean up dummy wordlist
    os.remove("test_wordlist_hybrid.txt")