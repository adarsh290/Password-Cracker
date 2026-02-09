# dictionary_utils.py

from hashing_utils import hash_md5, hash_sha256, hash_bcrypt, verify_bcrypt
import os

def dictionary_crack(target_hash, hash_type, wordlist_path):
    """
    Attempts to crack a hash using a dictionary attack.
    :param target_hash: The hash to crack.
    :param hash_type: 'md5', 'sha256', or 'bcrypt'.
    :param wordlist_path: Path to the wordlist file.
    :return: The cracked password if found, otherwise None.
    """
    if not os.path.exists(wordlist_path):
        print(f"Error: Wordlist file not found at '{wordlist_path}'")
        return None

    print(f"Starting dictionary attack for hash: {target_hash} ({hash_type}) using '{wordlist_path}'")

    if hash_type not in ['md5', 'sha256', 'bcrypt']:
        print(f"Error: Unsupported hash type '{hash_type}'.")
        return None

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if not word: # Skip empty lines
                    continue
                
                if hash_type == 'bcrypt':
                    if verify_bcrypt(word, target_hash):
                        print(f"Crack successful! Password found: '{word}'")
                        return word
                else: # For md5 and sha256
                    if hash_type == 'md5':
                        current_hash = hash_md5(word)
                    elif hash_type == 'sha256':
                        current_hash = hash_sha256(word)
                    
                    if current_hash == target_hash:
                        print(f"Crack successful! Password found: '{word}'")
                        return word
    except Exception as e:
        print(f"An error occurred while reading the wordlist: {e}")
        return None

    print("Dictionary attack completed. Password not found.")
    return None

if __name__ == "__main__":
    # Example usage for dictionary_crack:
    print("\n--- Dictionary Crack Test ---")
    
    # Create a dummy wordlist for testing
    dummy_wordlist_content = """apple
banana
password
123456
qwerty
gemini
"""
    with open("test_wordlist.txt", "w") as f:
        f.write(dummy_wordlist_content)

    # Test 1: MD5 hash of 'password'
    target_password_md5 = "password"
    target_hash_md5 = hash_md5(target_password_md5)
    print(f"Target password: '{target_password_md5}', MD5 Hash: '{target_hash_md5}'")
    cracked_password_md5 = dictionary_crack(target_hash_md5, 'md5', "test_wordlist.txt")
    print(f"Result for MD5 'password': {cracked_password_md5}\n")

    # Test 2: SHA256 hash of 'gemini'
    target_password_sha256 = "gemini"
    target_hash_sha256 = hash_sha256(target_password_sha256)
    print(f"Target password: '{target_password_sha256}', SHA-256 Hash: '{target_hash_sha256}'")
    cracked_password_sha256 = dictionary_crack(target_hash_sha256, 'sha256', "test_wordlist.txt")
    print(f"Result for SHA256 'gemini': {cracked_password_sha256}\n")

    # Test 3: Password not found in wordlist
    target_password_not_found = "nonexistent"
    target_hash_not_found = hash_md5(target_password_not_found)
    print(f"Target password: '{target_password_not_found}', MD5 Hash: '{target_hash_not_found}'")
    cracked_password_not_found = dictionary_crack(target_hash_not_found, 'md5', "test_wordlist.txt")
    print(f"Result for MD5 'nonexistent' (expected not found): {cracked_password_not_found}\n")

    # Test 4: Bcrypt hash of 'apple'
    target_password_bcrypt = "apple"
    target_hash_bcrypt = hash_bcrypt(target_password_bcrypt)
    print(f"Target password: '{target_password_bcrypt}', Bcrypt Hash: '{target_hash_bcrypt}'")
    cracked_password_bcrypt = dictionary_crack(target_hash_bcrypt, 'bcrypt', "test_wordlist.txt")
    print(f"Result for Bcrypt 'apple': {cracked_password_bcrypt}\n")

    # Test 5: Bcrypt hash not found in wordlist
    target_password_bcrypt_not_found = "unlisted"
    target_hash_bcrypt_not_found = hash_bcrypt(target_password_bcrypt_not_found)
    print(f"Target password: '{target_password_bcrypt_not_found}', Bcrypt Hash: '{target_hash_bcrypt_not_found}'")
    cracked_password_bcrypt_not_found = dictionary_crack(target_hash_bcrypt_not_found, 'bcrypt', "test_wordlist.txt")
    print(f"Result for Bcrypt 'unlisted' (expected not found): {cracked_password_bcrypt_not_found}\n")

    # Clean up dummy wordlist
    os.remove("test_wordlist.txt")