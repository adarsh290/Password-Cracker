# hashing_utils.py

import hashlib
import bcrypt # Import bcrypt

def hash_md5(text):
    """
    Generates the MD5 hash of a given string.
    """
    return hashlib.md5(text.encode()).hexdigest()

def hash_sha256(text):
    """
    Generates the SHA-256 hash of a given string.
    """
    return hashlib.sha256(text.encode()).hexdigest()

def hash_bcrypt(text):
    """
    Generates a bcrypt hash of a given string.
    The salt is automatically generated.
    """
    # bcrypt.gensalt() generates a salt
    hashed_password = bcrypt.hashpw(text.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def verify_bcrypt(text, hashed_text):
    """
    Verifies a plaintext string against a bcrypt hash.
    Returns True if they match, False otherwise.
    """
    try:
        return bcrypt.checkpw(text.encode('utf-8'), hashed_text.encode('utf-8'))
    except ValueError:
        # Handle cases where the hashed_text might be malformed or not a bcrypt hash
        return False

if __name__ == "__main__":
    test_string = "password"
    print(f"Original string: {test_string}")
    print(f"MD5 Hash: {hash_md5(test_string)}")
    print(f"SHA-256 Hash: {hash_sha256(test_string)}")

    # Bcrypt testing
    print("\n--- Bcrypt Testing ---")
    bcrypt_hash = hash_bcrypt(test_string)
    print(f"Bcrypt Hash: {bcrypt_hash}")

    # Verify correct password
    if verify_bcrypt(test_string, bcrypt_hash):
        print(f"Verification successful for '{test_string}' against its bcrypt hash.")
    else:
        print(f"Verification FAILED for '{test_string}' against its bcrypt hash.")

    # Verify incorrect password
    wrong_string = "wrongpassword"
    if verify_bcrypt(wrong_string, bcrypt_hash):
        print(f"Verification successful for '{wrong_string}' against its bcrypt hash (ERROR - should fail).")
    else:
        print(f"Verification FAILED (as expected) for '{wrong_string}' against its bcrypt hash.")

    # Test with a known bad hash format
    bad_bcrypt_hash = "$2b$04$thisisnotavalidsaltandhashformatforbcrypt"
    if verify_bcrypt(test_string, bad_bcrypt_hash):
        print(f"Verification successful for '{test_string}' against bad bcrypt hash (ERROR - should fail).")
    else:
        print(f"Verification FAILED (as expected) for '{test_string}' against bad bcrypt hash.")