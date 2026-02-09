# test_cracker.py

import unittest
import os
import string
from hashing_utils import hash_md5, hash_sha256, hash_bcrypt, verify_bcrypt
from bruteforce_utils import generate_candidates, bruteforce_crack
from dictionary_utils import dictionary_crack
from cracker import crack_password_hybrid

class TestHashingFunctions(unittest.TestCase):
    def test_md5(self):
        self.assertEqual(hash_md5("password"), "5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertNotEqual(hash_md5("Password"), "5f4dcc3b5aa765d61d8327deb882cf99") # Case sensitivity

    def test_sha256(self):
        self.assertEqual(hash_sha256("password"), "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
        self.assertNotEqual(hash_sha256("Password"), "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8") # Case sensitivity

    def test_bcrypt(self):
        # Hash a password
        plain_password = "testpassword"
        bcrypt_hash = hash_bcrypt(plain_password)
        self.assertTrue(bcrypt_hash.startswith("$2b$")) # Check format
        self.assertGreater(len(bcrypt_hash), 30) # Check length

        # Verify correct password
        self.assertTrue(verify_bcrypt(plain_password, bcrypt_hash))
        # Verify incorrect password
        self.assertFalse(verify_bcrypt("wrongpassword", bcrypt_hash))
        # Verify with different hash of same password (due to salt, hashes will differ)
        self.assertNotEqual(hash_bcrypt(plain_password), hash_bcrypt(plain_password))

class TestGenerateCandidates(unittest.TestCase):
    def test_single_length_lowercase(self):
        candidates = list(generate_candidates(string.ascii_lowercase, 1, 1))
        self.assertEqual(len(candidates), 26)
        self.assertIn("a", candidates)
        self.assertIn("z", candidates)
        self.assertNotIn("aa", candidates)

    def test_multiple_length_digits(self):
        candidates = list(generate_candidates(string.digits, 1, 2))
        self.assertEqual(len(candidates), 10 + 100) # 0-9 (len 1), 00-99 (len 2)
        self.assertIn("0", candidates)
        self.assertIn("9", candidates)
        self.assertIn("00", candidates)
        self.assertIn("99", candidates)
        self.assertNotIn("000", candidates)

class TestCrackingFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a dummy wordlist for dictionary tests
        cls.wordlist_path = "test_wordlist_for_tests.txt"
        with open(cls.wordlist_path, "w") as f:
            f.write("""apple
banana
password
123456
""")
        
        # Pre-generate some hashes for tests
        cls.md5_password = "test"
        cls.md5_hash = hash_md5(cls.md5_password)
        cls.sha256_password = "secret"
        cls.sha256_hash = hash_sha256(cls.sha256_password)
        cls.bcrypt_password = "apple"
        cls.bcrypt_hash = hash_bcrypt(cls.bcrypt_password)

    @classmethod
    def tearDownClass(cls):
        # Clean up the dummy wordlist
        if os.path.exists(cls.wordlist_path):
            os.remove(cls.wordlist_path)

    def test_bruteforce_md5(self):
        cracked = bruteforce_crack(self.md5_hash, 'md5', string.ascii_lowercase, 1, 4)
        self.assertEqual(cracked, self.md5_password)
        
        cracked_fail = bruteforce_crack(self.md5_hash, 'md5', string.ascii_lowercase, 1, 3) # Too short
        self.assertIsNone(cracked_fail)

    def test_bruteforce_bcrypt(self):
        # Need a very short password for brute-force bcrypt to pass quickly
        short_password = "a"
        short_bcrypt_hash = hash_bcrypt(short_password)
        cracked = bruteforce_crack(short_bcrypt_hash, 'bcrypt', string.ascii_lowercase, 1, 1)
        self.assertEqual(cracked, short_password)

        cracked_fail = bruteforce_crack(short_bcrypt_hash, 'bcrypt', string.ascii_lowercase, 2, 2) # Wrong length
        self.assertIsNone(cracked_fail)

    def test_dictionary_sha256(self):
        cracked = dictionary_crack(self.sha256_hash, 'sha256', self.wordlist_path) # 'secret' not in wordlist
        self.assertIsNone(cracked) 

        cracked = dictionary_crack(hash_sha256("apple"), 'sha256', self.wordlist_path)
        self.assertEqual(cracked, "apple")

    def test_dictionary_bcrypt(self):
        cracked = dictionary_crack(self.bcrypt_hash, 'bcrypt', self.wordlist_path)
        self.assertEqual(cracked, self.bcrypt_password)

        cracked_fail = dictionary_crack(hash_bcrypt("notinthelist"), 'bcrypt', self.wordlist_path)
        self.assertIsNone(cracked_fail)

    def test_hybrid_crack(self):
        # Test 1: Dictionary crack first (MD5)
        cracked_dict = crack_password_hybrid(hash_md5("password"), 'md5', 
                                              wordlist_path=self.wordlist_path,
                                              charset=string.ascii_lowercase, min_length=1, max_length=2)
        self.assertEqual(cracked_dict, "password")

        # Test 2: Brute-force after dictionary fails (MD5)
        # 'tes' is not in wordlist, but crackable by brute-force
        cracked_brute = crack_password_hybrid(hash_md5("tes"), 'md5',
                                               wordlist_path=self.wordlist_path,
                                               charset=string.ascii_lowercase, min_length=1, max_length=3)
        self.assertEqual(cracked_brute, "tes")

        # Test 3: Bcrypt dictionary crack
        cracked_bcrypt_dict = crack_password_hybrid(self.bcrypt_hash, 'bcrypt',
                                                     wordlist_path=self.wordlist_path,
                                                     charset=string.ascii_lowercase, min_length=1, max_length=1)
        self.assertEqual(cracked_bcrypt_dict, self.bcrypt_password)
        
        # Test 4: Bcrypt brute-force after dictionary fails
        short_password_bf = "b"
        short_bcrypt_hash_bf = hash_bcrypt(short_password_bf)
        cracked_bcrypt_brute = crack_password_hybrid(short_bcrypt_hash_bf, 'bcrypt',
                                                      wordlist_path="non_existent_wordlist.txt", # Ensure dict fails
                                                      charset=string.ascii_lowercase, min_length=1, max_length=1)
        self.assertEqual(cracked_bcrypt_brute, short_password_bf)


if __name__ == '__main__':
    unittest.main()
