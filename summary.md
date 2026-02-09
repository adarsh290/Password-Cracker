Here's a summary of the implemented password cracking tool:

### What has been implemented?

I have implemented a modular Python-based password cracking tool designed for educational purposes, covering various aspects of password security and attack methods:

1.  **Hashing Utilities (`hashing_utils.py`):**
    *   Functions to generate MD5 and SHA-256 hashes for a given plaintext.
    *   Functions to generate and verify Bcrypt hashes, demonstrating a more robust and modern hashing algorithm.
2.  **Brute-Force Utilities (`bruteforce_utils.py`):**
    *   A generator to produce candidate passwords based on a specified character set (lowercase, uppercase, digits, special characters, or all combined) and a length range (minimum and maximum).
    *   A function to perform a brute-force attack against MD5, SHA-256, or Bcrypt hashes by iterating through generated candidates.
3.  **Dictionary Attack Utilities (`dictionary_utils.py`):**
    *   A function to perform a dictionary attack against MD5, SHA-256, or Bcrypt hashes by comparing against words from a provided wordlist file.
4.  **Hybrid Cracker (`cracker.py`):**
    *   A central function that orchestrates a hybrid attack strategy: it first attempts a dictionary attack (if a wordlist is provided) and, if unsuccessful, falls back to a brute-force attack (if a character set is provided).
5.  **Command-Line Interface (CLI) (`cli_cracker.py`):**
    *   A user-friendly terminal interface using `argparse` for easy interaction.
    *   Allows users to specify target hashes, hash types, wordlist paths, brute-force character sets, and length ranges.
    *   Includes a mode to generate hashes for plaintext passwords.
    *   Features a dedicated test scenario for Bcrypt to demonstrate its functionality due to shell argument parsing complexities.
6.  **Unit Tests (`test_cracker.py`):**
    *   Comprehensive unit tests using Python's `unittest` framework to verify the correctness and functionality of all individual components (hashing, candidate generation, brute-force, dictionary, and hybrid cracking).

### How to use it?

The primary way to use the tool is via the `cli_cracker.py` script from your terminal:

**1. Generate a hash:**
To generate a hash for a plaintext password:
`python cli_cracker.py dummy_target_hash <hash_type> -g <plaintext_password>`
*   `<hash_type>`: `md5`, `sha256`, or `bcrypt`.
*   `<plaintext_password>`: The password you want to hash.
*   `dummy_target_hash`: A placeholder argument, as `target_hash` is a required positional argument by `argparse` even when generating.

_Example:_
`python cli_cracker.py dummy md5 -g mysecretpassword`
`python cli_cracker.py dummy bcrypt -g anothersecret`

**2. Crack a hash using a dictionary attack:**
`python cli_cracker.py <target_hash> <hash_type> -w <path_to_wordlist>`
*   `<target_hash>`: The hash you want to crack. **Important:** If cracking a Bcrypt hash, you might need to wrap the entire hash string in double quotes (e.g., `"$2b$..."`) in your shell to prevent interpretation of special characters.
*   `<hash_type>`: `md5`, `sha256`, or `bcrypt`.
*   `<path_to_wordlist>`: The path to your wordlist file (e.g., `wordlist.txt`).

_Example:_
`python cli_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 md5 -w wordlist.txt`
`python cli_cracker.py "$2b$12$..." bcrypt -w common_passwords.txt`

**3. Crack a hash using a brute-force attack:**
`python cli_cracker.py <target_hash> <hash_type> -c <charset> -min <min_length> -max <max_length>`
*   `<target_hash>`: The hash you want to crack. (Remember quoting for Bcrypt).
*   `<hash_type>`: `md5`, `sha256`, or `bcrypt`.
*   `<charset>`: Character set to use: `lower` (lowercase letters), `upper` (uppercase letters), `digits` (0-9), `special` (punctuation), or `all` (combination of common chars). Default is `lower`.
*   `<min_length>`: Minimum password length to try. Default is 1.
*   `<max_length>`: Maximum password length to try. Default is 4.

_Example:_
`python cli_cracker.py 0cc175b9c0f1b6a831c399e269772661 md5 -c lower -min 1 -max 1` (cracks 'a')
`python cli_cracker.py <bcrypt_hash> bcrypt -c lower -min 1 -max 2`

**4. Run the dedicated Bcrypt test scenario:**
`python cli_cracker.py --test_bcrypt_scenario`
This command runs a pre-configured test to demonstrate Bcrypt cracking without needing to manually handle the complex hash string in the command line.

### How fast is it?

The speed of the cracking process is highly dependent on several factors:

*   **Hashing Algorithm:**
    *   **MD5 and SHA-256:** These are cryptographic hash functions designed for speed. Attacks against these will be relatively fast, allowing for many attempts per second, especially for shorter passwords or smaller wordlists.
    *   **Bcrypt:** This algorithm is *intentionally designed to be slow* and computationally intensive (using a "work factor"). This is a security feature, making brute-force and dictionary attacks significantly slower and more resource-consuming. Attempting to crack a Bcrypt hash will take considerably longer than MD5 or SHA-256, even for very short passwords.
*   **Password Complexity:** Longer passwords, and those using a wider range of characters (e.g., `all` charset for brute-force), drastically increase the time required for brute-force attacks.
*   **Wordlist Size:** For dictionary attacks, speed is directly proportional to the size of the wordlist.
*   **System Resources:** The CPU power of the machine running the tool directly impacts how many hashes can be computed per second.

In summary, for MD5/SHA-256, it can be quite fast for simple cases. For Bcrypt, it will be much slower due to its design, which is a key educational takeaway about modern password security.

### Any other special features?

*   **Educational Focus:** The tool is explicitly built to demonstrate different password attack methodologies and the varying strengths of hashing algorithms. It provides a hands-on way to understand why certain hashing practices are considered secure and others are not.
*   **Modular Design:** The codebase is structured into logical modules (`hashing_utils`, `bruteforce_utils`, `dictionary_utils`, `cracker`), making it easy to understand, modify, and extend individual components.
*   **Clear Output:** The tool provides informative print statements during the cracking process, detailing which attack is being attempted, the parameters used, and whether a password was found or not.
*   **Testable Code:** The inclusion of comprehensive unit tests ensures reliability and serves as an example of good software engineering practices.
