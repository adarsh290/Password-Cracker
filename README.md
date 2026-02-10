# Password Cracker Tool

This project implements a password cracking tool in Python with a terminal-based interface. It's designed for educational purposes to understand various password attack vectors and hashing mechanisms.

## Features

*   **Hashing Exploration:** Supports MD5, SHA-256, and bcrypt for hashing and verification, allowing for the study of different cryptographic hashing principles.
*   **Attack Methods:**
    *   **Dictionary Attack:** Attempts to crack passwords using a provided wordlist.
    *   **Brute-Force Attack:** Generates and tests passwords systematically based on a defined character set and length range.
    *   **Hybrid Attack:** Combines dictionary and brute-force methods for more comprehensive cracking attempts.
*   **PDF Cracking:** Includes specialized functionality to crack passwords protecting PDF files using dictionary, brute-force, and hybrid approaches.
*   **Terminal-Based Interface:** Easy-to-use command-line interface for all operations.
*   **Performance:** The brute-force method, especially for PDF cracking, utilizes multiprocessing for improved speed and provides periodic progress updates (passwords per second).

## How to Use

### General Password Cracking

To use the tool for general password cracking (e.g., against a known hash):

1.  **Generate a Hash (Example):**
    ```bash
    python cli_cracker.py --generate_hash --password mysecretpassword --hash_type bcrypt
    ```
    This will output a hash like: `$2b$12$................................................`

2.  **Crack a Hash using Dictionary Attack:**
    ```bash
    python cli_cracker.py --hash_to_crack "$2b$12$................................................" --hash_type bcrypt --attack_type dictionary --wordlist path/to/your/wordlist.txt
    ```

3.  **Crack a Hash using Brute-Force Attack:**
    ```bash
    python cli_cracker.py --hash_to_crack "$2b$12$................................................" --hash_type bcrypt --attack_type bruteforce --charset lower,digits --min_len 4 --max_len 6
    ```
    *   `--charset`: Can be `lower`, `upper`, `digits`, `special`, `all`, or a custom string (e.g., `abc`).
    *   `--min_len`, `--max_len`: Minimum and maximum length of passwords to try.

4.  **Crack a Hash using Hybrid Attack:**
    ```bash
    python cli_cracker.py --hash_to_crack "$2b$12$................................................" --hash_type bcrypt --attack_type hybrid --wordlist path/to/your/wordlist.txt --charset lower --min_len 1 --max_len 2
    ```

### PDF Cracking

The PDF cracking functionality supports dictionary, brute-force, and hybrid methods.

**To crack a PDF using a dictionary attack:**
```bash
python cli_cracker.py --pdf_file <path_to_pdf> --pdf_attack_type dictionary --pdf_wordlist <path_to_wordlist>
```

**To crack a PDF using a brute-force attack:**
```bash
python cli_cracker.py --pdf_file <path_to_pdf> --pdf_attack_type bruteforce --pdf_charset <charset> --pdf_min_len <min_length> --pdf_max_len <max_length>
```
**To crack a PDF using a hybrid attack (dictionary then brute-force):**
```bash
python cli_cracker.py --pdf_file <path_to_pdf> --pdf_attack_type hybrid --pdf_wordlist <path_to_wordlist> --pdf_charset <charset> --pdf_min_len <min_length> --pdf_max_len <max_length>
```
For `<charset>`, you can use predefined options like `lower`, `upper`, `digits`, `special`, `all`, or provide a custom string of characters (e.g., `abc`).

The brute-force method now utilizes multiprocessing to leverage multiple CPU cores, which should significantly improve its speed. It also reports the number of passwords attempted and the passwords per second with periodic updates during the process.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/password_cracker.git
    cd password_cracker
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Tips for Shorter Commands

When working with long commands, especially for PDF cracking with many parameters, you can use environment variables or shell functions/aliases to make them more concise and easier to reuse.

### 1. Using Environment Variables

Store frequently used paths or values in environment variables.

**For Windows (Command Prompt):**
```cmd
set PDF_FILE="C:\Users\Adarsh Singh\Downloads\Clue_protected.pdf"
python cli_cracker.py --pdf_file %PDF_FILE% --pdf_attack_type hybrid --pdf_wordlist wordlist.txt --pdf_charset all --pdf_min_len 1 --pdf_max_len 14
```

**For Windows (PowerShell):**
```powershell
$env:PDF_FILE="C:\Users\Adarsh Singh\Downloads\Clue_protected.pdf"
python cli_cracker.py --pdf_file $env:PDF_FILE --pdf_attack_type hybrid --pdf_wordlist wordlist.txt --pdf_charset all --pdf_min_len 1 --pdf_max_len 14
```

**For Linux/macOS (Bash/Zsh):**
```bash
export PDF_FILE="/home/Adarsh Singh/Downloads/Clue_protected.pdf" # Adjust path for your system
python cli_cracker.py --pdf_file "$PDF_FILE" --pdf_attack_type hybrid --pdf_wordlist wordlist.txt --pdf_charset all --pdf_min_len 1 --pdf_max_len 14
```

### 2. Using Shell Aliases or Functions (Recommended for Flexibility)

Shell functions are highly recommended as they allow you to pass arguments and define default values, offering great flexibility. You can add these to your shell's configuration file (e.g., `~/.bashrc`, `~/.zshrc` for Linux/macOS, or your PowerShell `$PROFILE` for Windows) to make them permanent.

**For Windows (PowerShell Function):**
Add this to your PowerShell profile (`$PROFILE`):
```powershell
function Invoke-PdfCrackHybrid {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PdfFile,
        [string]$Wordlist = "wordlist.txt",
        [string]$Charset = "all",
        [int]$MinLen = 1,
        [int]$MaxLen = 14
    )
    python cli_cracker.py --pdf_file $PdfFile --pdf_attack_type hybrid --pdf_wordlist $Wordlist --pdf_charset $Charset --pdf_min_len $MinLen --pdf_max_len $MaxLen
}
```
Usage:
```powershell
Invoke-PdfCrackHybrid -PdfFile "C:\Users\Adarsh Singh\Downloads\Clue_protected.pdf"
# Or with custom arguments:
Invoke-PdfCrackHybrid -PdfFile "C:\Users\Adarsh Singh\Downloads\Clue_protected.pdf" -MinLen 5 -MaxLen 10 -Charset "lower,digits"
```

**For Linux/macOS (Bash/Zsh Function):**
Add this to your `~/.bashrc` or `~/.zshrc`:
```bash
crackpdf_hybrid() {
    PDF_FILE="${1:-C:\Users\Adarsh Singh\Downloads\Clue_protected.pdf}" # Default if not provided
    WORDLIST="${2:-wordlist.txt}"
    CHARSET="${3:-all}"
    MIN_LEN="${4:-1}"
    MAX_LEN="${5:-14}"
    python cli_cracker.py --pdf_file "$PDF_FILE" --pdf_attack_type hybrid --pdf_wordlist "$WORDLIST" --pdf_charset "$CHARSET" --pdf_min_len "$MIN_LEN" --pdf_max_len "$MAX_LEN"
}
```
Usage:
```bash
crackpdf_hybrid # Uses all defaults
# Or with custom arguments (order matters here):
crackpdf_hybrid "path/to/another.pdf" "my_custom_wordlist.txt" "lower" 5 8
```