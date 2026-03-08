"""GPU‑accelerated password cracking wrapper using hashcat.

This module provides a very thin wrapper around the external `hashcat` binary.
It is only used when the user passes the ``--use_gpu`` flag and the hash
algorithm is MD5 or SHA‑256 (these are the only algorithms that hashcat
accelerates well).  Bcrypt and PDF cracking are *not* supported on the GPU
path because they are memory‑hard and would not see a speed‑up.

The helper functions construct the appropriate hashcat command line and
run it via ``subprocess.run``.  If ``hashcat`` is not installed or the
required mode is unavailable, a ``RuntimeError`` is raised and the caller
can fall back to the pure‑CPU implementation.
"""

import os
import shutil
import subprocess
from typing import Optional

# Mapping from our hash type string to hashcat mode numbers
_HASHCAT_MODE = {
    "md5": "0",
    "sha256": "1400",
}

# Mapping from charset keywords to hashcat mask symbols
_CHARSET_MAP = {
    "lower": "?l",
    "upper": "?u",
    "digits": "?d",
    "special": "?s",
    "all": "?a",
}

def _ensure_hashcat() -> str:
    """Return the path to the ``hashcat`` executable or raise.

    ``hashcat`` must be on the system ``PATH``.  This helper is separated so
    that the calling code can give a clear error message.
    """
    exe = shutil.which("hashcat")
    if not exe:
        raise RuntimeError("hashcat executable not found in PATH. Install hashcat to use GPU acceleration.")
    return exe

def _build_bruteforce_mask(charset: str) -> str:
    """Convert a comma‑separated charset list to a hashcat mask.

    Example: ``"lower,upper,digits"`` → ``"?l?u?d"``
    If the list contains ``all`` we simply return ``?a`` because that already
    includes the full character set.
    """
    parts = [c.strip() for c in charset.split(",") if c.strip()]
    if "all" in parts:
        return "?a"
    mask = "".join(_CHARSET_MAP.get(p, p) for p in parts)
    if not mask:
        raise ValueError(f"Unrecognised charset specification: '{charset}'")
    return mask

def gpu_dictionary_crack(target_hash: str, hash_type: str, wordlist_path: str) -> Optional[str]:
    """Attempt a dictionary attack using hashcat on the GPU.

    Returns the cracked password string on success, or ``None`` if the
    password is not found.
    """
    if hash_type not in _HASHCAT_MODE:
        raise ValueError(f"GPU support only available for MD5 and SHA‑256, not '{hash_type}'.")
    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")

    hashcat = _ensure_hashcat()
    mode = _HASHCAT_MODE[hash_type]
    # Hashcat expects hash input via a file or stdin; we use the -m option with -a 0 (dictionary)
    cmd = [hashcat, "-m", mode, "-a", "0", "--quiet", "--remove", "--outfile-format", "2", "--outfile", "-", "--", target_hash, wordlist_path]
    # ``--quiet`` suppresses progress output; ``--outfile -`` prints cracked password to stdout.
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0 and result.stdout:
        # hashcat outputs "hash:plain"; we split on ':' and take the plain part.
        return result.stdout.strip().split(":", 1)[1]
    return None

def gpu_bruteforce_crack(
    target_hash: str,
    hash_type: str,
    charset: str,
    min_len: int,
    max_len: int,
) -> Optional[str]:
    """Brute‑force crack using hashcat.

    ``charset`` is a comma‑separated list like ``"lower,upper,digits"``.
    ``min_len``/``max_len`` control the incremental length range.
    """
    if hash_type not in _HASHCAT_MODE:
        raise ValueError(f"GPU support only available for MD5 and SHA‑256, not '{hash_type}'.")
    hashcat = _ensure_hashcat()
    mode = _HASHCAT_MODE[hash_type]
    mask = _build_bruteforce_mask(charset)
    # Use incremental mode (-i) with the given length bounds.
    cmd = [
        hashcat,
        "-m", mode,
        "-a", "3",  # brute‑force
        "-i",
        f"--increment-min={min_len}",
        f"--increment-max={max_len}",
        "--quiet",
        "--remove",
        "--outfile-format", "2",
        "--outfile", "-",
        "--", target_hash,
        mask,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0 and result.stdout:
        return result.stdout.strip().split(":", 1)[1]
    return None

# The module deliberately contains **no** fallback to CPU code; the caller should
# catch RuntimeError/ValueError and decide whether to use the regular multiprocessing
# implementation.
