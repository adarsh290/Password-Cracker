# bruteforce_utils.py

import itertools
import string
import hashlib
import os
import time
import multiprocessing
from hashing_utils import hash_md5, hash_sha256, hash_bcrypt, verify_bcrypt

def generate_candidates(charset, min_length, max_length):
    """
    Generates candidate passwords based on a given character set and length range.
    """
    for length in range(min_length, max_length + 1):
        for candidate_tuple in itertools.product(charset, repeat=length):
            yield "".join(candidate_tuple)

def _worker_bruteforce(target_hash, hash_type, task_queue, result_queue, found_event, attempts):
    """
    Worker function for multiprocessing brute-force.
    """
    while not found_event.is_set():
        try:
            password_candidate = task_queue.get(timeout=1)
            if password_candidate is None: # Sentinel value to stop worker
                break
            
            with attempts.get_lock(): # Safely increment shared counter
                attempts.value += 1

            if hash_type == 'bcrypt':
                if verify_bcrypt(password_candidate, target_hash):
                    result_queue.put(password_candidate)
                    found_event.set()
                    break
            elif hash_type == 'md5':
                if hash_md5(password_candidate) == target_hash:
                    result_queue.put(password_candidate)
                    found_event.set()
                    break
            elif hash_type == 'sha256':
                if hash_sha256(password_candidate) == target_hash:
                    result_queue.put(password_candidate)
                    found_event.set()
                    break
        except Exception:
            # Using a broad exception here to prevent worker death, 
            # but in a production environment, specific errors should be handled.
            continue

def bruteforce_crack(target_hash, hash_type, charset, min_length, max_length):
    """
    Attempts to crack a hash using a multi-processed brute-force approach.
    :param target_hash: The hash to crack.
    :param hash_type: 'md5', 'sha256', or 'bcrypt'.
    :param charset: The character set to use for generating candidates.
    :param min_length: Minimum length of passwords to try.
    :param max_length: Maximum length of passwords to try.
    :return: The cracked password if found, otherwise None.
    """
    print(f"Starting multi-core brute-force attack for hash: {target_hash} ({hash_type})")
    print(f"Character set: {charset}, Length: {min_length}-{max_length}")

    if hash_type not in ['md5', 'sha256', 'bcrypt']:
        print(f"Error: Unsupported hash type '{hash_type}'.")
        return None

    start_time = time.time()
    attempts = multiprocessing.Value('L', 0)
    task_queue = multiprocessing.Queue(maxsize=1000) # Limit queue size to prevent memory bloat
    result_queue = multiprocessing.Queue()
    found_event = multiprocessing.Event()

    num_processes = os.cpu_count() or 1
    processes = []

    # Start worker processes
    for _ in range(num_processes):
        p = multiprocessing.Process(target=_worker_bruteforce, 
                                    args=(target_hash, hash_type, task_queue, result_queue, found_event, attempts))
        processes.append(p)
        p.start()

    # Populate task queue
    candidate_generator = generate_candidates(charset, min_length, max_length)
    last_report_time = time.time()

    try:
        for candidate in candidate_generator:
            if found_event.is_set():
                break
            
            # Put candidate in queue, wait if full
            task_queue.put(candidate)

            # Periodic reporting
            current_time = time.time()
            if current_time - last_report_time > 2: # Report every 2 seconds
                elapsed_time = current_time - start_time
                current_attempts = attempts.value
                pps = current_attempts / elapsed_time if elapsed_time > 0 else 0
                print(f"Progress: {current_attempts} attempts - {pps:.2f} passwords/sec")
                last_report_time = current_time
    except StopIteration:
        pass

    # Send stop signal to workers
    for _ in range(num_processes):
        try:
            task_queue.put(None) # Use blocking put for stop signals
        except Exception:
            pass

    cracked_password = None
    # Wait for results or all processes to finish
    while any(p.is_alive() for p in processes) or not result_queue.empty():
        if found_event.is_set():
            try:
                cracked_password = result_queue.get(timeout=1)
            except multiprocessing.queues.Empty:
                pass
            break
        
        # Check if they all finished without finding it
        if all(not p.is_alive() for p in processes) and task_queue.empty() and result_queue.empty():
            break
        time.sleep(0.1)

    # Clean up processes
    for p in processes:
        if p.is_alive():
            p.terminate()
        p.join()

    end_time = time.time()
    elapsed_time = end_time - start_time
    total_attempts = attempts.value
    pps = total_attempts / elapsed_time if elapsed_time > 0 else 0

    if cracked_password:
        print(f"Crack successful! Password found: '{cracked_password}'")
        print(f"Statistics: {total_attempts} attempts in {elapsed_time:.2f}s ({pps:.2f} p/s)")
        return cracked_password
    
    print("Brute-force attack completed. Password not found.")
    print(f"Statistics: {total_attempts} attempts in {elapsed_time:.2f}s ({pps:.2f} p/s)")
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
