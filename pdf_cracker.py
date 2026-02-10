import os
import pikepdf
import itertools
import time
import multiprocessing # Import for generating brute-force combinations

def crack_pdf_dictionary(pdf_path: str, wordlist_path: str) -> str | None:
    """
    Attempts to crack a PDF password using a dictionary attack.

    Args:
        pdf_path: The path to the password-protected PDF file.
        wordlist_path: The path to the wordlist file.

    Returns:
        The cracked password if found, otherwise None.
    """
    if not os.path.exists(pdf_path):
        print(f"Error: PDF file not found at {pdf_path}")
        return None
    if not os.path.exists(wordlist_path):
        print(f"Error: Wordlist file not found at {wordlist_path}")
        return None

    print(f"Attempting dictionary attack on {pdf_path} with wordlist {wordlist_path}...")
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                try:
                    with pikepdf.open(pdf_path, password=password) as pdf:
                        print(f"Password found: {password}")
                        return password
                except pikepdf.PasswordError:
                    # Incorrect password, continue to next
                    pass
                except Exception as e:
                    print(f"An error occurred while trying password '{password}': {e}")
        print("Dictionary attack finished. Password not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during dictionary attack: {e}")
        return None

def generate_bruteforce_candidates(chars: str, min_len: int, max_len: int):
    """
    Generates candidate passwords for brute-force attack.

    Args:
        chars: The characters set to use for brute-force.
        min_len: Minimum length of the password.
        max_len: Maximum length of the password.
    """
    for length in range(min_len, max_len + 1):
        for candidate_tuple in itertools.product(chars, repeat=length):
            yield "".join(candidate_tuple)

def _worker_crack_pdf(pdf_path: str, task_queue: multiprocessing.Queue, result_queue: multiprocessing.Queue, found_event: multiprocessing.Event, attempts: multiprocessing.Value):
    """
    Worker function for multiprocessing PDF brute-force.
    Each worker attempts to crack the PDF with passwords from the task_queue.
    """
    while not found_event.is_set():
        try:
            password_candidate = task_queue.get(timeout=1) # Get with timeout to check event periodically
            if password_candidate is None: # Sentinel value to stop worker
                break
            
            with attempts.get_lock(): # Safely increment shared counter
                attempts.value += 1

            try:
                with pikepdf.open(pdf_path, password=password_candidate) as pdf:
                    result_queue.put(password_candidate)
                    found_event.set() # Signal that password is found
                    break
            except pikepdf.PasswordError:
                pass # Incorrect password, continue
            except Exception as e:
                # Log error, but don't stop other processes
                print(f"Worker error for password '{password_candidate}': {e}")
        except multiprocessing.queues.Empty:
            continue # Task queue is empty, check event again

def crack_pdf_bruteforce(pdf_path: str, chars: str, min_len: int, max_len: int) -> str | None:
    """
    Attempts to crack a PDF password using a brute-force attack with multiprocessing.

    Args:
        pdf_path: The path to the password-protected PDF file.
        chars: The characters set to use for brute-force.
        min_len: Minimum length of the password.
        max_len: Maximum length of the password.

    Returns:
        The cracked password if found, otherwise None.
    """
    if not os.path.exists(pdf_path):
        print(f"Error: PDF file not found at {pdf_path}")
        return None

    print(f"Attempting brute-force attack on {pdf_path} with chars '{chars}' (min_len={min_len}, max_len={max_len})...")
    
    start_time = time.time()
    attempts = multiprocessing.Value('L', 0) # Shared counter for attempts
    
    # Queues for inter-process communication
    task_queue = multiprocessing.Queue()
    result_queue = multiprocessing.Queue()
    found_event = multiprocessing.Event() # Event to signal when password is found

    num_processes = os.cpu_count() or 1
    processes = []

    # Start worker processes
    for _ in range(num_processes):
        p = multiprocessing.Process(target=_worker_crack_pdf, args=(pdf_path, task_queue, result_queue, found_event, attempts)) # Pass attempts
        processes.append(p)
        p.start()
    
    # Populate the task queue with password candidates and report progress
    last_report_time = time.time()
    candidate_generator = generate_bruteforce_candidates(chars, min_len, max_len)

    while not found_event.is_set():
        try:
            password_candidate = next(candidate_generator)
            task_queue.put(password_candidate, timeout=0.01) # Small timeout to avoid blocking indefinitely
        except StopIteration:
            break # No more candidates to generate
        except multiprocessing.queues.Full:
            # Queue is full, wait a bit and retry, or check results
            time.sleep(0.1)
            continue
        
        # Periodic reporting
        current_time = time.time()
        if current_time - last_report_time > 1: # Report every 1 second
            elapsed_time = current_time - start_time
            current_attempts = attempts.value
            pps = current_attempts / elapsed_time if elapsed_time > 0 else 0
            print(f"Progress: {current_attempts} attempts in {elapsed_time:.2f} seconds ({pps:.2f} passwords/sec) - {task_queue.qsize()} in queue")
            last_report_time = current_time

    # Put sentinel values to stop worker processes
    for _ in range(num_processes):
        task_queue.put(None)

    cracked_password = None
    # Wait for results or all processes to finish
    while any(p.is_alive() for p in processes) or not result_queue.empty():
        if found_event.is_set():
            cracked_password = result_queue.get()
            break
        try:
            # Check result queue with a small timeout
            cracked_password = result_queue.get(timeout=0.1)
            break
        except multiprocessing.queues.Empty:
            continue
    
    # Terminate all processes
    for p in processes:
        p.terminate()
        p.join() # Ensure processes are cleanly shut down

    end_time = time.time()
    elapsed_time = end_time - start_time
    total_attempts = attempts.value
    pps = total_attempts / elapsed_time if elapsed_time > 0 else 0

    if cracked_password:
        print(f"Password found: {cracked_password}")
        print(f"Brute-force statistics: {total_attempts} attempts in {elapsed_time:.2f} seconds ({pps:.2f} passwords/sec)")
        return cracked_password
    else:
        print("Brute-force attack finished. Password not found.")
        print(f"Brute-force statistics: {total_attempts} attempts in {elapsed_time:.2f} seconds ({pps:.2f} passwords/sec)")
        return None

def crack_pdf_hybrid(pdf_path: str, wordlist_path: str, chars: str, min_len: int, max_len: int) -> str | None:
    """
    Attempts to crack a PDF password using a hybrid approach (dictionary then brute-force).

    Args:
        pdf_path: The path to the password-protected PDF file.
        wordlist_path: The path to the wordlist file for the dictionary attack.
        chars: The characters set to use for brute-force.
        min_len: Minimum length of the password for brute-force.
        max_len: Maximum length of the password for brute-force.

    Returns:
        The cracked password if found, otherwise None.
    """
    print(f"Attempting hybrid attack on {pdf_path}...")

    # 1. Try dictionary attack first
    if wordlist_path and os.path.exists(wordlist_path):
        cracked_password = crack_pdf_dictionary(pdf_path, wordlist_path)
        if cracked_password:
            print("Hybrid attack: Password found via dictionary attack.")
            return cracked_password
        else:
            print("Hybrid attack: Dictionary attack failed, proceeding to brute-force.")
    else:
        print("Hybrid attack: No valid wordlist provided or found, skipping dictionary attack and proceeding to brute-force.")

    # 2. If dictionary attack fails or is skipped, try brute-force attack
    cracked_password = crack_pdf_bruteforce(pdf_path, chars, min_len, max_len)
    if cracked_password:
        print("Hybrid attack: Password found via brute-force attack.")
        return cracked_password
    else:
        print("Hybrid attack: Brute-force attack also failed. Password not found.")
        return None

if __name__ == "__main__":
    # Create dummy password-protected PDF for testing
    dummy_pdf_path = "test_protected.pdf"
    dummy_wordlist_path = "test_pdf_wordlist.txt"
    correct_password = "testpassword"

    # --- CLI Brute-force test specific files ---
    test_bruteforce_cli_password = "zZz" # Changed from "zZ"
    test_bruteforce_cli_pdf_path = "test_protected_cli_bf.pdf"
    # --- End CLI Brute-force test specific files ---

    # Create a dummy protected PDF using pikepdf for testing
    from pikepdf import Pdf, Encryption
    try:
        # Create a simple, unprotected PDF
        with Pdf.new() as pdf:
            pdf.add_blank_page()
            pdf.save("unprotected.pdf")
        
        # Protect it with a password
        with Pdf.open("unprotected.pdf") as pdf:
            no_permissions = Encryption(
                owner="ownerpass", allow=pikepdf.Permissions(extract=False, print_lowres=False, print_highres=False),
                user=correct_password
            )
            pdf.save(dummy_pdf_path, encryption=no_permissions)
        print(f"Created dummy protected PDF: {dummy_pdf_path} with password '{correct_password}'")
        os.remove("unprotected.pdf")
    except Exception as e:
        print(f"Could not create dummy PDF for testing: {e}")
        print("Skipping PDF cracking tests.")
        # Removed exit() to allow other dummy files to be created

    # --- Create CLI brute-force test PDF ---
    try:
        with Pdf.new() as pdf:
            pdf.add_blank_page()
            pdf.save("unprotected_cli_bf.pdf")
        
        with Pdf.open("unprotected_cli_bf.pdf") as pdf:
            no_permissions = Encryption(
                owner="ownerpass", allow=pikepdf.Permissions(extract=False, print_lowres=False, print_highres=False),
                user=test_bruteforce_cli_password
            )
            pdf.save(test_bruteforce_cli_pdf_path, encryption=no_permissions)
        print(f"Created dummy protected PDF for CLI brute-force test: {test_bruteforce_cli_pdf_path} with password '{test_bruteforce_cli_password}'")
        os.remove("unprotected_cli_bf.pdf")
    except Exception as e:
        print(f"Could not create dummy CLI BF PDF for testing: {e}")
        print("Skipping CLI brute-force PDF creation.")
    # --- End Create CLI brute-force test PDF ---
        
    # Create a dummy wordlist
    with open(dummy_wordlist_path, 'w') as f:
        f.write("wrongpass\n")
        f.write(f"{correct_password}\n")
        f.write("anotherwrong\n")
    print(f"Created dummy wordlist: {dummy_wordlist_path}")

    print("\n--- Testing crack_pdf_dictionary ---")
    found_dict_pass = crack_pdf_dictionary(dummy_pdf_path, dummy_wordlist_path)
    if found_dict_pass == correct_password:
        print("Dictionary test PASSED.")
    else:
        print("Dictionary test FAILED.")

    print("\n--- Testing crack_pdf_bruteforce ---")
    quick_brute_force_password = "ab"
    dummy_bf_pdf_path = "test_protected_bf.pdf"
    try:
        with Pdf.new() as pdf:
            pdf.add_blank_page()
            pdf.save("unprotected_bf.pdf")
        
        with Pdf.open("unprotected_bf.pdf") as pdf:
            no_permissions = Encryption(
                owner="ownerpass", allow=pikepdf.Permissions(extract=False, print_lowres=False, print_highres=False),
                user=quick_brute_force_password
            )
            pdf.save(dummy_bf_pdf_path, encryption=no_permissions)
        print(f"Created dummy protected PDF for brute-force: {dummy_bf_pdf_path} with password '{quick_brute_force_password}'")
        os.remove("unprotected_bf.pdf")
    except Exception as e:
        print(f"Could not create dummy BF PDF for testing: {e}")
        print("Skipping PDF brute-force tests.")
        dummy_bf_pdf_path = None
    
    if dummy_bf_pdf_path:
        chars_for_bf = "ab"
        min_len_bf = 2
        max_len_bf = 2
        
        found_bf_pass = crack_pdf_bruteforce(dummy_bf_pdf_path, chars_for_bf, min_len_bf, max_len_bf)
        if found_bf_pass == quick_brute_force_password:
            print("Brute-force test PASSED.")
        else:
            print("Brute-force test FAILED.")
    else:
        print("Brute-force test skipped due to setup failure.")

    # Clean up dummy files
    # if os.path.exists(dummy_pdf_path):
    #     os.remove(dummy_pdf_path)
    # if os.path.exists(dummy_wordlist_path):
    #     os.remove(dummy_wordlist_path)
    # if dummy_bf_pdf_path and os.path.exists(dummy_bf_pdf_path):
    #     os.remove(dummy_bf_pdf_path)
    # print("\nCleaned up dummy files.")