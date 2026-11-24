
# Import Path to work with file paths and properties.
from pathlib import Path

# Import hashlib to calculate a file's SHA-256 hash.
import hashlib


def calculate_hash(file_path):
    """
    Calculate the SHA-256 hash of a file.

    SHA-256 produces a unique-looking 64-character
    hexadecimal fingerprint for the file's contents.
    """

    # Create a new SHA-256 hash object.
    sha256 = hashlib.sha256()

    # Open the file in binary mode so we can read its bytes.
    with open(file_path, "rb") as file:

        # Read the file in small chunks to save memory.
        for chunk in iter(lambda: file.read(4096), b""):

            # Update the hash using the current chunk.
            sha256.update(chunk)

    # Return the final hash as a hexadecimal string.
    return sha256.hexdigest()



def check_double_extension(file_path):
    """
    Check whether a file has a misleading double extension.

    Example: invoice.pdf.exe

    This may indicate that an executable file is
    attempting to appear as a document or image.
    """

    # Extract the filename from the provided path.
    file_name = Path(file_path).name.lower()

    # Extensions commonly associated with documents or images.
    document_extensions = [
        ".pdf", ".jpg", ".jpeg", ".png",
        ".doc", ".docx", ".txt"
    ]

    # Extensions commonly associated with executable files.
    executable_extensions = [
        ".exe", ".bat", ".cmd", ".scr", ".com"
    ]

    # Check whether the filename ends with an executable extension.
    for executable in executable_extensions:
        if file_name.endswith(executable):

            # Remove the final executable extension.
            remaining_name = file_name[:-len(executable)]

            # Check whether the remaining name ends with
            # a document or image extension.
            for document in document_extensions:
                if remaining_name.endswith(document):
                    return True

    # No misleading double extension was detected.
    return False


def check_hash_blocklist(file_hash):
    """
    Compare a file's SHA-256 hash with hashes stored
    in our local test blocklist.

    Returns True if a matching hash is found.
    """

    # Locate the blocklist beside scanner.py.
    blocklist_path = Path(__file__).resolve().parent / "hash_blocklist.txt"

    # Check whether the blocklist file exists.
    if not blocklist_path.is_file():
        print("Warning: Hash blocklist was not found.")
        return False

    # Open the blocklist and read its stored hashes.
    with open(blocklist_path, "r", encoding="utf-8") as file:

        # Remove extra spaces and convert hashes to lowercase.
        known_hashes = {
            line.strip().lower()
            for line in file
            if line.strip()
        }

    # Return True if the scanned hash matches a stored hash.
    return file_hash.lower() in known_hashes


def scan_file(file_path):
    """
    Analyze a file using static analysis.

    Collect file information, calculate its SHA-256
    hash, and check for misleading double extensions.
    """

    # Convert the user input into a file path.
    path = Path(file_path).expanduser()

    # Check whether the file exists.
    if not path.is_file():
        print("\nError: File does not exist.")
        return

    # Collect basic file information.
    file_name = path.name
    file_extension = path.suffix.lower()
    file_size = path.stat().st_size

    # Calculate the SHA-256 hash.
    file_hash = calculate_hash(path)

    # Check for a misleading double extension.
    double_extension = check_double_extension(path)
    hash_match = check_hash_blocklist(file_hash)

    # Display file information.
    print("\n========== FILE ANALYSIS ==========")
    print("File Name:", file_name)
    print("File Extension:", file_extension or "(none)")
    print("File Size:", file_size, "bytes")
    print("SHA-256 Hash:", file_hash)
    print("===================================")

    # Display detection results.
    print("\n========== DETECTION RESULTS ==========")

    
    # Display double extension detection results.
    if double_extension:
        print("Double Extension: DETECTED")
    else:
        print("Double Extension: Not detected")

    # Display hash blocklist detection results.
    if hash_match:
        print("Hash Blocklist: MATCH FOUND")
    else:
        print("Hash Blocklist: No match")

    # Flag the file if either detection rule is triggered.
    if double_extension or hash_match:
        print("Status: FLAGGED FOR REVIEW")

        # Explain which indicators triggered the warning.
        if double_extension:
            print("Reason: Misleading double extension.")

        if hash_match:
            print("Reason: SHA-256 hash matched test blocklist.")
    else:
        print("Status: No suspicious indicators found.")

    print("=======================================")

