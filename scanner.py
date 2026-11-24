
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
    content_matches = check_suspicious_content(path)

    # Display file information.
    print("\n--------------------------- FILE ANALYSIS -----------------------")
    print("File Name:", file_name)
    print("File Extension:", file_extension or "(none)")
    print("File Size:", file_size, "bytes")
    print("SHA-256 Hash:", file_hash)
    print("----------------------------------------------------------------")

    # Display detection results.
    
    # Display the detection results.
    print("\n---------------------------- DETECTION RESULTS -------------------------------")

    # Check for misleading double extensions.
    if double_extension:
        print("Double Extension: DETECTED")
    else:
        print("Double Extension: Not detected")

    # Check for a SHA-256 blocklist match.
    if hash_match:
        print("Hash Blocklist: MATCH FOUND")
    else:
        print("Hash Blocklist: No match")

    # Display suspicious content indicators.
    if content_matches:
        print("Suspicious Content: DETECTED")

        # Display each matching indicator.
        for indicator in content_matches:
            print(" -", indicator)
    else:
        print("Suspicious Content: Not detected")

    # Flag the file if at least one rule is triggered.
    if double_extension or hash_match or content_matches:
        print("\nStatus: FLAGGED FOR REVIEW")

        # Explain why the file was flagged.
        if double_extension:
            print("Reason: Misleading double extension.")

        if hash_match:
            print("Reason: SHA-256 hash matched test blocklist.")

        if content_matches:
            print("Reason: Suspicious test indicators found.")
    else:
        print("\nStatus: No suspicious indicators found.")

    print("------------------------------------------------------------")



def check_suspicious_content(file_path):
    """
    Search a file for predefined suspicious test indicators.

    This function reads file contents without executing them.

    Returns a list of indicators found in the file.
    """

    # Define harmless indicators for our controlled experiment.
    suspicious_indicators = [
        "SIMULATED_CREDENTIAL_ACCESS",
        "SIMULATED_REMOTE_CONTROL",
        "SIMULATED_DATA_EXFILTRATION",
        "SIMULATED_PAYLOAD_DOWNLOAD"
    ]

    # Store any indicators detected in the file.
    detected_indicators = []

    # Open the file in binary mode.
    with open(file_path, "rb") as file:

        # Read the contents of the file.
        file_content = file.read()

    # Check each indicator against the file contents.
    for indicator in suspicious_indicators:

        # Convert the indicator to bytes before comparison.
        indicator_bytes = indicator.encode("utf-8")

        # Check whether the indicator appears in the file.
        if indicator_bytes in file_content:
            detected_indicators.append(indicator)

    # Return the list of detected indicators.
    return detected_indicators
