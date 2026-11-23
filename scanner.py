
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


def scan_file(file_path):
    """
    Read basic file information and calculate its hash.
    This function does not execute the file.
    """

    # Convert the input path into a Path object.
    path = Path(file_path).expanduser()

    # Check whether the path points to an existing file.
    if not path.is_file():
        print("\nError: File does not exist or is not a regular file.")
        return

    # Get the file's name and extension.
    file_name = path.name
    file_extension = path.suffix.lower()

    # Get the file size in bytes.
    file_size = path.stat().st_size

    # Calculate the file's SHA-256 hash.
    file_hash = calculate_hash(path)

    # Display the collected file information.
    print("\n========== FILE ANALYSIS ==========")
    print("File Name:", file_name)
    print("File Extension:", file_extension or "(none)")
    print("File Size:", file_size, "bytes")
    print("SHA-256 Hash:", file_hash)
    print("===================================")

    # This phase only collects information.
    # Detection rules will be added in Phase 3.
    print("Status: Basic file analysis completed.")
