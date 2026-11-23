
# Import the scanning function from scanner.py.
from scanner import scan_file


def main():
    """
    Main function for the Trojan Horse Detection prototype.
    It accepts a file path and starts static file analysis.
    """

    # Display the program title and version.
    print("================================")
    print("   Trojan Horse Detection Tool")
    print("================================")
    print("Version 1.0")
    print("Static File Analysis Prototype")
    print()

    # Ask the user to enter the path of the file to scan.
    file_path = input("Enter file path to scan: ").strip()

    # Check whether the user entered a file path.
    if not file_path:
        print("Error: No file path provided.")
        return

    # Send the file path to scanner.py for analysis.
    scan_file(file_path)


# Run main() only when this file is executed directly.
if __name__ == "__main__":
    main()
