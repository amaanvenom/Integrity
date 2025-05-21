import os
import hashlib
import json
from colorama import Fore, Style, init

#initialize colorama for colored terminal output
init(autoreset=True)

#this function returns the SHA-256 hash of a file 
def compute_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None  #in case the file doesn't exist

#creates a dictionary of file paths and their hashes
def generate_hashes(directory):
    hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            hashes[file_path] = compute_hash(file_path)
    return hashes

#saves hashes into a JSON file
def save_hashes(hashes, hash_file="hashes.json"):
    with open(hash_file, "w") as f:
        json.dump(hashes, f, indent=4)

#loads existing hashes from JSON (if available)
def load_hashes(hash_file="hashes.json"):
    try:
        with open(hash_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}  # No hashes yet

#checks for modified, deleted, and new files
def check_integrity(directory, hash_file="hashes.json"):
    stored_hashes = load_hashes(hash_file)
    curr_hashes = generate_hashes(directory)

    modified_files = []
    deleted_files = []
    new_files = []

    for file, old_hash in stored_hashes.items():
        if file not in curr_hashes:
            deleted_files.append(file)
        elif curr_hashes[file] != old_hash:
            modified_files.append(file)

    for file in curr_hashes:
        if file not in stored_hashes:
            new_files.append(file)

    # print("Debug:", modified_files, deleted_files, new_files)  # Just for testing
    return modified_files, deleted_files, new_files

#main interaction function
def main():
    directory = input("📁 Enter directory path to monitor: ").strip()

    choice = input("\n1️⃣  Generate Hashes\n2️⃣  Check Integrity\nChoose an option (1 or 2): ").strip()

    if choice == "1":
        hashes = generate_hashes(directory)
        save_hashes(hashes)
        print(Fore.GREEN + "✅ Hashes generated and saved successfully.")

    elif choice == "2":
        modified, deleted, new = check_integrity(directory)
        if not (modified or deleted or new):
            print(Fore.GREEN + "🟢 No integrity issues detected.")
        else:
            if modified:
                print(Fore.RED + "\n🔴 Modified files:")
                for file in modified:
                    print(Fore.RED + f" - {file}")
            if deleted:
                print(Fore.YELLOW + "\n🟡 Deleted files:")
                for file in deleted:
                    print(Fore.YELLOW + f" - {file}")
            if new:
                print(Fore.CYAN + "\n🔵 New files detected:")
                for file in new:
                    print(Fore.CYAN + f" - {file}")
    else:
        print(Fore.RED + "❌ Invalid option selected. Please choose 1 or 2.")

# Only runs if script is executed directly
if __name__ == "__main__":
    main()
