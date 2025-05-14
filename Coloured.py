import os
import hashlib
import json
from colorama import Fore, Style, init

init(autoreset=True)   # initialize colorama

#function to compute the SHA-256 hash of a file
def compute_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

#function to generate file hashes for all files in a directory
def generate_hashes(directory):
    hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            hashes[file_path] = compute_hash(file_path)
    return hashes

#function to save hashes to a JSON file
def save_hashes(hashes, hash_file="hashes.json"):
    with open(hash_file, "w") as f:
        json.dump(hashes, f, indent=4)

#function to load stored hashes from a JSON file
def load_hashes(hash_file="hashes.json"):
    try:
        with open(hash_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

#function to check integrity
def check_integrity(directory, hash_file="hashes.json"):
    stored_hashes = load_hashes(hash_file)
    current_hashes = generate_hashes(directory)

    modified_files = []
    deleted_files = []
    new_files = []

    #check for modified and deleted files
    for file, old_hash in stored_hashes.items():
        if file not in current_hashes:
            deleted_files.append(file)
        elif current_hashes[file] != old_hash:
            modified_files.append(file)

    #check for new files
    for file in current_hashes:
        if file not in stored_hashes:
            new_files.append(file)

    return modified_files, deleted_files, new_files

#main function
def main():
    directory = input("Enter directory path to monitor: ")

    choice = input("1: Generate Hashes\n2: Check Integrity\nChoose an option: ")

    if choice == "1":
        hashes = generate_hashes(directory)
        save_hashes(hashes)
        print(Fore.GREEN + "✅ Hashes generated and saved.")
    elif choice == "2":
        modified, deleted, new = check_integrity(directory)
        if not (modified or deleted or new):
            print(Fore.GREEN + "🟢 No integrity issues detected.")
        else:
            if modified:
                print(Fore.RED + "🔴 Modified files:")
                for file in modified:
                    print(Fore.RED + f" - {file}")
            if deleted:
                print(Fore.YELLOW + "🟡 Deleted files:")
                for file in deleted:
                    print(Fore.YELLOW + f" - {file}")
            if new:
                print(Fore.CYAN + "🔵 New files detected:")
                for file in new:
                    print(Fore.CYAN + f" - {file}")
    else:
        print(Fore.RED + "❌ Invalid option.")

if __name__ == "__main__":
    main()
