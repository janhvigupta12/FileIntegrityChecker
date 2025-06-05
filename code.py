import os
import hashlib
import json
import argparse

def calculate_file_hash(filepath, hash_algo='sha256', block_size=65536):
    hash_func = hashlib.new(hash_algo)
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(block_size):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        return None
    except PermissionError:
        print(f"Permission denied: {filepath}")
        return None

def scan_files(paths):
    file_hashes = {}
    for path in paths:
        if os.path.isfile(path):
            hash_val = calculate_file_hash(path)
            if hash_val:
                file_hashes[path] = hash_val
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    hash_val = calculate_file_hash(full_path)
                    if hash_val:
                        file_hashes[full_path] = hash_val
        else:
            print(f"Warning: '{path}' is neither a file nor a directory.")
    return file_hashes

def save_hashes(hash_dict, hashfile):
    with open(hashfile, 'w') as f:
        json.dump(hash_dict, f, indent=2)

def load_hashes(hashfile):
    try:
        with open(hashfile, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Error: Unable to load hash file '{hashfile}'.")
        return {}

def check_integrity(stored_hashes, current_hashes):
    all_files = set(stored_hashes.keys()) | set(current_hashes.keys())
    report = {}
    for file in all_files:
        stored_hash = stored_hashes.get(file)
        current_hash = current_hashes.get(file)
        if stored_hash and current_hash:
            if stored_hash == current_hash:
                report[file] = 'UNCHANGED'
            else:
                report[file] = 'CHANGED'
        elif stored_hash and not current_hash:
            report[file] = 'MISSING'
        elif not stored_hash and current_hash:
            report[file] = 'NEW'
    return report

def main():
    parser = argparse.ArgumentParser(description="File Integrity Checker using hashes.")
    parser.add_argument('mode', choices=['init', 'check'],
                        help="Mode 'init' to create baseline hashes. 'check' to check integrity against saved hashes.")
    parser.add_argument('paths', nargs='+',
                        help="Files or directories to scan.")
    parser.add_argument('--hashfile', default='file_hashes.json',
                        help="JSON file to save/load hashes (default: file_hashes.json).")

    args = parser.parse_args()

    if args.mode == 'init':
        print("Initializing hashes...")
        hashes = scan_files(args.paths)
        save_hashes(hashes, args.hashfile)
        print(f"Hashes saved to {args.hashfile}. Total files hashed: {len(hashes)}")
    elif args.mode == 'check':
        print("Checking file integrity...")
        stored_hashes = load_hashes(args.hashfile)
        if not stored_hashes:
            print("Stored hash file empty or not found. Run in 'init' mode first.")
            return
        current_hashes = scan_files(args.paths)
        report = check_integrity(stored_hashes, current_hashes)
        unchanged = sum(1 for r in report.values() if r == 'UNCHANGED')
        changed = sum(1 for r in report.values() if r == 'CHANGED')
        missing = sum(1 for r in report.values() if r == 'MISSING')
        new_files = sum(1 for r in report.values() if r == 'NEW')

        for file, status in sorted(report.items()):
            print(f"{status}: {file}")

        print(f"\nSummary:")
        print(f"Unchanged files: {unchanged}")
        print(f"Changed files: {changed}")
        print(f"Missing files: {missing}")
        print(f"New files: {new_files}")

if __name__ == '__main__':
    main()

