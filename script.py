import hashlib
import os
import sys
from datetime import datetime
import subprocess
import pefile  # Ensure this library is installed

def calculate_hashes(file_path):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
    except IOError as e:
        print(f"Error opening or reading the file: {e}")
        return None, None

    return md5_hash.hexdigest(), sha256_hash.hexdigest()

def get_file_size(file_path):
    size_bytes = os.path.getsize(file_path)
    size_kilobytes = size_bytes / 1024
    return size_kilobytes, size_bytes

def list_dlls_and_apis(file_path):
    try:
        pe = pefile.PE(file_path)
        dll_api_mapping = {}

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            apis = [imp.name.decode('utf-8') if imp.name else 'UNKNOWN' for imp in entry.imports]
            dll_api_mapping[dll_name] = apis

        return dll_api_mapping
    except Exception as e:
        print(f"Error analyzing PE file: {e}")
        return None

def get_file_info(file_path):
    if not os.path.exists(file_path):
        print("The specified file does not exist.")
        return None

    file_info = {}
    md5, sha256 = calculate_hashes(file_path)
    if md5 is None or sha256 is None:
        return None

    file_info["MD5"] = md5
    file_info["SHA256"] = sha256

    size_ko, size_bytes = get_file_size(file_path)
    file_info["Size (KB)"] = size_ko
    file_info["Size (Bytes)"] = size_bytes

    creation_time = os.path.getctime(file_path)
    file_info["Creation Date"] = datetime.fromtimestamp(creation_time).strftime("%d/%m/%Y %H:%M:%S")

    try:
        file_type = subprocess.check_output(["file", "--brief", file_path], universal_newlines=True)
        file_info["File Type"] = file_type.strip()
        if "MS Windows" in file_type:
            dll_api_mapping = list_dlls_and_apis(file_path)
            if dll_api_mapping is not None:
                file_info["DLLs with APIs"] = dll_api_mapping
    except subprocess.CalledProcessError:
        file_info["File Type"] = "N/A"

    return file_info

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py filename")
        sys.exit(1)

    file_path = sys.argv[1]
    file_info = get_file_info(file_path)

    if file_info:
        for key, value in file_info.items():
            if key == "DLLs with APIs":
                print(f"{key}:")
                for dll, apis in value.items():
                    print(f"  {dll}:")
                    for api in apis:
                        print(f"    {api}")
            else:
                print(f"{key}: {value}")
    else:
        print("Unable to retrieve file information.")
