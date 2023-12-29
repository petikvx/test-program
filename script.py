import hashlib
import os
import sys
from datetime import datetime
import subprocess

def calculate_hashes(file_path):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return md5_hash.hexdigest(), sha256_hash.hexdigest()

def get_file_info(file_path):
    if not os.path.exists(file_path):
        return None

    file_info = {}
    file_info["MD5"] = calculate_hashes(file_path)[0]
    file_info["SHA256"] = calculate_hashes(file_path)[1]

    # Convertir la date de création en format "DD/MM/YYYY HH:MM:SS"
    creation_time = os.path.getctime(file_path)
    file_info["Date de création"] = datetime.fromtimestamp(creation_time).strftime("%d/%m/%Y %H:%M:%S")

    # Utiliser la commande "file" pour obtenir le type de fichier
    try:
        file_type = subprocess.check_output(["file", file_path], universal_newlines=True)
        file_info["Type de fichier"] = file_type.strip()
    except subprocess.CalledProcessError:
        file_info["Type de fichier"] = "N/A"

    return file_info

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Utilisation: python script.py nom_du_fichier.exe")
        sys.exit(1)

    file_path = sys.argv[1]
    file_info = get_file_info(file_path)

    if file_info:
        for key, value in file_info.items():
            print(f"{key}: {value}")
    else:
        print("Le fichier n'existe pas.")
