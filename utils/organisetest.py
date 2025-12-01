import os
import requests
import shutil

BASE_DIR = "/home/r4ph/soutenance/conf/semgrep/rules"

SERVER_URL = "http://localhost:8888"
SECRET_TOKEN = "R4ph_t0k3n_s3cr3t."

def read_file_from_server(file_path):
    """Récupère un fichier depuis le serveur."""
    if '..' in file_path or '../' in file_path:
        return None
    url = f"{SERVER_URL}/{file_path}"
    headers = {"Authorization": f"Bearer {SECRET_TOKEN}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print("[INFO] ... Fichier récupéré avec succès !")
        return response.text
    else:
        print(f"[ERREUR] ... Erreur lors de l'accès au fichier : {response.status_code}")
        return None

def get_rules(language, framework="pure"):
    headers = {"Authorization": f"Bearer {SECRET_TOKEN}"}
    body = {"language": language, "framework": framework}
    response = requests.post(SERVER_URL, json=body, headers=headers)

    if response.status_code == 200:
        print("[INFO] ... Règle trouvée.")
        return response.json().get('link')
    else:
        print(f"[ERREUR] ... Erreur lors de l'accès au fichier : {response.status_code}")
        return None


def process_language_framework(language_path, framework_path):
    full_dir = os.path.join(framework_path, "full")
    os.makedirs(full_dir, exist_ok=True)
    
    for root, _, files in os.walk(framework_path):
        for file in files:
            file_path = os.path.join(root, file)
            yaml_file_path = os.path.join(root, f"{os.path.splitext(file)[0]}.yaml")
            
            if os.path.exists(yaml_file_path) and not file.endswith(".yaml"):
                dest_file = os.path.join(full_dir, file)
                dest_yaml = os.path.join(full_dir, os.path.basename(yaml_file_path))
                
                if not os.path.exists(dest_file):
                    shutil.copy(file_path, dest_file)
                    print(f"Copied: {file} to {full_dir}")
                
                if not os.path.exists(dest_yaml):
                    shutil.copy(yaml_file_path, dest_yaml)
                    print(f"Copied: {os.path.basename(yaml_file_path)} to {full_dir}")

def process_all_languages(base_dir):
    for language in os.listdir(base_dir):
        language_path = os.path.join(base_dir, language)
        if os.path.isdir(language_path):
            for framework in os.listdir(language_path):
                framework_path = os.path.join(language_path, framework)
                if os.path.isdir(framework_path):
                    process_language_framework(language_path, framework_path)

process_all_languages(BASE_DIR)
