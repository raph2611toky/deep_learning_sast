import os
import yaml

def concat_yaml_files(framework_path):
    full_yaml_path = os.path.join(framework_path, 'full.yaml')
    combined_yaml = []

    for root, dirs, files in os.walk(framework_path):
        for file in files:
            if file.endswith('.yaml') and not file.endswith('.test.yaml'):
                yaml_path = os.path.join(root, file)
                try:
                    with open(yaml_path, 'r') as f:
                        data = yaml.safe_load(f)
                        combined_yaml.append(data)
                        print(f"Ajout du fichier : {yaml_path}")
                except Exception as e:
                    print(f"Erreur lors de la lecture de {yaml_path}: {e}")
    
    try:
        with open(full_yaml_path, 'w') as f:
            yaml.dump(combined_yaml, f)
        print(f"Fichier full.yaml créé pour {framework_path}")
    except Exception as e:
        print(f"Erreur lors de la création de {full_yaml_path}: {e}")

def organize_yaml_files(base_path):
    for lang in os.listdir(base_path):
        lang_path = os.path.join(base_path, lang)

        if os.path.isdir(lang_path):
            for framework in os.listdir(lang_path):
                framework_path = os.path.join(lang_path, framework)
                if os.path.isdir(framework_path):
                    print(f"Traitement du framework : {framework_path}")
                    concat_yaml_files(framework_path)

base_path = '/home/r4ph/soutenance/conf/semgrep/rules'

organize_yaml_files(base_path)