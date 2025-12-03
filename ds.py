from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset, DataLoader
from sklearn.metrics import classification_report
import glob
import os
import json
import torch
import argparse
import random
import string
from sys import argv
import torch.nn.functional as F

##############################################################################################
#                                       FONCTIONS                                            #
##############################################################################################

def load_data(base_path):
    data = []
    json_files = glob.glob(os.path.join(base_path, "*.json"))

    # POSITIFS – on accepte toutes les extensions courantes
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                json_data = json.load(f)
        except:
            continue

        base_name = os.path.splitext(json_file)[0]
        possible_ext = ['.py', '.js', '.html', '.htm', '.css', '.php', '.java', '.go', '.sh', '.yaml', '.yml', '.json', '.xml', '.ts', '.tsx', '.jsx', '']
        code_file = None
        for ext in possible_ext:
            candidate = base_name + ext
            if os.path.exists(candidate):
                code_file = candidate
                break
        if not code_file:
            continue

        try:
            with open(code_file, 'r', encoding='utf-8', errors='ignore') as cf:
                code_lines = cf.readlines()
            full_code = ''.join(code_lines)
        except:
            continue

        for result in json_data.get("results", []):
            try:
                s_line = result['start']['line'] - 1
                e_line = result['end']['line']
                s_col = result['start']['col'] - 1
                e_col = result['end']['col']

                if s_line >= len(code_lines) or e_line > len(code_lines) + 1:
                    continue

                if s_line == e_line - 1:  # même ligne
                    snippet = code_lines[s_line][s_col:e_col]
                else:
                    snippet = code_lines[s_line][s_col:] + \
                              ''.join(code_lines[s_line + 1:e_line - 1]) + \
                              code_lines[e_line - 1][:e_col]

                data.append({
                    "code_snippet": snippet.strip(),
                    "label": 1,
                    "code": full_code,
                    "result": result
                })
            except:
                continue

    # NÉGATIFS – même logique d'extensions
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                json_data = json.load(f)
        except:
            continue

        if json_data.get("results"):
            continue

        base_name = os.path.splitext(json_file)[0]
        possible_ext = ['.py', '.js', '.html', '.htm', '.css', '.php', '.java', '.go', '.sh', '.yaml', '.yml', '.json', '.xml', '.ts', '.tsx', '.jsx', '']
        code_file = None
        for ext in possible_ext:
            candidate = base_name + ext
            if os.path.exists(candidate):
                code_file = candidate
                break
        if not code_file:
            continue

        try:
            with open(code_file, 'r', encoding='utf-8', errors='ignore') as cf:
                full_code = cf.read()
            data.append({
                "code_snippet": full_code.strip()[:1500],
                "label": 0,
                "code": full_code,
                "result": {}
            })
        except:
            continue

    return data


def list_directories(path):
    try:
        dirs = [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]
        if not dirs:
            return []
        print("\nAvailable directories:")
        mur = "+===============================================================+"
        print(mur)
        for i, name in enumerate(dirs, 1):
            print(f"| {i} | {name}"+" "*max(len(mur)-7-len(str(i))-len(name),0) + " |")
        print("|"+"-"*(len(mur)-2)+"|")
        print("| 0 | Retour"+' '*(len(mur)-13)+"|")
        print(mur)
        return dirs
    except FileNotFoundError:
        print("[ERREUR] Chemin introuvable.")
        return []


def select_option(options):
    """options = liste de strings, retourne l'élément choisi ou None si retour"""
    while True:
        try:
            choix = input("> ").strip()
            if choix == "0":
                return None
            idx = int(choix) - 1
            if 0 <= idx < len(options):
                return options[idx]
            else:
                print("[ERREUR] Numéro invalide, réessaie.")
        except ValueError:
            print("[ERREUR] Entre un nombre valide ou 0 pour retour.")


def prepare_input(item):
    vuln_info = json.dumps(item.get('result', {}), ensure_ascii=False, indent=2)
    return f"""
Code Snippet:
{item['code_snippet']}

Vulnerability Details:
{vuln_info}
""".strip()


def analyze_code_dir(model_path, code_dir):
    extensions = ["*.py", "*.js", "*.html", "*.htm", "*.css", "*.php", "*.java", "*.go", "*.sh", 
                  "*.yaml", "*.yml", "Dockerfile", "*.json", "*.xml", "*.ts", "*.tsx", "*.jsx"]
    files = []
    for ext in extensions:
        files.extend(glob.glob(os.path.join(code_dir, "**", ext), recursive=True))
        files.extend(glob.glob(os.path.join(code_dir, "**", ext.upper()), recursive=True))

    if not files:
        print("[INFO] Aucun fichier à analyser trouvé.")
        return []

    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    results = []

    print(f"\n[INFO] Analyse de {len(files)} fichiers...\n")

    for f in files:
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
                code = fp.read()
        except:
            results.append({"file": f, "status": "ERREUR_LECTURE"})
            continue

        inputs = tokenizer(code, return_tensors="pt", truncation=True, padding=True, max_length=512)
        with torch.no_grad():
            outputs = model(**inputs)
        pred = torch.argmax(outputs.logits, dim=-1).item()
        conf = F.softmax(outputs.logits, dim=-1).max().item()

        status = "VULNÉRABLE" if pred == 1 else "SÛR"
        results.append({"file": f, "status": status, "confidence": round(conf, 4)})
        print(f"{os.path.basename(f)} → {status} (confiance: {conf:.4f})")

    return results


def use_model(model_name, code_path):
    model = AutoModelForSequenceClassification.from_pretrained(f"./models/{model_name}")
    tokenizer = AutoTokenizer.from_pretrained(f"./models/{model_name}")
    
    with open(code_path, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()

    inputs = tokenizer(code, return_tensors="pt", padding="max_length", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
    pred = torch.argmax(outputs.logits, dim=-1).item()
    conf = F.softmax(outputs.logits, dim=-1).max().item()
    pred_str = "VULNÉRABLE" if pred == 1 else "SÛR"
    return pred_str, round(conf, 4)


##############################################################################################
#                                          CLASSES                                           #
##############################################################################################

class CodeDataset(Dataset):
    def __init__(self, data, tokenizer, max_length=512):
        self.data = data
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        item = self.data[idx]
        inputs = self.tokenizer(
            prepare_input(item),
            padding="max_length",
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt"
        )
        label = torch.tensor(item["label"], dtype=torch.long)
        return {
            'input_ids': inputs["input_ids"].squeeze(),
            'attention_mask': inputs["attention_mask"].squeeze(),
            'label': label
        }


class DeepSASTModel:
    def __init__(self, model_name, num_labels=2, local_files_only=False):
        print(f"[INFO] Chargement modèle : {model_name}")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_name, num_labels=num_labels, local_files_only=local_files_only, ignore_mismatched_sizes=True
        )
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=local_files_only)
        print("[INFO] Modèle chargé !")

    def train(self, train_data, val_data):
        print("[INFO] Début entraînement...")
        training_args = TrainingArguments(
            output_dir="./results",
            eval_strategy="epoch",
            learning_rate=2e-5,
            per_device_train_batch_size=16,
            num_train_epochs=3,
            weight_decay=0.01,
            logging_dir="./logs",
            save_strategy="epoch",
            load_best_model_at_end=True,
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_data,
            eval_dataset=val_data,
        )
        trainer.train()

        os.makedirs("./models", exist_ok=True)
        model_id = f"deep_sast_model_{len(os.listdir('./models'))+1}_{''.join(random.choices(string.ascii_lowercase, k=6))}"
        save_path = f"./models/{model_id}"
        self.model.save_pretrained(save_path)
        self.tokenizer.save_pretrained(save_path)
        print(f"[INFO] Modèle sauvegardé → {save_path}")

    def evaluate(self, val_data):
        if len(val_data) == 0:
            print("[INFO] Pas de données de validation → évaluation ignorée.")
            return
        print("[INFO] Évaluation...")
        loader = DataLoader(val_data, batch_size=16)
        preds = []
        labels = []

        self.model.eval()
        with torch.no_grad():
            for batch in loader:
                outputs = self.model(input_ids=batch['input_ids'], attention_mask=batch['attention_mask'])
                preds.extend(torch.argmax(outputs.logits, dim=-1).tolist())
                labels.extend(batch['label'].tolist())

        names = ["Sûr", "Vulnérable"] if len(set(labels)) > 1 else (["Sûr"] if 0 in labels else ["Vulnérable"])
        print(classification_report(labels, preds, target_names=names, zero_division=0))


##############################################################################################
#                                       TRAIN FUNCTIONS                                       #
##############################################################################################

def train(PROJECT_PATH, LANGUAGE, FRAMEWORK="pure"):
    full_dir = os.path.join(PROJECT_PATH, LANGUAGE, FRAMEWORK if FRAMEWORK != 'full' else '', 'full')
    print(f"[INFO] Dossier cible → {full_dir}")

    data = load_data(full_dir)

    if not data:
        print("[ERREUR] Aucun échantillon trouvé dans ce dossier (vérifie que les .json ont leurs fichiers correspondants).")
        input("\nAppuie sur Entrée pour revenir au menu...")
        return

    pos = sum(1 for x in data if x['label'] == 1)
    print(f"[INFO] {len(data)} échantillons chargés ({pos} vulnérables, {len(data)-pos} sûrs)")

    train_data, val_data = train_test_split(data, test_size=0.2, random_state=42)
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
    train_dataset = CodeDataset(train_data, tokenizer)
    val_dataset = CodeDataset(val_data, tokenizer)

    model = DeepSASTModel("bert-base-uncased", num_labels=2, local_files_only=False)
    model.train(train_dataset, val_dataset)
    model.evaluate(val_dataset)


def train_with_model_info(model_path, project_path, language, framework="pure"):
    full_dir = os.path.join(project_path, language, framework if framework != 'full' else '', 'full')
    print(f"[INFO] Dossier cible → {full_dir}")
    data = load_data(full_dir)
    
    if not data:
        print("[ERREUR] Aucun échantillon trouvé dans ce dossier.")
        print(f"[WARNING] Assurer qu'il y a des fichiers .json dans de repertoire → {full_dir} . C'est le seule format accepté pour l'instant, si vous avez des fichiers .yml ou .yaml pour l'evaluation, trasformer les en .json d'abord puis reessayez.")
        input("\n[OPTIONS] Appuie sur Entrée pour revenir au menu...")
        return

    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
    train_data, val_data = train_test_split(data, test_size=0.2, random_state=42)
    train_dataset = CodeDataset(train_data, tokenizer)
    val_dataset = CodeDataset(val_data, tokenizer)

    model = DeepSASTModel(model_path, num_labels=2, local_files_only=True)
    model.train(train_dataset, val_dataset)
    model.evaluate(val_dataset)


##############################################################################################
#                                            MAIN                                              #
##############################################################################################

def main():
    banner = """
    ███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    ██                                                                                                                               ██
    ██                                                                                                                               ██
    ██                    ██████╗   ███████╗  ███████╗  ██████╗     ███████╗   █████╗   ███████╗  ████████╗                          ██
    ██                    ██╔══██╗  ██╔════╝  ██╔════╝  ██╔══██╗    ██╔════╝  ██╔══██╗  ██╔════╝  ╚══██╔══╝                          ██
    ██                    ██║  ██║  █████╗    █████╗    ██████╔╝    ███████╗  ███████║  ███████╗     ██║                             ██
    ██                    ██║  ██║  ██╔══╝    ██╔══╝    ██╔═══╝     ╚════██║  ██╔══██║  ╚════██║     ██║                             ██
    ██                    ██████╔╝  ███████╗  ███████╗  ██║         ███████║  ██║  ██║  ███████║     ██║                             ██ 
    ██                    ╚═════╝   ╚══════╝  ╚══════╝  ╚═╝         ╚══════╝  ╚═╝  ╚═╝  ╚══════╝     ╚═╝                             ██                                        
    ██                                                                                                                               ██
    ██                                                                                                                               ██
    ███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    """
    print(banner)
    print("[INFO] Welcome to DeepSAST - Code Security Analysis Tool")
    print("===============================================")

    TOKEN_PRODUCTION = '121246856ab4545644c645e6664f644e46e46f6464e6a479682849e65a6b6b6b'

    if len(argv) >= 4:
        parser = argparse.ArgumentParser()
        parser.add_argument("--model", required=True)
        parser.add_argument("--code-dir", required=True)
        parser.add_argument("--token", required=True)
        parser.add_argument("--output-sast")
        args = parser.parse_args()

        if args.token != TOKEN_PRODUCTION:
            print('[ERREUR] Token invalide.')
            exit(1)

        results = analyze_code_dir(args.model, args.code_dir)
        if args.output_sast:
            with open(args.output_sast, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
        print("[INFO] Analyse terminée.")
    else:
        print('[INFO] Mode développement\n')
        while True:
            print("\nAvailable Commands:")
            print("+==========================+")
            print("| 1 | TRAIN                |")
            print("| 2 | USE MODEL            |")
            print("| 3 | TRAIN WITH MODEL     |")
            print("|--------------------------|")
            print("| exit | QUIT              |")
            print("+==========================+")

            cmd = input("\n> ").strip().lower()

            if cmd == "exit":
                print("Bye !")
                break

            elif cmd == "1":
                path = input("\nProject path:\n> ").strip()
                if not path or not os.path.exists(path):
                    print("[ERREUR] Chemin invalide.")
                    continue
                dirs = list_directories(path)
                if not dirs:
                    continue
                lang = select_option(dirs)
                if lang is None:
                    continue
                fw_path = os.path.join(path, lang)
                fws = list_directories(fw_path)
                fw = select_option(fws) or "pure"
                if fw is None:
                    continue
                print(f"\n[INFO] Lancement entraînement sur {lang}/{fw}...\n")
                train(path, lang, fw)

            elif cmd == "2":
                models = [d for d in os.listdir("./models") if os.path.isdir(os.path.join("./models", d))]
                if not models:
                    print("[WARNING] Aucun modèle trouvé.")
                    continue
                print("\nModèles disponibles:")
                mur = "+===============================================================+"
                print(mur)
                for i, name in enumerate(models, 1):
                    print(f"| {i} | {name}"+" "*max(len(mur)-7-len(str(i))-len(name),0) + " |")
                print("|"+"-"*(len(mur)-2)+"|")
                print("| 0 | Retour"+' '*(len(mur)-13)+"|")
                print(mur)
                choice = select_option(models)
                if choice is None:
                    continue
                code_path = input("\nFichier à analyser:\n> ").strip()
                if os.path.exists(code_path):
                    status, conf = use_model(choice, code_path)
                    print(f"\n[RÉSULTAT] → {status} (confiance: {conf})")
                else:
                    print("[ERREUR] Fichier introuvable.")

            elif cmd == "3":
                models = [d for d in os.listdir("./models") if os.path.isdir(os.path.join("./models", d))]
                if not models:
                    print("[WARNING] Aucun modèle.")
                    continue
                print("\nModèles disponibles:")
                mur = "+===============================================================+"
                print(mur)
                for i, name in enumerate(models, 1):
                    print(f"| {i} | {name}"+" "*max(len(mur)-7-len(str(i))-len(name),0) + " |")
                print("|"+"-"*(len(mur)-2)+"|")
                print("| 0 | Retour"+' '*(len(mur)-13)+"|")
                print(mur)
                model_dir = select_option(models)
                if model_dir is None:
                    continue
                path = input("\nData Project path:\n> ").strip()
                if not path or not os.path.exists(path):
                    print("[ERREUR] Chemin invalide.")
                    continue
                dirs = list_directories(path)
                if not dirs:
                    continue
                lang = select_option(dirs)
                if lang is None:
                    continue
                fw_path = os.path.join(path, lang)
                fws = list_directories(fw_path)
                fw = select_option(fws) or "pure"
                if fw is None:
                    continue
                print(f"\n[INFO] Fine-tuning {model_dir} sur {lang}/{fw}...")
                train_with_model_info(f"./models/{model_dir}", path, lang, fw)

if __name__ == "__main__":
    main()