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

##############################################################################################
#                                                                                            #
#                                       FUNCTION LISTS                                       #
#                                                                                            #
##############################################################################################

def load_data(base_path):
    data = []
    json_files = glob.glob(os.path.join(base_path, "*.json"))
    
    for json_file in json_files:
        with open(json_file, 'r') as f:
            json_data = json.load(f)
        
        code_file = json_file.replace('.json', '.py')
        with open(code_file, 'r') as code_f:
            code_lines = code_f.readlines()
        if "results" not in json_data:
            print(f"[ERREUR] Clé 'results' manquante dans le fichier JSON: {json_file}")
            continue

        for result in json_data.get("results", []):
            start_line = result['start']['line'] - 1
            end_line = result['end']['line']
            start_col = result['start']['col'] - 1
            end_col = result['end']['col']
            
            if start_line == end_line - 1:
                code_snippet = code_lines[start_line]
            else:
                code_snippet = code_lines[start_line] + '\n'.join(code_lines[start_line + 1:end_line - 1]) + code_lines[end_line - 1]
            
            label = 1 if 'check_id' in result else 0
            
            data.append({
                "code_snippet": code_snippet.strip(),
                "label": label,
                "code": ''.join(code_lines),
                "result": result
            })
    
    return data

def list_directories(path, with_path=False):
    """Lists directories and returns the list."""
    try:
        dirs = os.listdir(path)
        print("\nAvailable directories:")
        print("\n-----------------------------------")
        for i, dir_name in enumerate(dirs, start=1):
            print(f"{i}. {dir_name}")
            print("-----------------------------------")
        if with_path:
            return [os.path.join(path, dir)for dir in dirs]
        return dirs
    except FileNotFoundError:
        print("[ERROR] Path not found.")
        return []

def select_by_number(items):
    """Prompts user to select an item by number."""
    try:
        index = int(input("> ")) - 1
        if 0 <= index < len(items):
            return items[index]
        else:
            print("[ERROR] Invalid selection.")
            return None
    except ValueError:
        print("[ERROR] Invalid input. Please enter a number.")
        return None

def prepare_input(item):
    assert isinstance(item, dict), "item doit être un dictionnaire"
    vuln_info = json.dumps(item.get('result', {}))
    combined_text = f"""
        Code Snippet: {item['code_snippet']}
        Vulnerability Details:
        {vuln_info}
        """
    return combined_text

def analyze_code_dir(model_path, code_dir):
    python_files = glob.glob(os.path.join(code_dir, "*.py"))
    results = []
    
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    
    for code_file in python_files:
        print(f"[INFO] Analyse du fichier {code_file} ...")
        with open(code_file, 'r') as file:
            code = file.read()
        
        inputs = tokenizer(code, return_tensors="pt", padding="max_length", truncation=True)
        outputs = model(**inputs)
        prediction = torch.argmax(outputs.logits, dim=-1).item()
        
        result = {
            "file": code_file,
            "prediction": prediction
        }
        results.append(result)
        print(f"[INFO] Analyzed {code_file}: {result['prediction']}")
    
    return results

def write_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)
        
def detect_dir_language(dir):
    print(f'[INFO] ... Detection de language du repertoire {dir}')
    pass

def get_extension_language(language):
    print(f'[INFO] ... Extraction de l\'extension du language {language}')
    pass

##############################################################################################
#                                                                                            #
#                                        CLASS LISTS                                         #
#                                                                                            #
##############################################################################################


class CodeDataset(Dataset):
    """Classe pour créer un dataset torch pour le code."""
    def __init__(self, data, tokenizer, max_length=512):
        self.data = data
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            return [self.have_item(self.data[i]) for i in range(*idx.indices(len(self)))]
        else:
            item = self.data[idx]
            return self.have_item(item)

    def have_item(self, item):
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
    """Classe pour le modèle d'apprentissage profond."""
    def __init__(self, model_name, num_labels=2, local_files_only=True):
        print(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=num_labels, local_files_only=local_files_only,ignore_mismatched_sizes=True)
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=local_files_only,ignore_mismatched_sizes=True)
        print("[INFO] ... Deep SAST model est initialisé avec succès👌")

    def train(self, train_data, val_data):
        """Entraîne le modèle."""
        print("[INFO] ... Début de l'entraînement.")
        #train_dataloader = DataLoader(train_data, batch_size=16, shuffle=True)
        #val_dataloader = DataLoader(val_data, batch_size=16)

        training_args = TrainingArguments(
            output_dir="./results",
            eval_strategy="epoch",
            learning_rate=2e-5,
            per_device_train_batch_size=16,
            num_train_epochs=3,
            weight_decay=0.01,
            logging_dir="./logs"
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_data,
            eval_dataset=val_data
        )
        trainer.train()
        
        if not os.path.exists("./models"):
            os.makedirs("./models")
        
        model_name = f'deep_sast_model_{len(os.listdir("./models"))+1}_'+''.join(random.choices(string.ascii_letters, k=4))

        self.model.save_pretrained(f"./models/{model_name}")
        self.tokenizer.save_pretrained(f"./models/{model_name}")

        print(f"[INFO]  save to model  :  models/{model_name}")

    def evaluate(self, val_data):
        """Évalue le modèle."""
        val_dataloader = DataLoader(val_data, batch_size=16)
        all_preds = []
        all_labels = []

        self.model.eval()
        with torch.no_grad():
            for batch in val_dataloader:
                inputs, masks, labels = batch['input_ids'], batch['attention_mask'], batch['label']
                outputs = self.model(input_ids=inputs, attention_mask=masks)
                preds = torch.argmax(outputs.logits, dim=-1)
                all_preds.extend(preds.tolist())
                all_labels.extend(labels.tolist())

        print(classification_report(all_labels, all_preds))


    def predict(self, code_snippets):
        """Prédictions pour des snippets de code."""
        inputs = self.tokenizer(code_snippets, return_tensors="pt", padding="max_length", truncation=True)
        outputs = self.model(**inputs)
        predictions = torch.argmax(outputs.logits, dim=-1)
        return ["Vulnérable" if pred.item() == 1 else "Sûr" for pred in predictions]


##############################################################################################
#                                                                                            #
#                                        MAIN SCRIPT                                         #
#                                                                                            #
##############################################################################################

def train(PROJECT_PATH, LANGUAGE, FRAMEWORK="pure"):

    full_dir = os.path.join(PROJECT_PATH, LANGUAGE, FRAMEWORK if FRAMEWORK != 'full' else '', 'full')
    print(full_dir)
    data = load_data(full_dir)

    train_data, val_data = train_test_split(data, test_size=0.2, random_state=42)
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
    train_dataset = CodeDataset(train_data, tokenizer)
    val_dataset = CodeDataset(val_data, tokenizer)

    model = DeepSASTModel("bert-base-uncased", num_labels=len(set(prepare_input(item) for item in data)))
    model.train(train_dataset, val_dataset)
    model.evaluate(val_dataset)

def use_model(model_name, code_path):
    model = AutoModelForSequenceClassification.from_pretrained(f"./models/{model_name}")
    tokenizer = AutoTokenizer.from_pretrained(f"./models/{model_name}")
    
    with open(code_path, 'r') as file:
        code = file.read()

    inputs = tokenizer(code, return_tensors="pt", padding="max_length", truncation=True)
    outputs = model(**inputs)
    predictions = torch.argmax(outputs.logits, dim=-1)
    return predictions

def train_with_model_info(model_path, project_path, language, framework="pure"):
    full_dir = os.path.join(project_path, language, framework if framework != 'full' else '', 'full')
    data = load_data(full_dir)

    train_data, val_data = train_test_split(data, test_size=0.2, random_state=42)
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    train_dataset = CodeDataset(train_data, tokenizer)
    val_dataset = CodeDataset(val_data, tokenizer)

    model = DeepSASTModel(model_path, num_labels=len(set(prepare_input(item) for item in data)),local_files_only=True)
    model.train(train_dataset, val_dataset)
    model.evaluate(val_dataset)

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
    print("Welcome to DeepSAST - Code Security Analysis Tool")
    print("===============================================")

    TOKEN_PRODUCTION = '121246856ab4545644c645e6664f644e46e46f6464e6a479682849e65a6b6b6b'
    
    parser = argparse.ArgumentParser(description="SAST Analysis and Decision Maker")
    parser.add_argument("--model", required=True, help="Chemin du model dejà pre-entrainé.")
    parser.add_argument("--code-dir", required=True, help="Chemin du repértoire à analyser.")
    parser.add_argument("--token", required=True, help="Jeton de sécurité pour le model.")
    parser.add_argument("--output-sast", help="Path to store the SAST output as JSON.")
    parser.add_argument("--output-decision", help="Path to store the decision output as JSON.")
    args = parser.parse_args()
    
    if len(argv)>=4:
        print('[INFO] .... DeepSAST PRODUCTION mode.')
        model_path = args.model
        code_dir = args.code_dir
        token_prod = args.token
        if not os.path.exists(model_path):
            print('[ERREUR].... Utilisation incorrecte.')
            print(f'[ERREUR] ... {model_path} est introuvable, veuillez verifier ce chemin s\'il existe ou pas.')
            exit(1)
        if not os.path.exists(code_dir):
            print('[ERREUR].... Utilisation incorrecte.')
            print(f'[ERREUR] ... {code_dir} est introuvable, veuillez verifier ce chemin s\'il existe ou pas.')
            exit(1)
        if token_prod!=TOKEN_PRODUCTION:
            print('[ERREUR] ... Ce token n\'est pas valide ou expiré.')
            exit(1)
        results = analyze_code_dir(model_path, code_dir)
        print("[INFO] Analyse terminée.")
        if 'output_sast' in args and args.output_sast is not None:
            open(args.output_sast,'w').write(json.dumps(results, indent=4))
        
    else:
        print('[INFO] .... Deep sast developpement mode.....')
        while True:
            print("\nAvailable Commands:")
            print("+==========================+")
            print("|  1  |        TRAIN       |    - Entrainer le model de depart à 0.")
            print("+==========================+")
            print("|  2  |      USE MODEL     |    - Utiliser un model pour identifier des vulnérabilités.")
            print("+==========================+")
            print("|  3  |  TRAIN WITH MODEL  |    - Entrainer le model avec un model dejà préentrainé au paravant.")
            print("+==========================+")
            print("| exit |   QUIT COMMAND    |")
            print("+==========================+")
            
            command = input("> ").strip()

            if command.lower().strip() == "exit":
                print("Exiting...")
                break

            elif command.strip() == "1":
                print("Enter the project path:")
                path = input("> ").strip()
                dirs = list_directories(path)
                if dirs:
                    print("Select a directory by number:")
                    selected_dir = select_by_number(dirs)
                    if selected_dir:
                        language_path = os.path.join(path, selected_dir)
                        frameworks = list_directories(language_path)
                        if frameworks:
                            print("Select the framework by number (or press Enter for 'pure'):")
                            framework = select_by_number(frameworks) or "pure"
                            train(path, selected_dir, framework)


            elif command.strip() == "2":
                print("Listing models in './models'...")
                models = list_directories('./models')
                if models:
                    print("Select a model by number:")
                    model_name = select_by_number(models)
                    if model_name:
                        print("Enter path file for the code:")
                        code_path = input("> ").strip()
                        if os.path.exists(code_path):
                            predictions = use_model(model_name, code_path)
                            print(f"Predictions: {predictions}")
                        else:
                            print(f"path {code_path} est introuvable , veuillez verifier si ce fichier existe ou pas.😒")
                        
            elif command.strip() == "3":
                print("Listing models in './models'...")
                models = list_directories('./models', with_path=True)
                if models:
                    print("Select a model by number:")
                    model_name = select_by_number(models)
                    print("Enter the project path:")
                    path = input("> ").strip()
                    dirs = list_directories(path)
                    if dirs:
                        print("Select a directory by number:")
                        selected_dir = select_by_number(dirs)
                        if selected_dir:
                            language_path = os.path.join(path, selected_dir)
                            frameworks = list_directories(language_path)
                            if frameworks:
                                print("Select the framework by number (or press Enter for 'pure'):")
                                framework = select_by_number(frameworks) or "pure"
                                train_with_model_info(model_name, path, selected_dir, framework)

            else:
                print("[ERROR] Unknown caommand. Type 'train' or 'use_model'.")

if __name__ == "__main__":
    main()

