# DeepSAST - Code Security Analysis Tool

    ███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    ██                                                                                                                               ██
    ██                                                                                                                               ██
    ██                    ██████╗   ███████╗  ███████╗  ██████╗     ███████╗   █████╗   ███████╗  ████████╗                          ██
    ██                    ██╔══██╗  ██╔════╝  ██╔════╝  ██╔══██╗    ██╔════╝  ██╔══██╗  ██╔════╝  ╚══██╔══╝                          ██
    ██                    ██║  ██║  █████╗    █████╗    ██████╔╝    ███████╗  ███████║  ███████╗     ██║                             ██
    ██                    ██║  ██║  ██╔══╝    ██╔══╝    ██╔═══╝     ╚════██║  ██╔══██║  ╚════██║     ██║                             ██
    ██                    ██████╔╝  ███████╗  ███████╗  ██║         ███████║  ██║  ██║  ███████║     ██║                             ██ 
    ██                    ╚═════╝   ╚══════╝  ╚══════╝  ╚═╝         ╚══════╝  ╚═╝  ╚═╝  ╚══════╝     ╚═╝                             ██  ██                                                                                                                               ██
    ██                                                                                                                               ██
    ██                                                                                                                               ██
    ███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████


DeepSAST est un outil d'analyse de sécurité de code source basé sur l'apprentissage profond. Il permet de détecter automatiquement les vulnérabilités dans des fichiers Python et peut être entraîné sur vos propres projets pour améliorer la détection.

---

## Fonctionnalités principales

* **Chargement de données depuis JSON et fichiers Python** pour créer des exemples d’entraînement.
* **Préparation des snippets de code** et des détails de vulnérabilité pour le modèle.
* **Modèle Deep Learning** basé sur `Transformers` (BERT) pour classifier les codes vulnérables.
* **Entraînement, évaluation et prédiction** sur des fichiers ou répertoires de code.
* **Mode production et développement**, avec un token de sécurité pour protéger les modèles.

---

## Installation

1. Cloner le dépôt :

```bash
git clone <repository_url>
cd deep_learning
```

2. Installer les dépendances Python :

```bash
pip install torch transformers scikit-learn
```

---

## Utilisation

### Mode développement

Lancer le script directement :

```bash
python main.py
```

Un menu interactif vous permet de :

1. **TRAIN** : entraîner un nouveau modèle à partir de zéro.
2. **USE MODEL** : utiliser un modèle existant pour analyser un fichier de code.
3. **TRAIN WITH MODEL** : continuer l’entraînement à partir d’un modèle déjà pré-entraîné.

Vous pourrez sélectionner le projet, la langue et le framework, ainsi que les modèles et fichiers à analyser.

### Mode production

Pour analyser automatiquement un répertoire avec un modèle pré-entraîné :

```bash
python main.py --model <chemin_du_model> --code-dir <chemin_du_code> --token <jeton_de_securite> --output-sast <resultats.json>
```

* `--model` : chemin vers le modèle pré-entraîné.
* `--code-dir` : répertoire contenant le code à analyser.
* `--token` : jeton de sécurité requis pour le mode production.
* `--output-sast` *(optionnel)* : fichier JSON pour enregistrer les résultats.

---

## Structure du projet

* `main.py` : script principal avec le menu interactif et le mode production.
* `models/` : dossier où les modèles entraînés sont sauvegardés.
* `data/` : exemples de fichiers JSON et Python pour l’entraînement.
* `utils/` *(optionnel)* : fonctions utilitaires pour le traitement des fichiers et du code.

---

## Classes et fonctions importantes

* **`DeepSASTModel`** : classe principale du modèle, permet d’entraîner, évaluer et prédire.
* **`CodeDataset`** : classe pour créer un dataset PyTorch à partir des snippets de code.
* **`load_data`** : charge et prépare les données à partir des fichiers JSON et Python.
* **`analyze_code_dir`** : analyse tous les fichiers Python dans un répertoire donné.
* **`prepare_input`** : combine le snippet de code et les détails de vulnérabilité pour le modèle.

---

## Remarques

* Les fichiers contenant des secrets ou des clés API doivent être exclus de l’entraînement pour éviter les problèmes de push sur GitHub.
* Les modèles sont basés sur BERT et nécessitent un GPU pour un entraînement efficace.

---

## Licence

Ce projet est open-source et peut être utilisé et modifié librement.

---

💡 **Conseil** : commencez par entraîner un modèle sur un petit projet pour vérifier le fonctionnement avant de l’utiliser sur des projets plus larges.
