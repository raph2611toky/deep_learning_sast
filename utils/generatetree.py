import os

def generate_tree(base_path, max_depth=3, prefix=""):
    """
    Génère un affichage en arbre pour le répertoire spécifié.
    Args:
        base_path (str): Chemin de base du répertoire.
        max_depth (int): Profondeur maximale de l'arbre.
        prefix (str): Préfixe utilisé pour l'affichage en cascade.
    """
    if max_depth < 1:
        return
    
    try:
        entries = sorted(os.listdir(base_path))
    except PermissionError:
        print(f"{prefix}[ACCESS DENIED] {base_path}")
        return
    
    for i, entry in enumerate(entries):
        entry_path = os.path.join(base_path, entry)
        is_last = i == len(entries) - 1
        connector = "└─" if is_last else "├─"
        print(f"{prefix}{connector} {entry}")
        
        if os.path.isdir(entry_path):  # Si c'est un répertoire, parcourir récursivement
            new_prefix = prefix + ("   " if is_last else "│  ")
            generate_tree(entry_path, max_depth - 1, new_prefix)

# Chemin de base
base_path = "/home/r4ph/soutenance/conf/semgrep/rules"

# Générer l'arbre
print(f"Arborescence de : {base_path}")
generate_tree(base_path, max_depth=3)
