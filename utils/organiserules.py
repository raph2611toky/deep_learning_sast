import os
import shutil

from sys import argv

frameworks = {
    'python': ['django', 'flask', 'fastapi', 'pyramid', 'bottle', 'tornado', 'cherrypy', 'web2py', 'sanic', 'falcon', 'hug', 'dash', 'cuba', 'masonite', 'quokka', 'zope'],
    'php': ['laravel', 'symfony', 'codeigniter', 'zend', 'yii', 'fuelphp'],
    'javascript': ['express', 'koa', 'meteor', 'nextjs', 'nuxt', 'sails', 'hapi'],
    'java': ['spring', 'struts', 'hibernate', 'javaee'],
    'csharp': ['aspnet', 'nunit', 'xamarin'],
    'go': ['gin', 'beego', 'echo', 'revel'],
    'ruby': ['rails', 'sinatra'],
    'rust': ['rocket', 'actix'],
    'scala': ['play', 'akka'],
    'swift': ['vapor', 'kitura'],
    'typescript': ['nestjs', 'express', 'koa'],
    'bash': [],
    'dockerfile': [],
    'elixir': ['phoenix'],
    'kotlin': ['ktor'],
    'solidity': [],
    'terraform': [],
    'ocaml': [],
    'json': [],
    'libsonnet': [],
    'yaml': [],
    'apex': [],
    'generic': []
}

def move_non_frameworks(base_path, frameworks, lang):
    lang_path = os.path.join(base_path, lang)
    pure_path = os.path.join(lang_path, 'pure')
    if not os.path.exists(pure_path):
        os.mkdir(pure_path)

    for item in os.listdir(lang_path):
        item_path = os.path.join(lang_path, item)
        if os.path.isdir(item_path) and item.lower() not in frameworks[lang]+['pure']:
            try:
                shutil.move(item_path, os.path.join(pure_path, item))
                print(f"[INFO] ... Dossier '{item}' déplacé dans 'pure'")
            except Exception as e:
                print(f"[ERREUR] ... Erreur lors du déplacement de '{item}': {e}")

def organize_project(base_path):
    for langage in frameworks.keys():
        print(f"[INFO] ... Organiser le repertoire {langage}")
        move_non_frameworks(base_path, frameworks, langage)

def main():
    if len(argv)==2:
        base_path = argv[1]
    else:
        print(f"[ERREUR].... utilisation: python3 {argv[0]} [<path_dir>]")
    organize_project(base_path)

main()