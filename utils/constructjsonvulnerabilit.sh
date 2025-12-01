#!/bin/bash

cd /home/r4ph/soutenance/conf/semgrep/rules

apply_semgrep() {
  local full_dir="$1"
  
  cd "$full_dir" || exit
  
  for py_file in *.py; do
    base_name="${py_file%.py}"
    
    yaml_file="${base_name}.yaml"
    
    json_file="${base_name}.json"
    
    if [[ -f "$yaml_file" ]]; then
      semgrep --config="$yaml_file" "$py_file" --json > "$json_file"
      echo "Generated $json_file from $py_file using $yaml_file"
    else
      echo "YAML file $yaml_file not found for $py_file"
    fi
  done
  
  cd - > /dev/null || exit
}

for language in */; do
  language_path="${language%/}"
  
  if [[ -d "$language_path" ]]; then
    echo "Processing language: $language_path"
    
    for framework in "$language_path"/*/; do
      framework_path="${framework%/}"
      
      if [[ -d "$framework_path/full" ]]; then
        full_dir="$framework_path/full"
      else
        full_dir="$framework_path"
      fi
      
      if [[ -d "$full_dir" ]]; then
        apply_semgrep "$full_dir"
      fi
    done
  fi
done