# Path Matching Script Pattern

Reusable Python pattern for cross-referencing OJK audit paths against Tyk gateway configs.

## Core Matching Logic

```python
import csv
import re

def normalize_params(path):
    """Replace all {param} with {id} for comparison"""
    return re.sub(r'\{[^}]+\}', '{id}', path)

def clean_tyk_path(path):
    """Clean regex/glob artifacts from Tyk config paths"""
    clean = path.strip().rstrip('$').lstrip('^')
    clean = clean.replace('\\/', '/').replace('\\?', '?')
    if clean.endswith('/*'):
        clean = clean[:-2]
    return clean

def build_path_map(csv_file, path_col=3):
    """Build {path: [(source_file, listen_path)]} from assessment CSV"""
    path_map = {}
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            if len(row) > path_col:
                path = clean_tyk_path(row[path_col])
                if '/black-list-url' in path:
                    continue
                src = row[0].strip()
                listen = row[1].strip()
                if path not in path_map:
                    path_map[path] = []
                path_map[path].append((src, listen))
    return path_map

def find_match(ojk_path, path_map):
    """Find ojk_path in path_map using direct + normalized + suffix matching"""
    # 1. Direct match
    if ojk_path in path_map:
        return path_map[ojk_path]
    
    # 2. Parameter-normalized match
    ojk_norm = normalize_params(ojk_path)
    for config_path, sources in path_map.items():
        config_norm = normalize_params(config_path)
        if ojk_norm == config_norm:
            return sources
    
    # 3. Suffix match (handles listen_path prefix stripping)
    for config_path, sources in path_map.items():
        if ojk_path.endswith(config_path) and config_path.startswith('/'):
            return sources
    
    return None

def find_prefix_mismatch(ojk_path, path_map, min_segments=2):
    """Find closest match by trailing segment comparison"""
    ojk_norm = normalize_params(ojk_path)
    ojk_parts = [p for p in ojk_norm.split('/') if p]
    
    best_match = None
    best_score = 0
    
    for config_path, sources in path_map.items():
        config_norm = normalize_params(config_path)
        config_parts = [p for p in config_norm.split('/') if p]
        
        # Count matching trailing segments
        match_count = 0
        for o, c in zip(reversed(ojk_parts), reversed(config_parts)):
            if o == c:
                match_count += 1
            else:
                break
        
        if match_count >= min_segments and match_count > best_score:
            best_score = match_count
            best_match = (config_path, sources)
    
    return best_match
```

## Usage Pattern

```python
whitelist_map = build_path_map('assessment/whitelist-endpoints.csv')
blacklist_map = build_path_map('assessment/blacklist-endpoints.csv')

# For each OJK row:
bl_match = find_match(ojk_path, blacklist_map)
wl_match = find_match(ojk_path, whitelist_map)

if bl_match:
    col_f = 'Yes'
    col_g = '; '.join(sorted(set(s[0] for s in bl_match)))
elif wl_match:
    col_f = 'No'
    col_g = '; '.join(sorted(set(s[0] for s in wl_match)))
else:
    # Try prefix mismatch detection
    mismatch = find_prefix_mismatch(ojk_path, {**whitelist_map, **blacklist_map})
```
