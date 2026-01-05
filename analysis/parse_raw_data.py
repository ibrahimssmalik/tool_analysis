import pandas as pd
import json

df = pd.read_excel('../Real_world_vulnerability_dataset/Real-world_benchmark.xlsx', sheet_name='Overall')

def fix_cwe_1000_format(cwe_1000_str):
    """
    Fix concatenated CWE classes like '664693' → 'CWE-664, CWE-693'
    """
    cwe_1000_str = str(cwe_1000_str).strip()
    
    if ',' in cwe_1000_str:
        parts = [p.strip() for p in cwe_1000_str.split(',')]
        return ', '.join([f"CWE-{p}" if not p.startswith('CWE-') else p for p in parts])
    
    # Single class (3 digits)
    if cwe_1000_str.isdigit() and len(cwe_1000_str) == 3:
        return f"CWE-{cwe_1000_str}"
    
    # Concatenated classes (6+ digits) - need to split
    if cwe_1000_str.isdigit() and len(cwe_1000_str) >= 6:
        # Split into groups of 3
        classes = [cwe_1000_str[i:i+3] for i in range(0, len(cwe_1000_str), 3)]
        return ', '.join([f"CWE-{c}" for c in classes])
    
    # Fallback
    if not cwe_1000_str.startswith('CWE-'):
        return f"CWE-{cwe_1000_str}"
    return cwe_1000_str

# Rebuild mapping with fixed formatting
cve_to_class = {}
for _, row in df.iterrows():
    cve_id = row['CVE_ID']
    cwe_1000 = row['CWE_1000']
    cve_to_class[cve_id] = fix_cwe_1000_format(cwe_1000)

# Save fixed version
with open('../Real_world_vulnerability_dataset/cve_to_class_official.json', 'w') as f:
    json.dump(cve_to_class, f, indent=2, sort_keys=True)

print("Saved to ../Real_world_vulnerability_dataset/cve_to_class_official.json")