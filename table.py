import json
from collections import defaultdict
import os

def process_json_file(filepath):
    # Load the JSON data
    with open(filepath, 'r') as file:
        data = json.load(file)
    
    cwe_severity_counts = defaultdict(lambda: defaultdict(int))
    test_id_severity_counts = defaultdict(lambda: defaultdict(int))
    
    for result in data.get("results", []):
        if "issue_cwe" in result:
            cwe_id = result["issue_cwe"]["id"]
            severity = result["issue_severity"].upper()
            cwe_severity_counts[cwe_id][severity] += 1
        
        if "test_id" in result:
            test_id = result["test_id"]
            severity = result["issue_severity"].upper()
            test_id_severity_counts[test_id][severity] += 1

    return cwe_severity_counts, test_id_severity_counts

json_dir = "."

all_cwe_counts = defaultdict(lambda: defaultdict(int))
all_test_id_counts = defaultdict(lambda: defaultdict(int))

for filename in os.listdir(json_dir):
    if filename.endswith('.json'):
        filepath = os.path.join(json_dir, filename)
        file_cwe_counts, file_test_id_counts = process_json_file(filepath)
        
        for cwe, severities in file_cwe_counts.items():
            for severity, count in severities.items():
                all_cwe_counts[cwe][severity] += count
        
        for test_id, severities in file_test_id_counts.items():
            for severity, count in severities.items():
                all_test_id_counts[test_id][severity] += count

print("CWE Results:")
for cwe, severities in all_cwe_counts.items():
    print(f"CWE-{cwe}: ", end="")
    for severity, count in severities.items():
        print(f"{severity.lower()}: {count}", end=", ")
    print()

print("\nTest ID Results:")
for test_id, severities in all_test_id_counts.items():
    print(f"Test-{test_id}: ", end="")
    for severity, count in severities.items():
        print(f"{severity.lower()}: {count}", end=", ")
    print()
