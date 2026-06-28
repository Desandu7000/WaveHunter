import json
with open('report.json', 'r') as f:
    report = json.load(f)
for cand in report.get('candidates', []):
    print(cand['name'])
