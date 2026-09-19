import json
meta = json.load(open('app/core/model_artifacts/metadata.json'))
meta['current_version'] = 4
with open('app/core/model_artifacts/metadata.json', 'w') as f:
    json.dump(meta, f, indent=2)
print('rolled back to v4:', meta['current_version'])