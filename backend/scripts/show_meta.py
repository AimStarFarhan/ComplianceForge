import json
meta = json.load(open('app/core/model_artifacts/metadata.json'))
for v in meta['versions']:
    print(f"v{v['version']}: acc={v['accuracy']:.4f} n={v['n_examples']}")
print('current:', meta['current_version'])