"""Compare details of discrepant results between Python and PS tools."""
import json, os, collections

def load_checkpoints(ckpt_dir):
    results = []
    for f in os.listdir(ckpt_dir):
        if f.endswith('.json'):
            with open(os.path.join(ckpt_dir, f)) as fh:
                data = json.load(fh)
                if isinstance(data, dict) and 'results' in data:
                    results.extend(data['results'])
                elif isinstance(data, list):
                    results.extend(data)
    return results

py_results = load_checkpoints('cis_checkpoints')
ps_results = load_checkpoints(r'C:\Temp\CISAzureBenchmark-PS\cis_checkpoints')

discrepant = ['9.3.4', '9.3.5', '8.3.6', '9.3.6', '5.27', '7.6', '7.10', '6.1.1.2', '8.3.5', '8.3.8', '9.3.2.1', '9.3.2.3']

for ctrl in discrepant:
    print(f'=== {ctrl} ===')
    py_r = [r for r in py_results if r['control_id'] == ctrl]
    ps_r = [r for r in ps_results if r['control_id'] == ctrl]
    py_by_res = {r.get('resource', '').lower(): r for r in py_r}
    ps_by_res = {r.get('resource', '').lower(): r for r in ps_r}
    found = False
    for res in sorted(set(py_by_res) & set(ps_by_res)):
        pr, psr = py_by_res[res], ps_by_res[res]
        if pr['status'] != psr['status']:
            print(f'  Resource: {res}')
            print(f'  PY: {pr["status"]} | {pr["details"][:150]}')
            print(f'  PS: {psr["status"]} | {psr["details"][:150]}')
            found = True
            break
    if not found:
        if py_r:
            print(f'  PY sample: {py_r[0]["status"]} | {py_r[0]["details"][:150]}')
        if ps_r:
            print(f'  PS sample: {ps_r[0]["status"]} | {ps_r[0]["details"][:150]}')
    print()
