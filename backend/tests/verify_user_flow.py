"""Verify the exact user flow:
ingest unknown file -> shows unknown + trainable
-> TRAIN (bulk confirm AI proposals)
-> re-ingest the SAME file -> recognized, no unknown lines
-> full audit runs with rule checks and AI+human-confirmed sources
"""
from fastapi.testclient import TestClient
from app.main import app

RAW = open('../demo/unseen_vendor_config.txt', 'rb').read()

with TestClient(app) as c:
    tok = c.post('/login', json={'username': 'admin', 'password': 'admin'}).json()['token']
    h = {'Authorization': f'Bearer {tok}'}

    # 1. FIRST ingest: unknown
    files = {'file': ('unseen_vendor_config.txt', RAW, 'text/plain')}
    r1 = c.post('/ingest', files=files, data={'device_id': 'demo-flow'}, headers=h).json()
    print('1) first ingest:  vendor=%s unknown=%s trainable=%s unrecognized=%d next=%s' % (
        r1['vendor'], r1['is_unknown_vendor'], r1['trainable'], r1['unparsed_count'], r1['next_step']))

    # 2. TRAIN on the data (one click)
    t = c.post('/training/train-device', json={'device_id': 'demo-flow', 'confirmed_by': 'admin'}, headers=h).json()
    print('2) trained:       learned=%d already_known=%d' % (t['trained_lines'], t['already_learned']))

    # 3. SECOND ingest of the SAME file: now known
    files = {'file': ('unseen_vendor_config.txt', RAW, 'text/plain')}
    r2 = c.post('/ingest', files=files, data={'device_id': 'demo-flow'}, headers=h).json()
    print('3) re-ingest:     next=%s recognized=%d/%d' % (
        r2['next_step'], r2.get('recognized_count', 0), r2['unparsed_count']))

    # 4. Training queue should no longer ask about these lines
    q = c.get('/training/queue', headers=h).json()
    demo_lines = [e for e in q['queue'] if e['device_id'] == 'demo-flow']
    print('4) queue for this device after training: %d (should be 0)' % len(demo_lines))

    # 5. FULL AUDIT now runs
    a = c.post('/audit/demo-flow', headers=h).json()
    s = a['summary']
    print('5) audit:         rules=%d pass=%d fail=%d pct=%s' % (s['total_rules'], s['pass_count'], s['fail_count'], s['compliance_pct']))
    src = set(f['source'] for f in a['findings'])
    print('6) finding sources:', src)
    fails = [f['rule_id'] for f in a['findings'] if f['status'] == 'fail']
    print('7) failed rules:', fails)
    print('8) unmapped lines remaining:', a['unparsed_count'])
