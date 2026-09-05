"""Manual verification: the full learn-a-new-vendor loop."""
from fastapi.testclient import TestClient
from app.main import app

with TestClient(app) as c:
    tok = c.post('/login', json={'username': 'admin', 'password': 'admin'}).json()['token']
    h = {'Authorization': f'Bearer {tok}'}

    files = {'file': ('unseen_vendor_config.txt', open('../demo/unseen_vendor_config.txt', 'rb').read(), 'text/plain')}
    r = c.post('/ingest', files=files, data={'device_id': 'unseen-demo'}, headers=h).json()
    print('1) ingest: vendor=%s queue=%d' % (r['vendor'], r['unparsed_count']))

    a = c.post('/audit/unseen-demo', headers=h).json()
    print('2) audit before training: rules=%d pass=%d fail=%d' % (a['summary']['total_rules'], a['summary']['pass_count'], a['summary']['fail_count']))

    confirms = [
        ('service telnet daemon-start auto', 'management_protocol'),
        ('disable secure-shell protocol-2 enforcement', 'ssh_policy'),
        ('management web-console port 8080 plaintext', 'management_protocol'),
        ('event-log forward destination 192.0.2.99 minimum-severity debug', 'syslog'),
        ('local-account admin password-strength minimum', 'password_policy'),
        ('monitor protocol snmp read-string "public-string"', 'snmp_management'),
        ('clock source ntp primary 10.10.1.1', 'ntp'),
        ('threat-protection profile untrust-zone strict', 'zone_policy'),
        ('tls profile cipher enable des-cbc-md5 legacy', 'cryptography'),
        ('loop-protection service activate', 'service_hardening'),
    ]
    for line, cat in confirms:
        rq = {'example_line': line, 'category': cat, 'confirmed_by': 'admin', 'ai_suggested': True, 'ai_confidence': 0.6}
        rr = c.post('/training/confirm', json=rq, headers=h)
        assert rr.status_code == 200, rr.text
    print('3) trained: %d mappings human-confirmed' % len(confirms))

    a = c.post('/audit/unseen-demo', headers=h).json()
    s = a['summary']
    print('4) audit after training: rules=%d pass=%d fail=%d pct=%s' % (s['total_rules'], s['pass_count'], s['fail_count'], s['compliance_pct']))
    for f in a['findings']:
        if f['status'] == 'fail':
            print('   FAIL %-11s %-55s src=%s' % (f['rule_id'], f['title'][:55], f['source']))
    print('5) sources:', set(f['source'] for f in a['findings']))
    print('6) still-unmapped lines:', a['unparsed_count'])
