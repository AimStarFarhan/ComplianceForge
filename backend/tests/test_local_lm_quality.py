"""Test local-LM classification quality end to end."""
from app.core.ai_classifier import get_classifier
import time

c = get_classifier()
tests = [
    'disable secure-shell protocol-2 enforcement',
    'monitor protocol snmp read-string "public-string"',
    'event-log forward destination 192.0.2.99 minimum-severity debug',
    'service telnet daemon-start auto',
    'tls profile cipher enable des-cbc-md5 legacy',
    'local-account admin password-strength minimum',
]
for line in tests:
    t0 = time.time()
    r = c.classify(line)
    print("%-58s -> %-18s (src=%s conf=%.2f) [%.1fs]" % (
        line[:58], r["category"], r["source"], r["confidence"], time.time() - t0))
