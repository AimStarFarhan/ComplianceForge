"""Verify detect_vendor on ALL fixtures: known vendors detect correctly,
demo unknowns route to unseen_vendor."""
from pathlib import Path

from app.core.parsers.base_parser import detect_vendor

ROOT = Path(__file__).resolve().parent.parent.parent  # complianceforge/

FILES = {
    "backend/sample_configs/cisco_ios_compliant.cfg": "cisco_ios",
    "backend/sample_configs/cisco_ios_noncompliant.cfg": "cisco_ios",
    "backend/sample_configs/juniper_srx_compliant.cfg": "juniper_srx",
    "backend/sample_configs/juniper_srx_noncompliant.cfg": "juniper_srx",
    "backend/sample_configs/sonic_compliant.cfg": "sonic",
    "backend/sample_configs/sonic_noncompliant.cfg": "sonic",
    "demo/golden_config_100_percent.cfg": "cisco_ios",
    "demo/unseen_vendor_config.txt": "unseen_vendor",
    "demo/demo_unknown_A_branch_switch.txt": "unseen_vendor",
    "demo/demo_unknown_B_firewall.txt": "unseen_vendor",
    "demo/demo_unknown_C_wan_router.txt": "unseen_vendor",
}

ok = True
for rel, want in FILES.items():
    p = ROOT / rel
    text = p.read_text(encoding="utf-8")
    got = detect_vendor(text, p.name)
    good = got == want
    ok &= good
    print("%s %-38s -> %-14s (want %s)" % ("OK  " if good else "FAIL", p.name, got, want))

print("ALL CORRECT" if ok else "REGRESSIONS FOUND")
raise SystemExit(0 if ok else 1)
