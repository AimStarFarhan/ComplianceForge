from app.core.parsers.base_parser import (
    BaseParser,
    VENDORS,
    VENDOR_CISCO_IOS,
    VENDOR_JUNIPER_SRX,
    VENDOR_SONIC,
    VENDOR_UNSEEN,
    VENDOR_LABELS,
    detect_vendor,
    vendor_from_string,
)
from app.core.parsers.cisco_ios import CiscoIOSParser
from app.core.parsers.juniper_srx import JuniperSRXParser
from app.core.parsers.sonic import SonicParser
from app.core.schema import SecurityBaselineModel

PARSERS = {
    VENDOR_CISCO_IOS: CiscoIOSParser,
    VENDOR_JUNIPER_SRX: JuniperSRXParser,
    VENDOR_SONIC: SonicParser,
}


def get_parser(vendor: str) -> BaseParser | None:
    cls = PARSERS.get(vendor)
    return cls() if cls else None


def parse_any(vendor: str, config_text: str, device_id: str) -> SecurityBaselineModel:
    parser = get_parser(vendor)
    if parser is None:
        raise ValueError(f"No parser registered for vendor '{vendor}'")
    return parser.parse(config_text, device_id)
