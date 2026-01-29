"""Registry of available sub-scans.

Names are the module-like filenames (without .py), matching the user request.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from .core.base_check import BaseCheck

from .network.port_scanner_aggressive import PortScannerAggressive
from .network.default_services_detection import DefaultServicesDetection
from .network.open_services_exposure import OpenServicesExposure
from .network.banner_analysis import BannerAnalysis
from .network.smb_ftp_etc_detection import SMBFTPEtcDetection

from .web.headers_security_check import HeadersSecurityCheck
from .web.cookie_flags_aggressive import CookieFlagsAggressive
from .web.http_methods_aggressive import HTTPMethodsAggressive
from .web.directory_listing_detection import DirectoryListingDetection
from .web.verbose_error_detection import VerboseErrorDetection
from .web.sensitive_files_probing import SensitiveFilesProbing
from .web.common_directories_fuzzing import CommonDirectoriesFuzzing
from .web.xxe_probing import XXEProbing
from .web.active_debug_detection import ActiveDebugDetection
from .web.cloud_storage_permissions import CloudStoragePermissions
from .web.unencrypted_transmission import UnencryptedTransmission


CHECKS: Dict[str, Type[BaseCheck]] = {
    # Network - Configuration des services
    "port_scanner_aggressive": PortScannerAggressive,
    "default_services_detection": DefaultServicesDetection,
    "open_services_exposure": OpenServicesExposure,
    "banner_analysis": BannerAnalysis,
    "smb_ftp_etc_detection": SMBFTPEtcDetection,

    # Web - Headers & Cookies (CWE-614, CWE-942, CWE-1004, CWE-315)
    "headers_security_check": HeadersSecurityCheck,
    "cookie_flags_aggressive": CookieFlagsAggressive,

    # Web - Configuration HTTP (CWE-16)
    "http_methods_aggressive": HTTPMethodsAggressive,
    "directory_listing_detection": DirectoryListingDetection,

    # Web - Erreurs & Information Disclosure (CWE-537, CWE-756, CWE-260, CWE-526)
    "verbose_error_detection": VerboseErrorDetection,
    "sensitive_files_probing": SensitiveFilesProbing,
    "common_directories_fuzzing": CommonDirectoriesFuzzing,

    # Web - XML Configuration (CWE-611, CWE-776)
    "xxe_probing": XXEProbing,

    # OWASP A02:2025 - Nouveaux CWEs
    "active_debug_detection": ActiveDebugDetection,  # CWE-489, CWE-11
    "cloud_storage_permissions": CloudStoragePermissions,  # CWE-16, CWE-15, Scenario #4
    "unencrypted_transmission": UnencryptedTransmission,  # CWE-5
}


def all_checks() -> List[Type[BaseCheck]]:
    return list(CHECKS.values())


def get_check_by_name(name: str) -> Optional[Type[BaseCheck]]:
    if name == "__list__":
        return list(CHECKS.keys())  # type: ignore[return-value]
    return CHECKS.get(name)
