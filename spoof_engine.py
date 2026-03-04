"""DNS amplification spoof engine -- Layer-3 IP spoofing via Scapy."""

import os
import sys


def _is_root():
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.getuid() == 0