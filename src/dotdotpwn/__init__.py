"""
DotDotPwn - The Directory Traversal Fuzzer (Python Implementation)

This is a complete Python reimplementation of the original DotDotPwn Perl tool
with added API capabilities for GUI integration.

Original Authors: chr1x & nitr0us
Python Implementation: AI Assistant

License: GPL-3.0-or-later
"""

__version__ = "3.0.2"
__author__ = "chr1x & nitr0us (Original), AI Assistant (Python Implementation)"
__license__ = "GPL-3.0-or-later"

from .core.traversal_engine import TraversalEngine, OSType, DetectionMethod
from .core.fingerprint import Fingerprint
from .core.bisection_algorithm import BisectionAlgorithm
from .protocols.http_fuzzer import HTTPFuzzer
from .protocols.ftp_fuzzer import FTPFuzzer
from .protocols.tftp_fuzzer import TFTPFuzzer
from .protocols.payload_fuzzer import PayloadFuzzer
from .protocols.http_url_fuzzer import HTTPURLFuzzer
from .utils.reporter import Reporter
from .stdout import STDOUTHandler, OutputMode, get_stdout_handler

__all__ = [
    "TraversalEngine",
    "OSType",
    "Fingerprint", 
    "BisectionAlgorithm",
    "HTTPFuzzer",
    "FTPFuzzer", 
    "TFTPFuzzer",
    "PayloadFuzzer",
    "HTTPURLFuzzer",
    "Reporter",
    "STDOUTHandler",
    "OutputMode", 
    "get_stdout_handler",
]