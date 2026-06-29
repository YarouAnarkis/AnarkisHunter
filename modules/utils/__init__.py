"""AnarkisHunter — modules/utils/__init__.py"""
from .report import ReportEngine, ScanResult
from .utils_request import HTTPClient, normalize_url, build_url, get_domain
from .utils_payload import payload_manager, PayloadManager
from .utils_wordlist import wordlist_manager, WordlistManager

# v3.0 — New modules
from .utils_evasion import EvasionEngine, evasion_engine, get_evasion_engine
from .utils_heuristic import HeuristicAnalyzer, heuristic_analyzer
from .utils_oob import OOBListener, oob_listener, get_oob_listener
from .utils_autologin import AutoLoginHandler, LoginResult, LoginForm
from .utils_template import TemplateEngine, TemplateResult
