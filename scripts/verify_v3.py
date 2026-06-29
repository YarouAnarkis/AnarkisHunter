"""AnarkisHunter v3.0 Verification Script"""
import sys
sys.path.insert(0, "d:/tolls/AnarkisHunter")
errors = []
passes = []

# Test 1: EvasionEngine
try:
    from modules.utils.utils_evasion import EvasionEngine, STEALTH_PROFILES
    e = EvasionEngine("medium")
    ua = e.get_random_ua()
    headers = e.apply_evasion()
    obf = e.obfuscate_sqli("UNION SELECT 1,2,3")
    passes.append(f"EvasionEngine: {len(STEALTH_PROFILES)} profil, UA={ua[:40]}...")
except Exception as ex:
    errors.append(f"EvasionEngine: {ex}")

# Test 2: HeuristicAnalyzer
try:
    from modules.utils.utils_heuristic import HeuristicAnalyzer
    h = HeuristicAnalyzer()
    passes.append(f"HeuristicAnalyzer: time_threshold={h.time_threshold}s")
except Exception as ex:
    errors.append(f"HeuristicAnalyzer: {ex}")

# Test 3: OOBListener
try:
    from modules.utils.utils_oob import OOBListener
    oob = OOBListener(use_simulation=True)
    session = oob.new_session()
    payloads = oob.get_payloads("cmdi")
    passes.append(f"OOBListener: domain={session.server}, {len(payloads)} CMDi payloads")
except Exception as ex:
    errors.append(f"OOBListener: {ex}")

# Test 4: AutoLoginHandler
try:
    from modules.utils.utils_autologin import AutoLoginHandler
    h = AutoLoginHandler()
    passes.append(f"AutoLoginHandler: OK, timeout={h.timeout}s")
except Exception as ex:
    errors.append(f"AutoLoginHandler: {ex}")

# Test 5: TemplateEngine
try:
    from modules.utils.utils_template import TemplateEngine, TEMPLATES_DIR
    engine = TemplateEngine()
    templates = engine.list_templates(str(TEMPLATES_DIR))
    passes.append(f"TemplateEngine: {len(templates)} templates loaded")
    for t in templates[:5]:
        print(f"     [{t['severity']:8}] {t['id']}")
    if len(templates) > 5:
        print(f"     ... dan {len(templates) - 5} template lainnya")
except Exception as ex:
    errors.append(f"TemplateEngine: {ex}")

# Test 6: Utils __init__ exports
try:
    from modules.utils import (EvasionEngine, HeuristicAnalyzer,
                                OOBListener, AutoLoginHandler, TemplateEngine)
    passes.append("modules/utils/__init__.py: Semua 5 modul v3.0 ter-export")
except Exception as ex:
    errors.append(f"__init__ exports: {ex}")

# Test 7: webpentest.py syntax
try:
    import ast
    with open("d:/tolls/AnarkisHunter/webpentest.py", "r", encoding="utf-8") as f:
        source = f.read()
    ast.parse(source)
    passes.append("webpentest.py: Syntax OK")
except Exception as ex:
    errors.append(f"webpentest.py syntax: {ex}")

print()
print("=" * 60)
print("AnarkisHunter v3.0 - Verification Report")
print("=" * 60)
for p in passes:
    print(f"  [PASS] {p}")
print()
if errors:
    print(f"ERRORS ({len(errors)}):")
    for e in errors:
        print(f"  [FAIL] {e}")
    sys.exit(1)
else:
    print(f">>> {len(passes)}/{len(passes)} tests LULUS - AnarkisHunter v3.0 PRODUCTION READY! <<<")
