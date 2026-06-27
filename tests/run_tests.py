"""AnarkisHunter — tests/run_tests.py — Run all unit tests"""
import sys, os, unittest
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1]))

from tests.test_utils import (TestEncoding, TestHashUtils, TestRegexUtils, TestJWTUtils,
    TestRequestUtils, TestWordlistUtils, TestReportEngine, TestDatabase)
from tests.test_exploits import (TestSQLiExploit, TestXSSExploit, TestParameterTampering,
    TestIDORExploit, TestJWTExploit, TestGraphQLExploit)

loader = unittest.TestLoader()
suite = unittest.TestSuite()
for cls in [TestEncoding, TestHashUtils, TestRegexUtils, TestJWTUtils,
    TestRequestUtils, TestWordlistUtils, TestReportEngine, TestDatabase,
    TestSQLiExploit, TestXSSExploit, TestParameterTampering,
    TestIDORExploit, TestJWTExploit, TestGraphQLExploit]:
    suite.addTests(loader.loadTestsFromTestCase(cls))

runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
print(f'\nTests: {result.testsRun} | Failures: {len(result.failures)} | Errors: {len(result.errors)}')
print('STATUS: ALL PASSED' if result.wasSuccessful() else 'STATUS: FAILED')
sys.exit(0 if result.wasSuccessful() else 1)
