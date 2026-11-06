import unittest

from agentlure.evidence import exit_code_for
class ExitCodeErrorTest(unittest.TestCase):
    def test_error_always_exits_3(self):
        self.assertEqual(exit_code_for("ERROR"), 3)
        self.assertEqual(exit_code_for("ERROR", fail_on="malicious"), 3)
        self.assertEqual(exit_code_for("ERROR", fail_on="suspicious"), 3)
