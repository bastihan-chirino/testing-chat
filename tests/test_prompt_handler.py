import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "content"))

from prompt_handler import decide_prompt_action


class PromptHandlerTests(unittest.TestCase):
    def test_warns_when_pii_is_detected(self) -> None:
        result = decide_prompt_action("Mi correo es juan@example.com")

        self.assertEqual(result["action"], "warn")
        self.assertTrue(result["pii_check"]["found"])

    def test_allows_processing_when_override_is_enabled(self) -> None:
        result = decide_prompt_action("Mi correo es juan@example.com", allow_pii=True)

        self.assertEqual(result["action"], "send")
        self.assertTrue(result["pii_check"]["found"])


if __name__ == "__main__":
    unittest.main()
