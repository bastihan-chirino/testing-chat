import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "content"))

from conversation_store import add_conversation_event, load_conversations, save_conversations
from prompt_handler import should_process_new_prompt


class ConversationStoreTests(unittest.TestCase):
    def test_save_and_load_conversations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "conversations.json")
            messages = [
                {"role": "user", "content": "hola"},
                {"role": "assistant", "content": "hola, ¿en qué te ayudo?"},
            ]

            save_conversations(messages, file_path)
            loaded = load_conversations(file_path)

            self.assertEqual(len(loaded), len(messages))
            self.assertTrue(all("timestamp" in item for item in loaded))
            self.assertTrue(all("id" in item for item in loaded))
            self.assertEqual([item["id"] for item in loaded], [1, 2])
            self.assertTrue(os.path.exists(file_path))

    def test_add_conversation_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "conversation.json")
            messages = [{"role": "user", "content": "hola"}]

            add_conversation_event(messages, {"content": "blocked", "event_type": "pii_blocked"}, file_path)
            loaded = load_conversations(file_path)

            self.assertEqual(len(loaded), 2)
            self.assertEqual(loaded[-1]["event_type"], "pii_blocked")
            self.assertEqual([item["id"] for item in loaded], [1, 2])

    def test_add_multiple_pii_events_preserves_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "conversation.json")
            messages = []

            add_conversation_event(
                messages,
                {
                    "content": "Se bloqueo un mensaje por informacion personal detectada.",
                    "event_type": "pii_blocked",
                    "details": {"prompt": "correo: persona@example.com"},
                },
                file_path,
            )
            add_conversation_event(
                messages,
                {
                    "content": "Se reintento un mensaje tras una deteccion de PII.",
                    "event_type": "retry_after_pii",
                    "details": {"original_prompt": "correo: persona@example.com"},
                },
                file_path,
            )

            loaded = load_conversations(file_path)

            self.assertEqual(len(loaded), 2)
            self.assertEqual(
                [item["event_type"] for item in loaded],
                ["pii_blocked", "retry_after_pii"],
            )
            self.assertEqual(loaded[0]["details"]["prompt"], "correo: persona@example.com")
            self.assertEqual(
                loaded[1]["details"]["original_prompt"],
                "correo: persona@example.com",
            )
            self.assertEqual([item["id"] for item in loaded], [1, 2])

    def test_should_process_new_prompt_ignores_stale_input_while_pending(self) -> None:
        self.assertFalse(should_process_new_prompt("mensaje con pii", "mensaje pendiente"))
        self.assertTrue(should_process_new_prompt("mensaje nuevo", None))


if __name__ == "__main__":
    unittest.main()
