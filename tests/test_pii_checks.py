import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "content"))

from pii_detector import detect_pii
from prompt_handler import decide_prompt_action


class PiiChecksTests(unittest.TestCase):
    def test_detects_student_name(self) -> None:
        prompts = [
            "El alumno es Carlos Eduardo Valenzuela Retamales.",
            "Favor revisar el caso de Carlos Valenzuela",
            "¿Cuál es el estado de Carlos Eduardo Valenzuela?",
        ]
        for p in prompts:
            with self.subTest(prompt=p):
                res = detect_pii(p)
                self.assertTrue(res["found"])
                entity_types = {e["type"] for e in res["entities"]}
                self.assertIn("STUDENT_NAME", entity_types)

    def test_detects_rut(self) -> None:
        prompts = [
            "Su RUT es 20.483.912-K.",
            "20483912-K es el rut ficticio",
            "Identificación: 20.483.912-k",
        ]
        for p in prompts:
            with self.subTest(prompt=p):
                res = detect_pii(p)
                self.assertTrue(res["found"])
                entity_types = {e["type"] for e in res["entities"]}
                self.assertIn("RUT", entity_types)

    def test_detects_matricula(self) -> None:
        res = detect_pii("Matrícula 202273045-2")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("MATRICULA", entity_types)

    def test_detects_medical_folio(self) -> None:
        res = detect_pii("El certificado tiene folio MED-993821")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("MEDICAL_FOLIO", entity_types)

    def test_detects_doc_ref(self) -> None:
        res = detect_pii("Documento ref: NOT-CONF-2026-DEPINF-0892")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("DOC_REF", entity_types)

    def test_detects_doctor_name(self) -> None:
        res = detect_pii("Emitido por la Dra. Mariana Fuentes")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("DOCTOR_NAME", entity_types)

    def test_detects_social_worker_name(self) -> None:
        res = detect_pii("Contactar a Patricia Gómez R.")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("SOCIAL_WORKER_NAME", entity_types)

    def test_detects_address(self) -> None:
        res = detect_pii("Vive en Avenida Los Pajaritos 4320, Maipú")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("ADDRESS", entity_types)

    def test_detects_chilean_phone(self) -> None:
        res = detect_pii("Teléfono de contacto es +56 9 7432 8819")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("PHONE_NUMBER_CL", entity_types)


if __name__ == "__main__":
    unittest.main()
