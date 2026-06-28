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
                self.assertIn("PERSON", entity_types)

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

    def test_detects_doctor_registry(self) -> None:
        res = detect_pii("Su registro médico es 482910")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("DOCTOR_REGISTRY", entity_types)
        self.assertNotIn("PHONE_NUMBER", entity_types)

    def test_detects_doctor_name(self) -> None:
        res = detect_pii("Emitido por la Dra. Mariana Fuentes")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("PERSON", entity_types)

    def test_detects_social_worker_name(self) -> None:
        res = detect_pii("Contactar a Patricia Gómez R.")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("PERSON", entity_types)

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
    def test_detects_general_name(self) -> None:
        res = detect_pii("Hola, mi nombre es Juan Pérez", enable_presidio=True)
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("PERSON", entity_types)

    def test_detects_general_location(self) -> None:
        res = detect_pii("Viajo a Madrid mañana", enable_presidio=True)
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("LOCATION", entity_types)

    def test_ignores_phone_without_plus(self) -> None:
        res = detect_pii("Mi número es 9 7432 8819")
        if res["found"]:
            entity_types = {e["type"] for e in res["entities"]}
            self.assertNotIn("PHONE_NUMBER", entity_types)
            self.assertNotIn("PHONE_NUMBER_CL", entity_types)
    def test_detects_all_uncal_names(self) -> None:
        names = [
            "Ps. Jorge Valenzuela Fuentealba",
            "Jorge Valenzuela Fuentealba",
            "Jorge Valenzuela",
            "Dra. Beatriz Retamal Sepúlveda",
            "Beatriz Retamal Sepúlveda",
            "Dra. Beatriz Retamal",
            "Beatriz Retamal",
            "Sra. Mónica Ugarte L.",
            "Mónica Ugarte L.",
            "Sra. Mónica Ugarte",
            "Mónica Ugarte",
            "Dr. Alejandro Sandoval M.",
            "Dr Alejandro Sandoval M",
            "Alejandro Sandoval M.",
            "Dr. Alejandro Sandoval",
            "Alejandro Sandoval"
        ]
        for name in names:
            with self.subTest(name=name):
                res = detect_pii(name)
                self.assertTrue(res["found"])
                entity_types = {e["type"] for e in res["entities"]}
                self.assertIn("PERSON", entity_types)

    def test_detects_pii_with_line_skips(self) -> None:
        res = detect_pii("El alumno es Carlos\nEduardo\nValenzuela Retamales.")
        self.assertTrue(res["found"])
        entity_types = {e["type"] for e in res["entities"]}
        self.assertIn("PERSON", entity_types)
    def test_detects_office_numbers_and_resolucion(self) -> None:
        res1 = detect_pii("Llama a la oficina +56 2 2978 4512.")
        self.assertTrue(res1["found"])
        self.assertIn("PHONE_NUMBER", {e["type"] for e in res1["entities"]})

        res2 = detect_pii("La resolución exenta es la 074/2021.")
        self.assertTrue(res2["found"])
        self.assertIn("DOC_REF", {e["type"] for e in res2["entities"]})

        res3 = detect_pii("+56229784902 es el número administrativo")
        self.assertTrue(res3["found"])
        self.assertIn("PHONE_NUMBER", {e["type"] for e in res3["entities"]})
    def test_ignores_non_pii_locations(self) -> None:
        non_pii = [
            "Bloque K, Piso 1",
            "Decanato, Ala Norte, Módulo B",
            "Departamento 802",
            "Edificio Central",
            "Maipú",
            "Oficina INF-302, 3º Piso"
        ]
        for text in non_pii:
            with self.subTest(text=text):
                res = detect_pii(text)
                self.assertFalse(res["found"])


if __name__ == "__main__":
    unittest.main()
