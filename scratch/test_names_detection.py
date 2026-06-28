import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "content"))
from pii_detector import detect_pii

text = "Ps. Jorge Valenzuela Fuentealba, Sra. Patricia Gómez R., Dra. Beatriz Retamal Sepúlveda, Sra. Mónica Ugarte L., Dr. Alejandro Sandoval M"
res = detect_pii(text)
print("Found PII?", res["found"])
print("Entities detected:")
for e in res["entities"]:
    print(f"Type: {e['type']}, Text: '{e['text']}', Score: {e['score']}")
