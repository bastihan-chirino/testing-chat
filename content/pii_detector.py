import re
from functools import lru_cache
from typing import Any, Dict, List, Optional


PII_CONFIDENCE_THRESHOLD = 0.75


def simple_regex_pii(text: str) -> List[Dict[str, Any]]:
    """Busca patrones comunes de PII con regex como fallback."""
    patterns = [
        {
            "type": "EMAIL_ADDRESS",
            "pattern": r"[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}",
        },
        {
            "type": "PHONE_NUMBER",
            "pattern": r"\b(?:\+\d{1,3}[\s-]?)?(?:\d{2,4}[\s-]?){2,4}\d{2,4}\b",
        },
        {
            "type": "DNI/NIE",
            "pattern": r"\b\d{7,8}[A-Z]?\b",
        },
        {
            "type": "CREDIT_CARD",
            "pattern": r"\b(?:\d[ -]*?){13,16}\b",
        },
        {
            "type": "IBAN",
            "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b",
        },
        {
            "type": "IP_ADDRESS",
            "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        },
    ]
    entities = []
    for pattern in patterns:
        for match in re.finditer(pattern["pattern"], text):
            entities.append(
                {
                    "type": pattern["type"],
                    "text": match.group(0),
                    "score": 1.0,
                }
            )
    return entities


def filter_confident_entities(
    entities: List[Dict[str, Any]],
    threshold: float = PII_CONFIDENCE_THRESHOLD,
) -> List[Dict[str, Any]]:
    """Devuelve solo entidades con confianza suficiente para actuar."""
    return [entity for entity in entities if entity.get("score", 0) >= threshold]


@lru_cache(maxsize=1)
def build_presidio_analyzer() -> Optional[object]:
    """Construye un AnalyzerEngine una sola vez para evitar lentitud por mensaje."""
    try:
        from presidio_analyzer import AnalyzerEngine
    except ImportError:
        return None
    except Exception:
        return None

    try:
        return AnalyzerEngine(supported_languages=["en"])
    except Exception:
        return None


def detect_pii(texto: str) -> Dict[str, Any]:
    """Detecta información personal identificable en el texto."""
    entities = []
    fallback_used = False

    analyzer = build_presidio_analyzer()
    if analyzer:
        try:
            supported_entities = [
                "PHONE_NUMBER",
                "EMAIL_ADDRESS",
                "CREDIT_CARD",
                "IP_ADDRESS",
                "URL",
            ]
            results = analyzer.analyze(
                text=texto,
                entities=supported_entities,
                language="en",
            )
            for result in results:
                entities.append(
                    {
                        "type": result.entity_type,
                        "text": texto[result.start : result.end],
                        "score": result.score,
                    }
                )
        except Exception:
            fallback_used = True
            entities = simple_regex_pii(texto)
    else:
        fallback_used = True
        entities = simple_regex_pii(texto)

    if not entities and not fallback_used:
        entities = simple_regex_pii(texto)
        fallback_used = True

    confident_entities = filter_confident_entities(entities)

    if confident_entities:
        summary = (
            f"Se detectaron {len(confident_entities)} posibles datos sensibles: "
            f"{', '.join(sorted(set(e['type'] for e in confident_entities)))}. "
            "No se enviará esta información a la IA para proteger datos sensibles "
            "y evitar posibles filtraciones."
        )
        if fallback_used:
            summary += " (detección basada en regex de fallback)"
        debug = "Presidio" if not fallback_used else "Fallback regex"
        return {
            "found": True,
            "entities": confident_entities,
            "ignored_entities": [
                entity for entity in entities if entity not in confident_entities
            ],
            "summary": summary,
            "debug": debug,
        }

    debug = "Presidio sin entidades" if not fallback_used else "Fallback regex sin entidades"
    return {"found": False, "entities": [], "summary": "No se detectó PII", "debug": debug}


def check_documents_pii(documents: List[Dict[str, str]]) -> Dict[str, Any]:
    """Revisa si hay PII en los documentos cargados."""
    results = {}
    total_found = False

    for doc in documents:
        detection = detect_pii(doc["content"])
        if detection["found"]:
            total_found = True
        results[doc["name"]] = detection

    return {"documents": results, "has_pii": total_found}
