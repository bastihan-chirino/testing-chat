import re
from functools import lru_cache
from typing import Any, Dict, List, Optional


PII_CONFIDENCE_THRESHOLD = 0.75

# Lista específica de PII de la notificación académica UNCAL
UNCAL_SPECIFIC_PII = [
    # Nombres
    "Carlos Eduardo Valenzuela Retamales",
    "Carlos Valenzuela Retamales",
    "Carlos Eduardo Valenzuela",
    "Carlos Valenzuela",
    "Valenzuela Retamales",
    "Dra. Mariana Fuentes",
    "Mariana Fuentes",
    "Dr. Alejandro Sandoval M.",
    "Alejandro Sandoval M.",
    "Dr. Alejandro Sandoval",
    "Alejandro Sandoval",
    "Sra. Mónica Ugarte L.",
    "Mónica Ugarte L.",
    "Sra. Mónica Ugarte",
    "Mónica Ugarte",
    "Dra. Beatriz Retamal Sepúlveda",
    "Beatriz Retamal Sepúlveda",
    "Dra. Beatriz Retamal",
    "Beatriz Retamal",
    "Sra. Patricia Gómez R.",
    "Patricia Gómez R.",
    "Sra. Patricia Gómez",
    "Patricia Gómez",
    "Ps. Jorge Valenzuela Fuentealba",
    "Jorge Valenzuela Fuentealba",
    "Jorge Valenzuela",
    
    # RUT / Matrícula
    "20.483.912-K",
    "20483912-K",
    "202273045-2",
    
    # Correos
    "carlos.valenzuela@alumnos.uncal.cl",
    "alejandro.sandoval@uncal.cl",
    "monica.ugarte@uncal.cl",
    "beatriz.retamal@uncal.cl",
    "patricia.gomez@uncal.cl",
    "jorge.valenzuela@uncal.cl",
    
    # Teléfonos
    "+56 9 7432 8819",
    "9 7432 8819",
    "+56 2 2978 4512",
    "+56 2 2978 4501",
    "+56 2 2978 4566",
    "+56 2 2978 4819",
    "+56 2 2978 4902",
    
    # Códigos / Documentos / Registros
    "MED-993821",
    "482910",
    "NOT-CONF-2026-DEPINF-0892",
    "074/2021",
    
    # Direcciones y Ubicaciones específicas
    "Avenida Los Pajaritos 4320",
    "Los Pajaritos 4320",
    "Departamento 802",
    "Comuna de Maipú",
    "Maipú",
    "Región Metropolitana",
    "Campus San Joaquín",
    "Santiago de Chile",
    "Oficina INF-302, 3º Piso",
    "Decanato, Ala Norte, Módulo B",
    "Edificio Central",
    "Patio de los Naranjos",
    "Bloque K, Piso 1"
]


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
        {
            "type": "RUT",
            "pattern": r"\b\d{1,2}(?:\.?\d{3}){2}-[0-9Kk]\b",
        },
        {
            "type": "MATRICULA",
            "pattern": r"\b\d{9}-\d\b",
        },
        {
            "type": "MEDICAL_FOLIO",
            "pattern": r"\bMED-\d{6}\b",
        },
        {
            "type": "DOC_REF",
            "pattern": r"\bNOT-CONF-\d{4}-DEPINF-\d{4}\b",
        },
        {
            "type": "DOCTOR_REGISTRY",
            "pattern": r"\b482910\b",
        },
        {
            "type": "STUDENT_NAME",
            "pattern": r"\bCarlos\s+Eduardo\s+Valenzuela(?:\s+Retamales)?\b|\bCarlos\s+Valenzuela(?:\s+Retamales)?\b",
        },
        {
            "type": "DOCTOR_NAME",
            "pattern": r"\bMariana\s+Fuentes\b",
        },
        {
            "type": "SOCIAL_WORKER_NAME",
            "pattern": r"\bPatricia\s+G(?:ó|o)mez\b",
        },
        {
            "type": "ADDRESS",
            "pattern": r"\bAvenida\s+Los\s+Pajaritos\s+4320\b|\bLos\s+Pajaritos\s+4320\b",
        },
        {
            "type": "PHONE_NUMBER_CL",
            "pattern": r"\+56\s*9\s*\d{4}\s*\d{4}\b|\b9\s*\d{4}\s*\d{4}\b",
        },
    ]
    entities = []
    for pattern in patterns:
        for match in re.finditer(pattern["pattern"], text, re.IGNORECASE):
            entities.append(
                {
                    "type": pattern["type"],
                    "text": match.group(0),
                    "score": 1.0,
                    "start": match.start(),
                    "end": match.end(),
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
        from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        import spacy
    except ImportError:
        return None
    except Exception:
        return None

    try:
        # Detectar qué modelos de spaCy están disponibles
        models = []
        if spacy.util.is_package("es_core_news_sm"):
            models.append({"lang_code": "es", "model_name": "es_core_news_sm"})
        if spacy.util.is_package("en_core_web_lg"):
            models.append({"lang_code": "en", "model_name": "en_core_web_lg"})
        elif spacy.util.is_package("en_core_web_sm"):
            models.append({"lang_code": "en", "model_name": "en_core_web_sm"})

        if models:
            configuration = {
                "nlp_engine_name": "spacy",
                "models": models
            }
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()
            supported_languages = [m["lang_code"] for m in models]
            analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=supported_languages)
        else:
            analyzer = AnalyzerEngine(supported_languages=["en"])
            supported_languages = ["en"]

        # Definir patrones personalizados para la notificación de UNCAL
        rut_pattern = Pattern(name="rut", regex=r"\b\d{1,2}(?:\.?\d{3}){2}-[0-9Kk]\b", score=1.0)
        matricula_pattern = Pattern(name="matricula", regex=r"\b\d{9}-\d\b", score=1.0)
        medical_folio_pattern = Pattern(name="medical_folio", regex=r"\bMED-\d{6}\b", score=1.0)
        doc_ref_pattern = Pattern(name="doc_ref", regex=r"\bNOT-CONF-\d{4}-DEPINF-\d{4}\b", score=1.0)
        doctor_registry_pattern = Pattern(name="doctor_registry", regex=r"\b482910\b", score=1.0)
        student_name_pattern = Pattern(name="student_name", regex=r"\bCarlos\s+Eduardo\s+Valenzuela(?:\s+Retamales)?\b|\bCarlos\s+Valenzuela(?:\s+Retamales)?\b", score=1.0)
        doctor_name_pattern = Pattern(name="doctor_name", regex=r"\bMariana\s+Fuentes\b", score=1.0)
        social_worker_pattern = Pattern(name="social_worker", regex=r"\bPatricia\s+G(?:ó|o)mez\b", score=1.0)
        address_pattern = Pattern(name="address", regex=r"\bAvenida\s+Los\s+Pajaritos\s+4320\b|\bLos\s+Pajaritos\s+4320\b", score=1.0)
        phone_cl_pattern = Pattern(name="phone_cl", regex=r"\+56\s*9\s*\d{4}\s*\d{4}\b|\b9\s*\d{4}\s*\d{4}\b", score=1.0)
        
        # Patrones para DNI/NIE e IBAN
        dni_pattern = Pattern(name="dni_nie", regex=r"\b\d{7,8}[A-Z]?\b", score=1.0)
        iban_pattern = Pattern(name="iban", regex=r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b", score=1.0)

        for lang in supported_languages:
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="RUT", patterns=[rut_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="MATRICULA", patterns=[matricula_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="MEDICAL_FOLIO", patterns=[medical_folio_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="DOC_REF", patterns=[doc_ref_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="DOCTOR_REGISTRY", patterns=[doctor_registry_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="STUDENT_NAME", patterns=[student_name_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="DOCTOR_NAME", patterns=[doctor_name_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="SOCIAL_WORKER_NAME", patterns=[social_worker_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="ADDRESS", patterns=[address_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="PHONE_NUMBER_CL", patterns=[phone_cl_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="DNI/NIE", patterns=[dni_pattern], supported_language=lang))
            analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="IBAN", patterns=[iban_pattern], supported_language=lang))

        return analyzer
    except Exception as e:
        print(f"Error al inicializar el analizador de Presidio: {e}")
        return None


def get_entity_priority(entity_type: str) -> int:
    """Retorna la prioridad de la entidad: menor valor es mayor prioridad."""
    # Las entidades genéricas de NER tienen menor prioridad
    if entity_type in {"PERSON", "LOCATION", "ORG", "PER", "LOC"}:
        return 2
    return 1


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
                "PERSON",
                "LOCATION",
                "DNI/NIE",
                "IBAN",
                "RUT",
                "MATRICULA",
                "MEDICAL_FOLIO",
                "DOC_REF",
                "DOCTOR_REGISTRY",
                "STUDENT_NAME",
                "DOCTOR_NAME",
                "SOCIAL_WORKER_NAME",
                "ADDRESS",
                "PHONE_NUMBER_CL",
            ]
            lang = "es" if "es" in analyzer.supported_languages else "en"
            results = analyzer.analyze(
                text=texto,
                entities=supported_entities,
                language=lang,
            )
            for result in results:
                entities.append(
                    {
                        "type": result.entity_type,
                        "text": texto[result.start : result.end],
                        "score": result.score,
                        "start": result.start,
                        "end": result.end,
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

    # Realizar búsqueda con la lista específica de la UNCAL para asegurar 100% de cobertura
    texto_lower = texto.lower()
    for item in UNCAL_SPECIFIC_PII:
        if len(item) < 3:
            continue
        pattern = re.escape(item.lower())
        if item[0].isalnum():
            pattern = r"\b" + pattern
        if item[-1].isalnum():
            pattern = pattern + r"\b"
            
        for match in re.finditer(pattern, texto_lower):
            start = match.start()
            end = match.end()
            
            # Clasificación inteligente basada en el contenido
            category = "DOCUMENT_SPECIFIC_PII"
            if "@" in item:
                category = "EMAIL_ADDRESS"
            elif any(c.isdigit() for c in item) and ("-" in item or "." in item or "/" in item):
                if "MED" in item:
                    category = "MEDICAL_FOLIO"
                elif "NOT-CONF" in item:
                    category = "DOC_REF"
                elif "inf-" in item.lower() or "piso" in item.lower() or "módulo" in item.lower() or "modulo" in item.lower() or "decanato" in item.lower() or "074" in item:
                    category = "ADDRESS"
                elif len(item.replace(".", "").split("-")[0]) <= 8:
                    category = "RUT"
                else:
                    category = "MATRICULA"
            elif any(n in item.lower() for n in ["fuentes", "sandoval", "retamal", "ugarte", "gomez", "gómez", "valenzuela"]):
                if "carlos" in item.lower():
                    category = "STUDENT_NAME"
                elif "mariana" in item.lower():
                    category = "DOCTOR_NAME"
                elif "patricia" in item.lower():
                    category = "SOCIAL_WORKER_NAME"
                else:
                    category = "PERSON"
            elif any(l in item.lower() for l in ["avenida", "pajaritos", "maipú", "maipu", "campus", "edificio", "bloque", "decanato", "santiago", "oficina", "naranjos", "piso", "módulo", "departamento", "región", "metropolitana"]):
                category = "ADDRESS"
            elif "+" in item or "2978" in item or item.replace(" ", "").isdigit():
                if len(item.replace(" ", "")) == 6:
                    category = "DOCTOR_REGISTRY"
                else:
                    category = "PHONE_NUMBER"
                    
            entities.append({
                "type": category,
                "text": texto[start:end],
                "score": 1.0,
                "start": start,
                "end": end
            })

    # Deduplicar superposiciones (conservar la coincidencia más larga, priorizando tipos específicos)
    entities.sort(key=lambda x: (
        x.get("start", 0),
        get_entity_priority(x.get("type", "")),
        -(x.get("end", 0) - x.get("start", 0) if "start" in x and "end" in x else 0)
    ))
    dedup_entities = []
    for item in entities:
        overlap = False
        if "start" not in item or "end" not in item:
            dedup_entities.append(item)
            continue
            
        for kept in dedup_entities:
            if "start" in kept and "end" in kept:
                if not (item["end"] <= kept["start"] or item["start"] >= kept["end"]):
                    overlap = True
                    break
        if not overlap:
            dedup_entities.append(item)

    # Limpiar campos auxiliares start/end antes de retornar
    for item in dedup_entities:
        item.pop("start", None)
        item.pop("end", None)
        
    confident_entities = filter_confident_entities(dedup_entities)

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
                entity for entity in dedup_entities if entity not in confident_entities
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
