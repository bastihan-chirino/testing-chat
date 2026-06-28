from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

def test():
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "es", "model_name": "es_core_news_sm"}]
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["es"])

    text = "Ps. Jorge Valenzuela Fuentealba, Sra. Patricia Gómez R., Dra. Beatriz Retamal Sepúlveda, Sra. Mónica Ugarte L., Dr. Alejandro Sandoval M"
    results = analyzer.analyze(text=text, entities=["PERSON"], language="es")
    for r in results:
        print(f"Match: '{text[r.start:r.end]}', Entity: {r.entity_type}, Score: {r.score}")

test()
