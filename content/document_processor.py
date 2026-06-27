from typing import Dict, List


def extract_text_from_file(file) -> str:
    """Extrae texto de un archivo cargado (TXT, PDF, DOCX o MD)."""
    try:
        if file.name.endswith((".txt", ".md")):
            return file.getvalue().decode("utf-8")

        if file.name.endswith(".pdf"):
            try:
                import PyPDF2

                pdf_reader = PyPDF2.PdfReader(file)
                text = ""
                for page in pdf_reader.pages:
                    text += (page.extract_text() or "") + "\n"
                return text
            except ImportError:
                return "[PDF detectado pero PyPDF2 no está instalado. Instala: pip install PyPDF2]"

        if file.name.endswith(".docx"):
            try:
                from docx import Document

                doc = Document(file)
                return "\n".join(paragraph.text for paragraph in doc.paragraphs)
            except ImportError:
                return "[DOCX detectado pero python-docx no está instalado. Instala: pip install python-docx]"

        return f"[Formato de archivo no soportado: {file.name}]"

    except Exception as e:
        return f"[Error al procesar archivo: {str(e)}]"


def format_documents_context(documents: List[Dict[str, str]]) -> str:
    """Formatea documentos cargados en un string de contexto para la IA."""
    if not documents:
        return ""

    context = "\n\n--- CONTEXTO DE DOCUMENTOS CARGADOS ---\n"
    for i, doc in enumerate(documents, 1):
        content = doc["content"]
        if len(content) > 1000:
            content = f"{content[:1000]}..."
        context += f"\n[Documento {i}: {doc['name']}]\n{content}\n"
    context += "\n--- FIN CONTEXTO ---\n\n"
    return context
