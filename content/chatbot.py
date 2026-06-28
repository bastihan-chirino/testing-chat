import argparse
import html
import sys

import streamlit as st

from ai_client import get_ai_response
from conversation_store import (
    add_conversation_event,
    get_default_conversation_path,
    load_conversations,
    save_conversations,
)
from document_processor import extract_text_from_file, format_documents_context
from pii_detector import check_documents_pii, detect_pii
from prompt_handler import decide_prompt_action, should_process_new_prompt


def parse_startup_options() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--disable-pii-warnings",
        action="store_true",
        help="Deshabilita las advertencias emergentes de PII en los mensajes.",
    )
    parser.add_argument(
        "--enable-document-upload",
        action="store_true",
        help="Habilita la subida de documentos desde la barra lateral.",
    )
    parser.add_argument(
        "--enable-presidio",
        action="store_true",
        help="Habilita el uso de Presidio Analyzer para la detección de PII.",
    )
    parser.add_argument(
        "--only-pii-list",
        action="store_true",
        help="Restringe la detección de PII únicamente a los elementos de la lista específica de la UNCAL.",
    )
    return parser.parse_known_args(sys.argv[1:])[0]


STARTUP_OPTIONS = parse_startup_options()
PII_WARNINGS_ENABLED = not STARTUP_OPTIONS.disable_pii_warnings
DOCUMENT_UPLOAD_ENABLED = STARTUP_OPTIONS.enable_document_upload
PRESIDIO_ENABLED = STARTUP_OPTIONS.enable_presidio
ONLY_PII_LIST = STARTUP_OPTIONS.only_pii_list


st.set_page_config(page_title="Chatbot IA", page_icon="🤖")
st.title("Mi Chatbot de Investigación con IA")
st.warning(
    "Este chatbot utiliza inteligencia artificial para generar respuestas y asistir en distintas tareas.\n\n"
    "Las conversaciones pueden ser almacenadas y utilizadas de forma agregada para fines de mejora del sistema, "
    "análisis estadístico y desarrollo de modelos.\n\n"
    "Se recomienda no compartir información personal sensible o datos que no desees que sean procesados por el sistema.\n\n"
    "Al continuar utilizando el chatbot, aceptas estas condiciones de uso."
)

st.markdown(
    """
    <style>
    .chat-row {
        display: flex;
        align-items: flex-start;
        gap: 10px;
        margin: 0.5rem 0;
    }
    .chat-row.user {
        flex-direction: row-reverse;
        justify-content: flex-end;
    }
    .chat-row.assistant {
        justify-content: flex-start;
    }
    .chat-avatar {
        width: 32px;
        height: 32px;
        border-radius: 50%;
        display: flex;
        justify-content: center;
        align-items: center;
        font-size: 16px;
        flex-shrink: 0;
        background: #e5e7eb;
        color: #374151;
        border: 1px solid #d1d5db;
    }
    .chat-row.user .chat-avatar {
        background: #dce7f3;
        color: #46617d;
        border-color: #c7d4e1;
    }
    .chat-bubble {
        width: min(78%, 720px);
        max-width: 78%;
        padding: 0.55rem 0.75rem;
        border-radius: 10px;
        background: #f3f4f6;
        color: #111827;
        white-space: pre-wrap;
        border: 1px solid #e5e7eb;
    }
    .chat-row.user .chat-bubble {
        background: #f7f9fc;
    }
    .chat-row.assistant .chat-bubble {
        background: #ffffff;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if "conversation_file_path" not in st.session_state:
    st.session_state.conversation_file_path = get_default_conversation_path()

if "messages" not in st.session_state:
    st.session_state.messages = load_conversations(st.session_state.conversation_file_path)

if "documents" not in st.session_state:
    st.session_state.documents = []

if "pending_prompt" not in st.session_state:
    st.session_state.pending_prompt = None

if "pending_pii_check" not in st.session_state:
    st.session_state.pending_pii_check = None


st.sidebar.header("📄 Documentos")
if not PII_WARNINGS_ENABLED:
    st.sidebar.warning("Advertencias emergentes de PII desactivadas por parámetro de inicio.")
if DOCUMENT_UPLOAD_ENABLED:
    uploaded_files = st.sidebar.file_uploader(
        "Sube documentos (TXT, PDF, DOCX)",
        type=["txt", "pdf", "docx", "md"],
        accept_multiple_files=True,
    )

    if uploaded_files:
        for uploaded_file in uploaded_files:
            if not any(doc["name"] == uploaded_file.name for doc in st.session_state.documents):
                content = extract_text_from_file(uploaded_file)
                st.session_state.documents.append(
                    {"name": uploaded_file.name, "content": content}
                )
                st.sidebar.success(f"✓ {uploaded_file.name} cargado")

                pii_check = detect_pii(content, enable_presidio=PRESIDIO_ENABLED, only_pii_list=ONLY_PII_LIST)
                if pii_check["found"]:
                    st.sidebar.warning(
                        f"⚠️ PII detectado en {uploaded_file.name}: {pii_check['summary']}"
                    )
                    st.sidebar.write(
                        "Este documento contiene datos sensibles que no deben ser enviados a la IA. "
                        "Por seguridad, evita usarlo en prompts o en el análisis automático."
                    )
                elif pii_check["found"] is None:
                    st.sidebar.info(pii_check["summary"])

    if st.session_state.documents:
        st.sidebar.subheader("Documentos cargados:")

        pii_summary = check_documents_pii(st.session_state.documents, enable_presidio=PRESIDIO_ENABLED, only_pii_list=ONLY_PII_LIST)
        if pii_summary["has_pii"]:
            st.sidebar.error("🚨 Se detectó PII en algunos documentos")
            st.sidebar.write(
                "Algunos archivos cargados contienen datos personales o sensibles. "
                "Para evitar filtraciones, no incluyas esos datos en prompts ni los envíes a la IA."
            )


        for i, doc in enumerate(st.session_state.documents):
            col1, col2 = st.sidebar.columns([3, 1])
            col1.write(f"📌 {doc['name']}")
            if col2.button("🗑️", key=f"delete_{i}"):
                st.session_state.documents.pop(i)
                st.rerun()


def render_chat_message(role: str, content: str) -> None:
    avatar = "👤" if role == "user" else "🤖"
    safe_content = html.escape(content).replace(chr(10), "<br>")
    css_role = "user" if role == "user" else "assistant"

    with st.container():
        st.markdown(
            f"""
            <div class="chat-row {css_role}">
                <div class="chat-avatar">{avatar}</div>
                <div class="chat-bubble">{safe_content}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


for message in st.session_state.messages:
    if message.get("role") in {"user", "assistant"}:
        render_chat_message(message["role"], message["content"])


def process_prompt(prompt_text: str) -> None:
    st.session_state.messages.append({"role": "user", "content": prompt_text})
    save_conversations(st.session_state.messages, st.session_state.conversation_file_path)
    render_chat_message("user", prompt_text)

    doc_context = ""
    if DOCUMENT_UPLOAD_ENABLED:
        doc_context = format_documents_context(st.session_state.documents)
    conversation_for_ai = [
        message
        for message in st.session_state.messages[:-1]
        if message.get("role") in {"user", "assistant"}
    ]

    assistant_response = get_ai_response(
        prompt_text,
        conversation=conversation_for_ai,
        document_context=doc_context,
    )
    st.session_state.messages.append({"role": "assistant", "content": assistant_response})
    save_conversations(st.session_state.messages, st.session_state.conversation_file_path)
    render_chat_message("assistant", assistant_response)


HIGH_CONFIDENCE_THRESHOLD = 0.75

PII_TYPE_LABELS = {
    "EMAIL_ADDRESS": "Correo electrónico",
    "PHONE_NUMBER": "Teléfono",
    "CREDIT_CARD": "Tarjeta de crédito",
    "IP_ADDRESS": "Dirección IP",
    "URL": "URL",
    "DNI/NIE": "DNI/NIE",
    "IBAN": "IBAN / cuenta bancaria",
    "RUT": "RUT chileno",
    "MATRICULA": "Código de matrícula",
    "MEDICAL_FOLIO": "Folio de certificado médico",
    "DOC_REF": "Código de documento institucional",
    "DOCTOR_REGISTRY": "Registro médico",
    "ADDRESS": "Dirección/Domicilio",
    "PHONE_NUMBER_CL": "Teléfono",
    "PERSON": "Nombre de persona",
    "LOCATION": "Ubicación geográfica",
}


def get_high_confidence_pii_types(pii_check: dict) -> list[str]:
    high_confidence_entities = [
        entity
        for entity in pii_check.get("entities", [])
        if entity.get("score", 0) >= HIGH_CONFIDENCE_THRESHOLD
    ]
    types_found = sorted({entity["type"] for entity in high_confidence_entities})
    return [PII_TYPE_LABELS.get(entity_type, entity_type) for entity_type in types_found]


def render_pii_warning(pii_check: dict, original_prompt: str = "") -> None:
    # Agrupar entidades por su etiqueta legible y recolectar sus valores correspondientes
    grouped_entities = {}
    for entity in pii_check.get("entities", []):
        if entity.get("score", 0) >= HIGH_CONFIDENCE_THRESHOLD:
            entity_type = entity["type"]
            friendly_label = PII_TYPE_LABELS.get(entity_type, entity_type)
            text_value = entity["text"]
            
            if friendly_label not in grouped_entities:
                grouped_entities[friendly_label] = set()
            grouped_entities[friendly_label].add(text_value)

    st.error(
        "❌ Se detectó información sensible en tu mensaje. "
        "Puedes decidir si deseas enviarlo de todas formas."
    )

    if original_prompt:
        with st.expander("Ver mensaje original", expanded=True):
            st.code(original_prompt, language=None)

    if grouped_entities:
        st.warning("Tipos de datos detectados:")
        for label, values in sorted(grouped_entities.items()):
            values_str = ", ".join(f"`{val}`" for val in sorted(values))
            st.markdown(f"- **{label}**: {values_str}")
    else:
        st.warning(
            "Se detectaron posibles datos sensibles, pero ningún tipo superó "
            f"la confianza de {HIGH_CONFIDENCE_THRESHOLD:.2f}."
        )





prompt = st.chat_input("Escribe algo aquí...")

if prompt:
    if st.session_state.pending_prompt:
        add_conversation_event(
            st.session_state.messages,
            {
                "content": "Se descartó la advertencia de PII anterior al enviar un nuevo mensaje.",
                "event_type": "pii_warning_discarded",
                "details": {
                    "discarded_prompt": st.session_state.pending_prompt,
                    "new_prompt": prompt,
                },
            },
            st.session_state.conversation_file_path,
        )
    st.session_state.pending_prompt = None
    st.session_state.pending_pii_check = None

if not PII_WARNINGS_ENABLED and st.session_state.pending_prompt:
    prompt_to_send = st.session_state.pending_prompt
    st.session_state.pending_prompt = None
    st.session_state.pending_pii_check = None
    process_prompt(prompt_to_send)
elif st.session_state.pending_prompt:
    pii_check = st.session_state.pending_pii_check or {
        "summary": "",
        "entities": [],
        "debug": "desconocido",
    }
    render_pii_warning(pii_check, st.session_state.pending_prompt)

    if st.button("Enviar de todas formas", key="allow_pii_send", type="primary"):
        prompt_to_send = st.session_state.pending_prompt
        st.session_state.pending_prompt = None
        st.session_state.pending_pii_check = None
        if prompt_to_send:
            add_conversation_event(
                st.session_state.messages,
                {
                    "content": "Se reintentó un mensaje tras una detección de PII.",
                    "event_type": "retry_after_pii",
                    "details": {"original_prompt": prompt_to_send},
                },
                st.session_state.conversation_file_path,
            )
            process_prompt(prompt_to_send)
elif should_process_new_prompt(prompt, st.session_state.pending_prompt):
    if not PII_WARNINGS_ENABLED:
        process_prompt(prompt)
        st.stop()

    decision = decide_prompt_action(prompt, enable_presidio=PRESIDIO_ENABLED, only_pii_list=ONLY_PII_LIST)
    pii_check = decision["pii_check"]

    if decision["action"] == "warn":
        st.session_state.pending_prompt = prompt
        st.session_state.pending_pii_check = pii_check
        add_conversation_event(
            st.session_state.messages,
            {
                "content": "Se bloqueó un mensaje por información personal detectada.",
                "event_type": "pii_blocked",
                "details": {"prompt": prompt, "summary": pii_check.get("summary", "")},
            },
            st.session_state.conversation_file_path,
        )
        render_pii_warning(pii_check, prompt)

        if st.button("Enviar de todas formas", key="allow_pii_send", type="primary"):
            prompt_to_send = st.session_state.pending_prompt
            st.session_state.pending_prompt = None
            st.session_state.pending_pii_check = None
            if prompt_to_send:
                add_conversation_event(
                    st.session_state.messages,
                    {
                        "content": "Se reintentó un mensaje tras una detección de PII.",
                        "event_type": "retry_after_pii",
                        "details": {"original_prompt": prompt_to_send},
                    },
                    st.session_state.conversation_file_path,
                )
                process_prompt(prompt_to_send)
    else:
        process_prompt(prompt)
