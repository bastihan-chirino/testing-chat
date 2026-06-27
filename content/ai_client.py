import os
from typing import Dict, List, Optional


def get_available_models(client) -> List[str]:
    """Lista los modelos disponibles en tu cuenta de Gemini."""
    try:
        models = client.models.list()
        return [model.name for model in models]
    except Exception as e:
        print(f"Error al listar modelos: {e}")
        return []


def select_cheapest_model(available_models: List[str]) -> Optional[str]:
    """Selecciona el modelo más barato de la lista disponible."""
    preference_keywords = [
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "gemini-pro",
    ]

    for keyword in preference_keywords:
        for model in available_models:
            if keyword in model.lower():
                print(f"[Info] Seleccionado: {model}")
                return model

    if available_models:
        print(f"[Info] Modelos disponibles: {available_models}")
        print(f"[Info] Usando: {available_models[0]}")
        return available_models[0]
    return None


def get_ai_response(
    prompt: str,
    conversation: Optional[List[Dict[str, str]]] = None,
    document_context: str = "",
) -> str:
    """Devuelve una respuesta de IA desde Gemini usando google.genai v2.

    Args:
        prompt: Mensaje del usuario.
        conversation: Historial previo de conversación.
        document_context: Contexto de documentos cargados.

    La API key debe estar en GEMINI_API_KEY (para AI Studio).
    """
    try:
        from google import genai
        from google.genai import types

        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return "[Error] GEMINI_API_KEY no configurada. Cópiala desde https://aistudio.google.com/app/apikey"

        client = genai.Client(api_key=api_key)

        try:
            available_models = get_available_models(client)
            if not available_models:
                return "[Error] No hay modelos disponibles. Verifica tu API key y permisos."
            model_name = select_cheapest_model(available_models)
        except Exception as e:
            print(f"Error detectando modelos: {e}")
            return f"[Error] Problemas detectando modelos: {str(e)}"

        if not model_name:
            return "[Error] No se pudo seleccionar un modelo."

        contents = []

        if document_context:
            contents.append(
                types.Content(
                    role="user",
                    parts=[types.Part(text=document_context)],
                )
            )

        if conversation:
            for msg in conversation:
                if msg.get("role") not in {"user", "assistant"}:
                    continue
                role = "user" if msg["role"] == "user" else "model"
                contents.append(
                    types.Content(
                        role=role,
                        parts=[types.Part(text=msg["content"])],
                    )
                )

        contents.append(
            types.Content(
                role="user",
                parts=[types.Part(text=prompt)],
            )
        )

        config = types.GenerateContentConfig(
            temperature=1,
            top_p=1,
            max_output_tokens=2048,
        )

        response = client.models.generate_content(
            model=model_name,
            contents=contents,
            config=config,
        )

        return response.text.strip()

    except ImportError:
        return "[Error] google-genai no está instalado. Instala: pip install google-genai"
    except Exception as e:
        return f"[Error] {str(e)}"
